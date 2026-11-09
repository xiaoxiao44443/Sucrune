// Package environment provides a development-time persistent environment
// catalog. It does not execute programs or implement a security boundary.
// A Catalog serializes operations within that instance. The owner must use one
// instance per data directory; cross-process locking is not implemented yet.
package environment

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"sucrune/internal/storagefs"
)

const (
	SchemaVersion = 1
	StateStopped  = "stopped"
	maxMetadata   = 1 << 20
)

var (
	ErrInvalidID   = errors.New("invalid environment ID")
	ErrInvalidName = errors.New("invalid environment name")
	ErrNotFound    = errors.New("environment not found")
	ErrCorrupt     = errors.New("invalid environment metadata")
	ErrUnsafePath  = errors.New("unsafe catalog path")
	idPattern      = regexp.MustCompile(`^env_[0-9a-f]{32}$`)
)

type Environment struct {
	SchemaVersion int       `json:"schema_version"`
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	BaseReference string    `json:"base_reference,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	State         string    `json:"state"`
}

type Paths struct {
	Environment  string `json:"environment"`
	Workspace    string `json:"workspace"`
	Dependencies string `json:"dependencies"`
}

type Catalog struct {
	root string
	mu   sync.Mutex
}

// Open requires an explicit data directory. Root metadata must remain owned by
// the trusted manager. Symlink checks prevent accidental redirection, not races
// against a malicious process with write access to the same directory.
func Open(dataDir string) (*Catalog, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("an explicit data directory is required")
	}
	root, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve data directory: %w", err)
	}
	if err := ensureDirectory(root); err != nil {
		return nil, err
	}
	parent := filepath.Join(root, "environments")
	if err := ensureDirectory(parent); err != nil {
		return nil, err
	}
	// A hidden deletion directory can survive a crash after rename. Older
	// versions used a random ID here, so recover by the reserved name. A
	// cleanup I/O failure leaves that hidden directory for a later retry;
	// unrelated projects must remain available.
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		id, hidden := strings.CutPrefix(entry.Name(), ".deleted-")
		if hidden && idPattern.MatchString(id) && entry.IsDir() {
			_ = removeDeleted(filepath.Join(parent, entry.Name()))
		}
	}
	return &Catalog{root: root}, nil
}

// Create publishes a complete directory with a single rename. Metadata files
// are never overwritten in place, avoiding Windows rename-over-existing issues.
// The result is a stopped environment: no guest process has been started.
func (c *Catalog) Create(name, baseReference string) (Environment, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	name = strings.TrimSpace(name)
	if !validName(name) {
		return Environment{}, ErrInvalidName
	}
	if len(baseReference) > 512 || strings.ContainsAny(baseReference, "\x00\r\n") {
		return Environment{}, errors.New("invalid base reference")
	}
	if err := c.checkRoot(); err != nil {
		return Environment{}, err
	}
	id, err := newID()
	if err != nil {
		return Environment{}, err
	}
	env := Environment{
		SchemaVersion: SchemaVersion, ID: id, Name: name,
		BaseReference: baseReference, CreatedAt: time.Now().UTC(), State: StateStopped,
	}
	parent := filepath.Join(c.root, "environments")
	temporary, err := os.MkdirTemp(parent, ".pending-")
	if err != nil {
		return Environment{}, fmt.Errorf("stage environment: %w", err)
	}
	defer os.RemoveAll(temporary)
	for _, name := range []string{"workspace", "dependencies"} {
		if err := os.Mkdir(filepath.Join(temporary, name), 0700); err != nil {
			return Environment{}, fmt.Errorf("prepare environment directory: %w", err)
		}
	}
	if err := writeMetadata(filepath.Join(temporary, "environment.json"), env); err != nil {
		return Environment{}, err
	}
	destination := filepath.Join(parent, id)
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return Environment{}, errors.New("generated environment ID already exists")
		}
		return Environment{}, err
	}
	if err := storagefs.RenameDirectory(temporary, destination); err != nil {
		return Environment{}, fmt.Errorf("publish environment: %w", err)
	}
	return env, nil
}

func (c *Catalog) Get(id string) (Environment, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.get(id)
}

func (c *Catalog) List() ([]Environment, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkRoot(); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(filepath.Join(c.root, "environments"))
	if err != nil {
		return nil, fmt.Errorf("list environments: %w", err)
	}
	result := make([]Environment, 0, len(entries))
	for _, entry := range entries {
		if !idPattern.MatchString(entry.Name()) {
			// Incomplete creation/deletion directories are never public entries.
			continue
		}
		env, err := c.get(entry.Name())
		if err != nil {
			return nil, err
		}
		result = append(result, env)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, nil
}

func (c *Catalog) Paths(id string) (Paths, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.get(id); err != nil {
		return Paths{}, err
	}
	root := filepath.Join(c.root, "environments", id)
	paths := Paths{Environment: root, Workspace: filepath.Join(root, "workspace"), Dependencies: filepath.Join(root, "dependencies")}
	for _, path := range []string{paths.Workspace, paths.Dependencies} {
		if err := checkDirectory(path); err != nil {
			return Paths{}, err
		}
	}
	return paths, nil
}

// Delete permanently removes the environment, including workspace/dependencies.
// It first removes the entry from the visible catalog by renaming its directory.
// A cleanup failure is returned with the retained deletion directory location.
func (c *Catalog) Delete(id string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	source := filepath.Join(c.root, "environments", id)
	destination := filepath.Join(c.root, "environments", ".deleted-"+id)
	if _, err := c.get(id); err != nil {
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		if cleanupErr := removeDeleted(destination); !errors.Is(cleanupErr, os.ErrNotExist) {
			return cleanupErr
		}
		return err
	}
	if err := storagefs.RenameDirectory(source, destination); err != nil {
		return fmt.Errorf("remove environment from catalog: %w", err)
	}
	return removeDeleted(destination)
}

func removeDeleted(destination string) error {
	if err := checkDirectory(destination); err != nil {
		return err
	}
	err := os.RemoveAll(destination)
	if errors.Is(err, os.ErrPermission) {
		// Toolchains such as Go leave read-only dependency directories.
		// Only change real directories inside the already detached project.
		err = filepath.WalkDir(destination, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return os.Chmod(path, 0700)
			}
			return nil
		})
		if err == nil {
			err = os.RemoveAll(destination)
		}
	}
	if err != nil {
		return fmt.Errorf("environment removed from catalog but cleanup is incomplete at %q: %w", destination, err)
	}
	return nil
}

func (c *Catalog) get(id string) (Environment, error) {
	if !idPattern.MatchString(id) {
		return Environment{}, ErrInvalidID
	}
	if err := c.checkRoot(); err != nil {
		return Environment{}, err
	}
	directory := filepath.Join(c.root, "environments", id)
	if err := checkDirectory(directory); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Environment{}, fmt.Errorf("%w: %s", ErrNotFound, id)
		}
		return Environment{}, err
	}
	path := filepath.Join(directory, "environment.json")
	stat, err := os.Lstat(path)
	if err != nil {
		return Environment{}, fmt.Errorf("%w: %s: %v", ErrCorrupt, id, err)
	}
	if !stat.Mode().IsRegular() || stat.Size() > maxMetadata {
		return Environment{}, fmt.Errorf("%w: metadata must be a bounded regular file", ErrCorrupt)
	}
	file, err := os.Open(path)
	if err != nil {
		return Environment{}, fmt.Errorf("read environment: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxMetadata+1))
	decoder.DisallowUnknownFields()
	var env Environment
	if err := decoder.Decode(&env); err != nil {
		return Environment{}, fmt.Errorf("%w: %s: %v", ErrCorrupt, id, err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return Environment{}, fmt.Errorf("%w: trailing metadata content", ErrCorrupt)
	}
	if env.SchemaVersion != SchemaVersion || env.ID != id || !validName(env.Name) || env.CreatedAt.IsZero() || env.State != StateStopped {
		return Environment{}, fmt.Errorf("%w: inconsistent fields for %s", ErrCorrupt, id)
	}
	return env, nil
}

func (c *Catalog) checkRoot() error {
	if err := checkDirectory(c.root); err != nil {
		return err
	}
	return checkDirectory(filepath.Join(c.root, "environments"))
}

func ensureDirectory(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("create catalog directory: %w", err)
	}
	return checkDirectory(path)
}

func checkDirectory(path string) error {
	stat, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if stat.Mode()&os.ModeSymlink != 0 || !stat.IsDir() {
		return fmt.Errorf("%w: expected a real directory at %q", ErrUnsafePath, path)
	}
	return nil
}

func validName(name string) bool {
	return name != "" && len(name) <= 256 && name == strings.TrimSpace(name) && !strings.ContainsFunc(name, unicode.IsControl)
}

func newID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate environment ID: %w", err)
	}
	return "env_" + hex.EncodeToString(bytes[:]), nil
}

func writeMetadata(path string, env Environment) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("create metadata: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(env); err != nil {
		file.Close()
		return fmt.Errorf("encode metadata: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync metadata: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close metadata: %w", err)
	}
	return nil
}
