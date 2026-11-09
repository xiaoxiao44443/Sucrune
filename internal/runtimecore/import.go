package runtimecore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Only manager-created UUID slots are accepted, never a caller-selected host path.
var importIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// importFile consumes a regular staging file, including on rejected publication.
// The service lock spans the active check and commit. As elsewhere in the
// manager, same-UID hostile directory mutation is outside the ownership model.
func (s *Service) importFile(req request) (result any, returnedErr error) {
	if !importIDPattern.MatchString(req.ImportID) {
		return nil, problem("invalid_arguments", "import_id must be a lowercase UUID")
	}
	if err := realDirectory(s.root); err != nil {
		return nil, err
	}
	imports := filepath.Join(s.root, "imports")
	if err := realDirectory(imports); err != nil {
		return nil, err
	}
	name := req.ImportID + ".bin"
	staged := filepath.Join(imports, name)
	info, err := os.Lstat(staged)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, problem("unsafe_path", "import source must be a regular staging file")
	}
	defer func() {
		if err := os.Remove(staged); err != nil && !errors.Is(err, os.ErrNotExist) && returnedErr == nil {
			result, returnedErr = nil, err
		}
	}()
	if req.Size == nil || *req.Size < 0 || *req.Size > MaxImportBytes {
		return nil, problem("invalid_arguments", "import size must be between 0 and 256 MiB")
	}
	expectedHash, err := hex.DecodeString(req.SHA256)
	if err != nil || len(expectedHash) != sha256.Size {
		return nil, problem("invalid_arguments", "sha256 must contain 64 hexadecimal characters")
	}
	if info.Size() != *req.Size {
		return nil, problem("integrity_mismatch", "import source size differs from declared size")
	}
	paths, err := s.catalog.Paths(req.EnvID)
	if err != nil {
		return nil, err
	}
	active, err := s.hasActive(req.EnvID)
	if err != nil {
		return nil, err
	}
	if active {
		return nil, problem("conflict", "cannot import into an environment with an active execution")
	}
	virtual, err := virtualPath(req.Path)
	if err != nil {
		return nil, err
	}
	if virtual == "/" {
		return nil, problem("invalid_arguments", "cannot import over the workspace root")
	}
	unlock, err := lockWorkspace(paths.Workspace, true)
	if err != nil {
		return nil, err
	}
	defer unlock()
	target, alias, err := inspectLeaf(paths.Workspace, virtual, true, false)
	if err != nil {
		return nil, err
	}
	if alias != nil {
		alias.body.Close()
	}
	if targetInfo, err := os.Lstat(target); err == nil && alias == nil && !targetInfo.Mode().IsRegular() {
		return nil, problem("unsafe_path", "import destination must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	source, err := os.OpenInRoot(imports, name)
	if err != nil {
		return nil, err
	}
	defer source.Close()
	openedInfo, err := source.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) || openedInfo.Size() != *req.Size {
		return nil, problem("integrity_mismatch", "import source changed while opening")
	}
	if err := atomicImportWorkspaceFile(target, source, *req.Size, strings.ToLower(req.SHA256), req.Executable, alias); err != nil {
		return nil, err
	}
	return map[string]any{"path": virtual, "size": *req.Size, "sha256": hex.EncodeToString(expectedHash), "executable": req.Executable}, nil
}

// Publication follows atomicWrite: copy and hash to a same-directory temporary,
// fsync content, then replace and sync the directory. Any pre-rename failure
// leaves the previous file intact. A post-rename sync error may already be visible.
func atomicImport(destination string, source io.Reader, size int64, expectedSHA256 string, executable bool) error {
	return atomicImportWorkspaceFile(destination, source, size, expectedSHA256, executable, nil)
}

func atomicImportWorkspaceFile(destination string, source io.Reader, size int64, expectedSHA256 string, executable bool, alias *linkedInode) error {
	parent := filepath.Dir(destination)
	if err := realDirectory(parent); err != nil {
		return err
	}
	file, err := os.CreateTemp(parent, ".pending-import-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	hash := sha256.New()
	written, err := io.CopyBuffer(io.MultiWriter(file, hash), io.LimitReader(source, size+1), make([]byte, 64<<10))
	if err != nil {
		return err
	}
	if written != size || hex.EncodeToString(hash.Sum(nil)) != expectedSHA256 {
		return problem("integrity_mismatch", "import content differs from declared size or SHA-256")
	}
	// File modes come only from this explicit API choice, never from an archive
	// or staging source. In particular, no setuid/setgid or external write bits.
	mode := os.FileMode(0600)
	if executable {
		mode = 0700
	}
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return publishWorkspaceFile(file.Name(), destination, alias)
}
