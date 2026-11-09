package runtimecore

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const testImportID = "2ed87822-f84a-4c51-a33e-826ba3adf286"

func importRequest(envID, path string, size int64, digest string) map[string]any {
	return map[string]any{"op": "file.import", "env_id": envID, "path": path, "import_id": testImportID, "size": size, "sha256": digest}
}

func stageImport(t *testing.T, service *Service, data []byte) (string, string) {
	t.Helper()
	file := filepath.Join(service.root, "imports", testImportID+".bin")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(data)
	return file, hex.EncodeToString(hash[:])
}

func noImportScratch(t *testing.T, service *Service, workspace string) {
	t.Helper()
	if _, err := os.Lstat(filepath.Join(service.root, "imports", testImportID+".bin")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging slot remains: %v", err)
	}
	entries, err := os.ReadDir(workspace)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".pending-import-") {
			t.Fatalf("publication temporary remains: %s", entry.Name())
		}
	}
}

func TestImportStreamsLargeBinaryWithoutGrowingJSONLimits(t *testing.T) {
	service := openTestService(t, t.TempDir())
	env := createTestEnvironment(t, service, "large")
	paths, err := service.catalog.Paths(env.ID)
	if err != nil {
		t.Fatal(err)
	}
	staging := filepath.Join(service.root, "imports", testImportID+".bin")
	file, err := os.Create(staging)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	block := bytes.Repeat([]byte{0, 1, 0xff, 0x80, '\n'}, 13_107)
	var size int64
	for range 35 {
		n, err := io.MultiWriter(file, hash).Write(block)
		if err != nil {
			t.Fatal(err)
		}
		size += int64(n)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	req := importRequest(env.ID, "/程序.bin", size, digest)
	encoded, err := json.Marshal(req)
	if err != nil || len(encoded) >= 512 || size <= MaxFileBytes {
		t.Fatalf("invalid test bounds: request=%d file=%d err=%v", len(encoded), size, err)
	}
	result := success[struct {
		Path   string `json:"path"`
		Size   int64  `json:"size"`
		SHA256 string `json:"sha256"`
	}](t, call(t, service, req))
	if result.Path != "/程序.bin" || result.Size != size || result.SHA256 != digest {
		t.Fatalf("bad import metadata: %+v", result)
	}
	imported, err := os.Open(filepath.Join(paths.Workspace, "程序.bin"))
	if err != nil {
		t.Fatal(err)
	}
	defer imported.Close()
	observed := sha256.New()
	n, err := io.Copy(observed, imported)
	if err != nil || n != size || hex.EncodeToString(observed.Sum(nil)) != digest {
		t.Fatalf("imported bytes mismatch: size=%d err=%v", n, err)
	}
	failure(t, call(t, service, map[string]any{"op": "file.read", "env_id": env.ID, "path": "/程序.bin"}), "too_large")
	if MaxRequestBytes != 4<<20 || MaxFileBytes != 1<<20 {
		t.Fatal("small JSON/file API limits changed")
	}
	noImportScratch(t, service, paths.Workspace)
}

func TestImportIntegrityFailureKeepsPreviousFile(t *testing.T) {
	service := openTestService(t, t.TempDir())
	env := createTestEnvironment(t, service, "integrity")
	paths, err := service.catalog.Paths(env.ID)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(paths.Workspace, "target")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"hash", "short", "long", "missing-size", "negative", "oversized", "invalid-hash"} {
		t.Run(kind, func(t *testing.T) {
			_, digest := stageImport(t, service, []byte("replacement"))
			req := importRequest(env.ID, "/target", 11, digest)
			code := "integrity_mismatch"
			switch kind {
			case "hash":
				req["sha256"] = strings.Repeat("0", 64)
			case "short":
				req["size"] = 10
			case "long":
				req["size"] = 12
			case "missing-size":
				delete(req, "size")
				code = "invalid_arguments"
			case "negative":
				req["size"], code = -1, "invalid_arguments"
			case "oversized":
				req["size"], code = MaxImportBytes+1, "invalid_arguments"
			case "invalid-hash":
				req["sha256"], code = "bad", "invalid_arguments"
			}
			failure(t, call(t, service, req), code)
			data, err := os.ReadFile(target)
			if err != nil || string(data) != "original" {
				t.Fatalf("failed import modified original: %q %v", data, err)
			}
			noImportScratch(t, service, paths.Workspace)
		})
	}
	// Empty imports still carry an explicit size and digest.
	_, digest := stageImport(t, service, nil)
	success[any](t, call(t, service, importRequest(env.ID, "/target", 0, digest)))
	data, err := os.ReadFile(target)
	if err != nil || len(data) != 0 {
		t.Fatalf("empty import failed: %q %v", data, err)
	}
	noImportScratch(t, service, paths.Workspace)
}

func TestImportBusyAndDestinationBoundaries(t *testing.T) {
	service := openTestService(t, t.TempDir())
	env := createTestEnvironment(t, service, "boundaries")
	paths, err := service.catalog.Paths(env.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ path, code string }{
		{"../escape", "unsafe_path"}, {"C:/escape", "unsafe_path"}, {"/", "invalid_arguments"}, {"/missing/file", "not_found"},
	} {
		_, digest := stageImport(t, service, []byte("new"))
		failure(t, call(t, service, importRequest(env.ID, test.path, 3, digest)), test.code)
		noImportScratch(t, service, paths.Workspace)
	}
	success[Execution](t, call(t, service, map[string]any{"op": "exec.create", "env_id": env.ID, "request": map[string]any{"kind": "linux", "path": "/bin/node"}}))
	_, digest := stageImport(t, service, []byte("new"))
	failure(t, call(t, service, importRequest(env.ID, "/target", 3, digest)), "conflict")
	if _, err := os.Lstat(filepath.Join(paths.Workspace, "target")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("busy import wrote target: %v", err)
	}
	noImportScratch(t, service, paths.Workspace)
}

func TestImportIDsCannotSelectHostPaths(t *testing.T) {
	service := openTestService(t, t.TempDir())
	env := createTestEnvironment(t, service, "slots")
	staged, digest := stageImport(t, service, []byte("new"))
	for _, id := range []string{"", "../outside", staged, testImportID + ".bin", strings.ToUpper(testImportID), strings.Repeat("0", 36)} {
		req := importRequest(env.ID, "/target", 3, digest)
		req["import_id"] = id
		failure(t, call(t, service, req), "invalid_arguments")
		if data, err := os.ReadFile(staged); err != nil || string(data) != "new" {
			t.Fatalf("invalid ID affected another staging slot: %v", err)
		}
	}
	req := importRequest(env.ID, "/target", 3, digest)
	req["host_path"] = staged
	failure(t, call(t, service, req), "invalid_request")
	success[any](t, call(t, service, importRequest(env.ID, "/target", 3, digest)))
}

func TestImportRejectsStagingDirectoriesAndSymlinks(t *testing.T) {
	service := openTestService(t, t.TempDir())
	env := createTestEnvironment(t, service, "sources")
	staged := filepath.Join(service.root, "imports", testImportID+".bin")
	if err := os.Mkdir(staged, 0700); err != nil {
		t.Fatal(err)
	}
	failure(t, call(t, service, importRequest(env.ID, "/target", 0, strings.Repeat("0", 64))), "unsafe_path")
	if err := os.Remove(staged); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(out, []byte("outside"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, staged); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	failure(t, call(t, service, importRequest(env.ID, "/target", 7, strings.Repeat("0", 64))), "unsafe_path")
	if data, err := os.ReadFile(out); err != nil || string(data) != "outside" {
		t.Fatalf("symlink source changed: %v", err)
	}
	if err := os.Remove(staged); err != nil {
		t.Fatal(err)
	}
	paths, err := service.catalog.Paths(env.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, filepath.Join(paths.Workspace, "link")); err != nil {
		t.Fatal(err)
	}
	_, digest := stageImport(t, service, []byte("new"))
	failure(t, call(t, service, importRequest(env.ID, "/link", 3, digest)), "unsafe_path")
	noImportScratch(t, service, paths.Workspace)
}

type failingImportReader struct{}

func (failingImportReader) Read([]byte) (int, error) { return 0, errors.New("test source interrupted") }

func TestImportReadFailureDoesNotPublishPartialFile(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	reader := io.MultiReader(strings.NewReader("partial"), failingImportReader{})
	if err := atomicImport(target, reader, 100, strings.Repeat("0", 64), false); err == nil {
		t.Fatal("failed source succeeded")
	}
	data, err := os.ReadFile(target)
	if err != nil || string(data) != "original" {
		t.Fatalf("source error replaced original: %q %v", data, err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != "target" {
		t.Fatalf("source error leaked temporary files: %v %v", entries, err)
	}
}

func TestImportExecutableModeIsExplicitAndRestricted(t *testing.T) {
	service := openTestService(t, t.TempDir())
	env := createTestEnvironment(t, service, "mode")
	paths, err := service.catalog.Paths(env.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, executable := range []bool{false, true, false} {
		staged, digest := stageImport(t, service, []byte("payload"))
		// A staging source's executable/public mode must not propagate implicitly.
		if err := os.Chmod(staged, 0777); err != nil {
			t.Fatal(err)
		}
		req := importRequest(env.ID, "/program", 7, digest)
		if executable {
			req["executable"] = true
		}
		result := success[struct {
			Executable bool `json:"executable"`
		}](t, call(t, service, req))
		if result.Executable != executable {
			t.Fatalf("mode choice not recorded: %+v", result)
		}
		info, err := os.Stat(filepath.Join(paths.Workspace, "program"))
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" {
			expected := os.FileMode(0600)
			if executable {
				expected = 0700
			}
			if info.Mode() != expected {
				t.Fatalf("want mode %v, got %v", expected, info.Mode())
			}
		} else {
			t.Log("Windows does not expose POSIX executable mode bits; content/publication/API choice checked")
		}
		noImportScratch(t, service, paths.Workspace)
	}
}
