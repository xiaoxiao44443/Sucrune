package runtimecore

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestInternalMarkerIsProjectScopedAndAtomicReplacementDetaches(t *testing.T) {
	root := t.TempDir()
	service := openTestService(t, root)
	env := createTestEnvironment(t, service, "marker")
	other := createTestEnvironment(t, service, "other")
	paths, err := service.catalog.Paths(env.ID)
	if err != nil {
		t.Fatal(err)
	}
	store := paths.Workspace + inodeStoreSuffix
	if err := os.Mkdir(store, 0700); err != nil {
		t.Fatal(err)
	}
	const contents = "journal bytes\x00here"
	pending := filepath.Join(store, "pending")
	if err := os.WriteFile(pending, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(pending)
	if err != nil {
		t.Fatal(err)
	}
	id, err := fileInodeID(file)
	file.Close()
	if err != nil {
		t.Skipf("host has no compatible file identity: %v", err)
	}
	if err := os.Rename(pending, filepath.Join(store, id)); err != nil {
		t.Fatal(err)
	}
	refPath := filepath.Join(store, id+".refs")
	if err := os.WriteFile(refPath, []byte{2, 0, 0, 0}, 0600); err != nil {
		t.Fatal(err)
	}
	marker := inodeMarkerPrefix + id
	first := filepath.Join(paths.Workspace, "first")
	if err := os.Symlink(marker, first); err != nil {
		t.Skipf("host does not support creating this relative symlink: %v", err)
	}
	if err := os.Symlink(marker, filepath.Join(paths.Workspace, "second")); err != nil {
		t.Fatal(err)
	}
	service = openTestService(t, root)
	read := func(name string) string {
		t.Helper()
		result := success[struct {
			Body []byte `json:"content_base64"`
			Size int    `json:"size"`
		}](t, call(t, service, map[string]any{"op": "file.read", "env_id": env.ID, "path": name}))
		if result.Size != len(result.Body) {
			t.Fatal("incorrect logical size")
		}
		return string(result.Body)
	}
	if read("first") != contents || read("second") != contents {
		t.Fatal("aliased contents changed across restart")
	}
	list := success[struct {
		Entries []FileEntry `json:"entries"`
	}](t, call(t, service, map[string]any{"op": "file.list", "env_id": env.ID, "path": "/"}))
	if len(list.Entries) != 2 {
		t.Fatalf("private store visible or entry missing: %+v", list.Entries)
	}
	for _, entry := range list.Entries {
		if entry.Kind != "file" || entry.Size != int64(len(contents)) {
			t.Fatal("marker exposed instead of logical content")
		}
	}
	otherPaths, err := service.catalog.Paths(other.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(marker, filepath.Join(otherPaths.Workspace, "foreign")); err != nil {
		t.Fatal(err)
	}
	failure(t, call(t, service, map[string]any{"op": "file.read", "env_id": other.ID, "path": "foreign"}), "corrupt_metadata")
	dirty := filepath.Join(store, id+".dirty")
	if err := os.WriteFile(dirty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	failure(t, call(t, service, map[string]any{"op": "file.list", "env_id": env.ID, "path": "/"}), "corrupt_metadata")
	if err := os.Remove(dirty); err != nil {
		t.Fatal(err)
	}
	stageImport(t, service, []byte("new"))
	failure(t, call(t, service, importRequest(env.ID, "/first", 3, strings.Repeat("0", 64))), "integrity_mismatch")
	if read("first") != contents {
		t.Fatal("failed import changed alias")
	}
	success[any](t, call(t, service, map[string]any{"op": "file.write", "env_id": env.ID,
		"path": "first", "content_base64": base64.StdEncoding.EncodeToString([]byte("edit"))}))
	refs, err := os.ReadFile(refPath)
	if err != nil || len(refs) != 4 || binary.LittleEndian.Uint32(refs) != 1 || read("first") != "edit" || read("second") != contents {
		t.Fatal("atomic write failed to detach exactly one alias")
	}
	_, digest := stageImport(t, service, []byte("new"))
	success[any](t, call(t, service, importRequest(env.ID, "second", 3, digest)))
	if read("second") != "new" || read("first") != "edit" {
		t.Fatal("atomic import altered another name")
	}
	entries, err := os.ReadDir(store)
	if err != nil || len(entries) != 0 {
		t.Fatalf("last old alias retained private data: %v %v", entries, err)
	}
	success[any](t, call(t, service, map[string]any{"op": "env.delete", "env_id": env.ID}))
	if _, err := os.Lstat(store); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("deleted project retained its private store")
	}
}

func TestInodeMarkerRejectsAlternatePathSpellings(t *testing.T) {
	id := "00000000000000af0123456789abcdef"
	if got, ok := inodeMarkerID(inodeMarkerPrefix + id); !ok || got != id {
		t.Fatal("canonical marker rejected")
	}
	for _, text := range []string{id, inodeMarkerPrefix + strings.ToUpper(id),
		inodeMarkerPrefix + id + "/", inodeMarkerPrefix + "../" + id, inodeMarkerPrefix + id[:31],
		inodeMarkerPrefix + id[:31] + "g", "/" + inodeMarkerPrefix + id} {
		if _, ok := inodeMarkerID(text); ok {
			t.Fatalf("noncanonical marker accepted: %q", text)
		}
	}
}

func TestManagerRejectsCorruptPrivateInodeFiles(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	store := workspace + inodeStoreSuffix
	for _, dir := range []string{workspace, store} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	body, err := os.CreateTemp(store, "original")
	if err != nil {
		t.Fatal(err)
	}
	id, err := fileInodeID(body)
	body.Close()
	if err != nil {
		t.Skipf("host has no compatible file identity: %v", err)
	}
	bodyPath := filepath.Join(store, id)
	refsPath := bodyPath + ".refs"
	if err := os.Rename(body.Name(), bodyPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(refsPath, []byte{1, 0, 0, 0}, 0600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(workspace, "alias")
	if err := os.Symlink(inodeMarkerPrefix+id, marker); err != nil {
		t.Skipf("host does not support creating this relative symlink: %v", err)
	}
	check := func(t *testing.T, valid bool) {
		t.Helper()
		for _, readBody := range []bool{true, false} {
			inode, err := inspectMarker(workspace, marker, readBody)
			if inode != nil {
				inode.body.Close()
			}
			if valid != (err == nil) {
				t.Fatalf("expected valid=%v with readBody=%v, got %v", valid, readBody, err)
			}
		}
	}
	check(t, true)
	for _, item := range []struct{ label, path string }{{"body", bodyPath}, {"refs", refsPath}} {
		t.Run("extra_link_"+item.label, func(t *testing.T) {
			extra := filepath.Join(root, "outside")
			if err := os.Link(item.path, extra); err != nil {
				t.Skipf("filesystem denies physical link fixture: %v", err)
			}
			t.Cleanup(func() { os.Remove(extra) })
			check(t, false)
		})
	}
	if runtime.GOOS == "linux" || runtime.GOOS == "android" {
		for _, item := range []struct {
			label, path string
			mode        os.FileMode
		}{{"store", store, 0700}, {"refs", refsPath, 0600}} {
			t.Run("public_"+item.label, func(t *testing.T) {
				if err := os.Chmod(item.path, item.mode|0040); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { os.Chmod(item.path, item.mode) })
				check(t, false)
			})
		}
	}
	t.Run("invalid_refcounts", func(t *testing.T) {
		for _, data := range [][]byte{{1, 0, 0}, {0, 0, 0, 0}, {1, 0, 0, 0, 1}} {
			if err := os.WriteFile(refsPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			check(t, false)
		}
	})
}

// A manager write/import publishes a replacement directory entry. An open guest
// file description, or another name for its inode, continues to see that inode.
func TestManagerReadsAndAtomicallyReplacesOneHardLinkName(t *testing.T) {
	root := t.TempDir()
	service := openTestService(t, root)
	env := createTestEnvironment(t, service, "linked")
	other := createTestEnvironment(t, service, "separate")
	paths, err := service.catalog.Paths(env.ID)
	if err != nil {
		t.Fatal(err)
	}
	path := func(name string) string { return filepath.Join(paths.Workspace, name) }
	write := func(name, content string) {
		t.Helper()
		success[any](t, call(t, service, map[string]any{"op": "file.write", "env_id": env.ID,
			"path": name, "content_base64": base64.StdEncoding.EncodeToString([]byte(content))}))
	}
	read := func(name, expected string) {
		t.Helper()
		result := success[struct {
			Content []byte `json:"content_base64"`
			Size    int    `json:"size"`
		}](t, call(t, service, map[string]any{"op": "file.read", "env_id": env.ID, "path": name}))
		if string(result.Content) != expected || result.Size != len(expected) {
			t.Fatalf("incorrect content or size for %s", name)
		}
	}
	write("journal", "pending")
	if err := os.Link(path("journal"), path("second")); err != nil {
		t.Skipf("test filesystem cannot create a host hard link: %v", err)
	}
	if err := os.Link(path("journal"), path("third")); err != nil {
		t.Fatal(err)
	}
	// Simulate a guest O_TRUNC/write to the shared inode before manager restart.
	const shared = "committed\n"
	if err := os.WriteFile(path("third"), []byte(shared), 0600); err != nil {
		t.Fatal(err)
	}
	service = openTestService(t, root)
	for _, name := range []string{"journal", "second", "third"} {
		read(name, shared)
	}
	entries := success[struct {
		Entries []FileEntry `json:"entries"`
	}](t, call(t, service, map[string]any{"op": "file.list", "env_id": env.ID, "path": "/"})).Entries
	if len(entries) != 3 {
		t.Fatalf("unexpected listing: %+v", entries)
	}
	for _, entry := range entries {
		if entry.Kind != "file" || entry.Size != int64(len(shared)) {
			t.Fatalf("incorrect logical file metadata: %+v", entry)
		}
	}
	failure(t, call(t, service, map[string]any{"op": "file.read", "env_id": other.ID, "path": "second"}), "not_found")

	write("second", "edit")
	read("second", "edit")
	read("journal", shared)
	data := []byte("imported")
	stageImport(t, service, data)
	failure(t, call(t, service, importRequest(env.ID, "third", int64(len(data)), strings.Repeat("0", 64))), "integrity_mismatch")
	read("third", shared)
	_, digest := stageImport(t, service, data)
	success[any](t, call(t, service, importRequest(env.ID, "third", int64(len(data)), digest)))
	read("third", string(data))
	read("journal", shared)
	success[any](t, call(t, service, map[string]any{"op": "env.delete", "env_id": env.ID}))
	failure(t, call(t, service, map[string]any{"op": "file.read", "env_id": env.ID, "path": "journal"}), "not_found")
	success[any](t, call(t, service, map[string]any{"op": "env.get", "env_id": other.ID}))
}
