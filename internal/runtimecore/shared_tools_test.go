package runtimecore

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSharedToolsDetachInManager(t *testing.T) {
	root := t.TempDir()
	s := openTestService(t, root)
	first := createTestEnvironment(t, s, "one")
	second := createTestEnvironment(t, s, "two")
	const initial = "from signed image"
	key := fmt.Sprintf("0600-%x", sha256.Sum256([]byte(initial)))
	store := filepath.Join(root, "shared-tools-v1")
	if err := os.Mkdir(store, 0700); err != nil {
		t.Fatal(err)
	}
	blob := filepath.Join(store, key)
	if err := os.WriteFile(blob, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{first.ID, second.ID} {
		p, err := s.catalog.Paths(id)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(sharedToolPrefix+key, filepath.Join(p.Workspace, "tool")); err != nil {
			t.Skipf("host lacks symlink support: %v", err)
		}
	}
	read := func(id string) string {
		t.Helper()
		got := success[struct {
			Data []byte `json:"content_base64"`
		}](t, call(t, s, map[string]any{
			"op": "file.read", "path": "/tool", "env_id": id,
		}))
		return string(got.Data)
	}
	list := success[struct {
		Entries []FileEntry `json:"entries"`
	}](t, call(t, s, map[string]any{"op": "file.list", "path": "/", "env_id": first.ID}))
	if len(list.Entries) != 1 || list.Entries[0] != (FileEntry{"tool", "file", int64(len(initial))}) || read(first.ID) != initial {
		t.Fatal("shared tool not exposed as a regular project file")
	}
	stageImport(t, s, []byte("package"))
	failure(t, call(t, s, importRequest(first.ID, "/tool", 7, strings.Repeat("f", 64))), "integrity_mismatch")
	if read(first.ID) != initial {
		t.Fatal("failed import detached shared object")
	}
	success[any](t, call(t, s, map[string]any{"op": "file.write", "path": "/tool", "env_id": first.ID,
		"content_base64": base64.StdEncoding.EncodeToString([]byte("private"))}))
	if read(first.ID) != "private" || read(second.ID) != initial {
		t.Fatal("changing one project affected another")
	}
	_, hash := stageImport(t, s, []byte("new version"))
	success[any](t, call(t, s, importRequest(second.ID, "/tool", 11, hash)))
	if read(first.ID) != "private" || read(second.ID) != "new version" {
		t.Fatal("independent project import failed")
	}
	if data, err := os.ReadFile(blob); err != nil || string(data) != initial {
		t.Fatal("shared object changed", err)
	}
}

func TestSharedToolKeysRejectEscapes(t *testing.T) {
	hash := strings.Repeat("a", 64)
	if k, ok := sharedToolKey(sharedToolPrefix + "0755-" + hash); !ok || k != "0755-"+hash {
		t.Fatal("valid key rejected")
	}
	for _, key := range []string{"../0755-" + hash, "0755-" + hash + "/a", "1755-" + hash, "0778-" + hash, "0755-" + strings.ToUpper(hash), "0755-" + hash[1:]} {
		if _, ok := sharedToolKey(sharedToolPrefix + key); ok {
			t.Fatalf("unsafe key accepted: %s", key)
		}
	}
}
