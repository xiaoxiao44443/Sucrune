package environment

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func openTestCatalog(t *testing.T) (*Catalog, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "catalog")
	catalog, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	return catalog, root
}

func TestReopenPreservesEnvironmentAndDependencyFiles(t *testing.T) {
	catalog, root := openTestCatalog(t)
	created, err := catalog.Create("project one", "example-base-v1")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := catalog.Paths(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{paths.Workspace, paths.Dependencies} {
		if err := os.WriteFile(filepath.Join(directory, "retained.txt"), []byte("persistent"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reopened.Get(created.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != created.ID || got.Name != created.Name || got.BaseReference != created.BaseReference || got.State != StateStopped {
		t.Fatalf("incorrect reopened environment: %+v", got)
	}
	if !got.CreatedAt.Equal(created.CreatedAt) {
		t.Fatal("creation time changed")
	}
	for _, directory := range []string{paths.Workspace, paths.Dependencies} {
		bytes, err := os.ReadFile(filepath.Join(directory, "retained.txt"))
		if err != nil || string(bytes) != "persistent" {
			t.Fatalf("persistent data was lost: %q, %v", bytes, err)
		}
	}
}

func TestInvalidIDsCannotAccessOrDeleteOutsideCatalog(t *testing.T) {
	catalog, root := openTestCatalog(t)
	outside := filepath.Join(filepath.Dir(root), "outside.txt")
	if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"", "..", "../outside.txt", "..\\outside.txt", outside, "env_abc", "ENV_00000000000000000000000000000000", "env_00000000000000000000000000000000/.."} {
		if _, err := catalog.Get(id); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Get(%q) = %v", id, err)
		}
		if err := catalog.Delete(id); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Delete(%q) = %v", id, err)
		}
		if _, err := catalog.Paths(id); !errors.Is(err, ErrInvalidID) {
			t.Errorf("Paths(%q) = %v", id, err)
		}
	}
	bytes, err := os.ReadFile(outside)
	if err != nil || string(bytes) != "keep" {
		t.Fatalf("outside data changed: %q, %v", bytes, err)
	}
}

func TestInvalidNamesDoNotPublishPartialEnvironments(t *testing.T) {
	catalog, root := openTestCatalog(t)
	for _, name := range []string{"", "   ", "bad\x00name", "bad\nname"} {
		if _, err := catalog.Create(name, ""); !errors.Is(err, ErrInvalidName) {
			t.Errorf("Create(%q) = %v", name, err)
		}
	}
	entries, err := os.ReadDir(filepath.Join(root, "environments"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("invalid creation left directories: %v", entries)
	}
}

func TestConcurrentCreationPublishesUniqueCompleteEnvironments(t *testing.T) {
	catalog, _ := openTestCatalog(t)
	const count = 24
	var wg sync.WaitGroup
	results := make(chan Environment, count)
	failures := make(chan error, count)
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			env, err := catalog.Create("same display name", "")
			if err != nil {
				failures <- err
				return
			}
			results <- env
		}()
	}
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	ids := map[string]bool{}
	for env := range results {
		if ids[env.ID] {
			t.Errorf("duplicate ID %s", env.ID)
		}
		ids[env.ID] = true
		if _, err := catalog.Paths(env.ID); err != nil {
			t.Errorf("incomplete environment: %v", err)
		}
	}
	list, err := catalog.List()
	if err != nil || len(list) != count {
		t.Fatalf("List length = %d, err = %v", len(list), err)
	}
}

func TestDeleteOnlyRemovesSelectedEnvironment(t *testing.T) {
	catalog, _ := openTestCatalog(t)
	first, err := catalog.Create("delete me", "")
	if err != nil {
		t.Fatal(err)
	}
	second, err := catalog.Create("keep me", "")
	if err != nil {
		t.Fatal(err)
	}
	paths, err := catalog.Paths(first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(paths.Workspace, "data.txt"), []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := catalog.Delete(first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := catalog.Get(first.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted environment still exists: %v", err)
	}
	if _, err := os.Stat(paths.Environment); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("deleted files remain: %v", err)
	}
	if _, err := catalog.Get(second.ID); err != nil {
		t.Fatalf("other environment damaged: %v", err)
	}
}

func TestIncompleteCreationIsNotVisible(t *testing.T) {
	catalog, root := openTestCatalog(t)
	if err := os.Mkdir(filepath.Join(root, "environments", ".pending-interrupted"), 0700); err != nil {
		t.Fatal(err)
	}
	list, err := catalog.List()
	if err != nil || len(list) != 0 {
		t.Fatalf("incomplete environment became visible: %+v, %v", list, err)
	}
}

func TestInterruptedDeletionCanFinish(t *testing.T) {
	for _, recovery := range []string{"retry", "restart"} {
		t.Run(recovery, func(t *testing.T) {
			catalog, root := openTestCatalog(t)
			env, err := catalog.Create("delete", "")
			if err != nil {
				t.Fatal(err)
			}
			parent := filepath.Join(root, "environments")
			suffix := env.ID
			if recovery == "restart" {
				suffix = "env_11111111111111111111111111111111" // Old randomized tombstone.
			}
			hidden := filepath.Join(parent, ".deleted-"+suffix)
			if err := os.Rename(filepath.Join(parent, env.ID), hidden); err != nil {
				t.Fatal(err)
			}
			if recovery == "retry" {
				err = catalog.Delete(env.ID)
			} else {
				_, err = Open(root)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(hidden); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unfinished deletion still exists: %v", err)
			}
		})
	}
}

func TestCorruptMetadataFailsClosed(t *testing.T) {
	for _, mutate := range []string{"invalid json", "other ID", "running state", "extra data", "future schema"} {
		t.Run(mutate, func(t *testing.T) {
			catalog, root := openTestCatalog(t)
			env, err := catalog.Create("project", "")
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, "environments", env.ID, "environment.json")
			var bytes []byte
			switch mutate {
			case "invalid json":
				bytes = []byte("{")
			case "other ID":
				env.ID = "env_00000000000000000000000000000000"
				bytes, err = json.Marshal(env)
			case "running state":
				env.State = "running"
				bytes, err = json.Marshal(env)
			case "extra data":
				bytes, err = json.Marshal(env)
				bytes = append(bytes, []byte("{}")...)
			case "future schema":
				env.SchemaVersion++
				bytes, err = json.Marshal(env)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, bytes, 0600); err != nil {
				t.Fatal(err)
			}
			list, err := catalog.List()
			if !errors.Is(err, ErrCorrupt) || list != nil {
				t.Fatalf("corrupt catalog silently accepted: %+v, %v", list, err)
			}
		})
	}
}

func TestSymlinkEnvironmentIsRejected(t *testing.T) {
	catalog, root := openTestCatalog(t)
	outside := t.TempDir()
	id := "env_00000000000000000000000000000000"
	if err := os.Symlink(outside, filepath.Join(root, "environments", id)); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	if _, err := catalog.Get(id); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink accepted: %v", err)
	}
	if err := catalog.Delete(id); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink deletion accepted: %v", err)
	}
}

func TestOpenRejectsImplicitDirectoryAndFileRoot(t *testing.T) {
	if _, err := Open(""); err == nil {
		t.Fatal("implicit data directory accepted")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(file); err == nil {
		t.Fatal("file root accepted")
	}
}
