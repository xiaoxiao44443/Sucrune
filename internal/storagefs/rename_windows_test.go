package storagefs

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestRenameWhileDirectoryIsOpen(t *testing.T) {
	for _, release := range []bool{true, false} {
		source := filepath.Join(t.TempDir(), "visible")
		destination := filepath.Join(filepath.Dir(source), "retired")
		if err := os.Mkdir(source, 0700); err != nil {
			t.Fatal(err)
		}
		path, err := syscall.UTF16PtrFromString(source)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := syscall.CreateFile(path, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
			nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			t.Fatal(err)
		}
		file := os.NewFile(uintptr(handle), source)
		t.Cleanup(func() { file.Close() })
		if err := os.Rename(source, destination); !errors.Is(err, syscall.ERROR_ACCESS_DENIED) && !errors.Is(err, syscall.Errno(32)) {
			t.Fatalf("expected an actual non-delete-sharing handle to prevent rename: %v", err)
		}
		var closed chan error
		if release {
			closed = make(chan error, 1)
			time.AfterFunc(35*time.Millisecond, func() { closed <- file.Close() })
		}
		err = RenameDirectory(source, destination)
		if release {
			if closeErr := <-closed; closeErr != nil || err != nil {
				t.Fatalf("rename after handle release: %v (close %v)", err, closeErr)
			}
		} else {
			if !errors.Is(err, syscall.ERROR_ACCESS_DENIED) && !errors.Is(err, syscall.Errno(32)) {
				t.Fatalf("persistent denial: %v", err)
			}
			if _, err := os.Stat(source); err != nil {
				t.Fatalf("source lost after failed rename: %v", err)
			}
			if _, err := os.Stat(destination); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("destination became visible after failed rename: %v", err)
			}
		}
	}
}
