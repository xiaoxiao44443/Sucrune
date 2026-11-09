//go:build !linux

package runtimecore

import (
	"os"
	"path/filepath"
)

// Non-Linux development hosts have no native Android broker sharing the
// workspace. The one-manager Service lock serializes their namespace calls.
func lockWorkspace(string, bool) (func(), error) { return func() {}, nil }

func openInodeFile(store, name string, metadataOnly, writable bool) (*os.File, error) {
	path := filepath.Join(store, name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, badInode()
	}
	flags := os.O_RDONLY
	if writable {
		flags = os.O_WRONLY
	}
	file, err := os.OpenFile(path, flags, 0)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) || !privateInodeFile(file) {
		file.Close()
		return nil, badInode()
	}
	return file, nil
}
