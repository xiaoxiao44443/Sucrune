package runtimecore

import (
	"os"
	"path/filepath"
	"sort"
)

// atomicWrite stages and fsyncs complete content, then publishes it with a
// same-directory rename. A failed publication never truncates the old file.
// A successful rename followed by a directory-sync error may already be visible.
// Actual power-loss durability still depends on the filesystem and storage.
func atomicWrite(destination string, data []byte) error {
	return atomicWriteWorkspaceFile(destination, data, nil)
}

func atomicWriteWorkspaceFile(destination string, data []byte, alias *linkedInode) error {
	parent := filepath.Dir(destination)
	if err := realDirectory(parent); err != nil {
		return err
	}
	file, err := os.CreateTemp(parent, ".pending-file-")
	if err != nil {
		return err
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return publishWorkspaceFile(temporary, destination, alias)
}

func sortFileEntries(entries []FileEntry) {
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
}
