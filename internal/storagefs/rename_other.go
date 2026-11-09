//go:build !windows

package storagefs

import "os"

// RenameDirectory atomically renames the source directory to its destination.
func RenameDirectory(source, destination string) error {
	return os.Rename(source, destination)
}
