package storagefs

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// RenameDirectory atomically renames a directory, allowing time for Windows
// readers that temporarily prevent renaming it. A persistent denial returns
// the underlying filesystem error.
func RenameDirectory(source, destination string) error {
	const sharingViolation = syscall.Errno(32)
	deadline := time.Now().Add(time.Second)
	delay := 2 * time.Millisecond
	for {
		err := os.Rename(source, destination)
		if !errors.Is(err, syscall.ERROR_ACCESS_DENIED) && !errors.Is(err, sharingViolation) {
			return err
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return err
		}
		time.Sleep(min(delay, remaining))
		delay = min(2*delay, 64*time.Millisecond)
	}
}
