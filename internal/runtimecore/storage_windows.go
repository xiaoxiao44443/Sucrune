package runtimecore

import (
	"os"
	"syscall"
	"unsafe"
)

var moveFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")

func replaceFile(source, destination string) error {
	sourceUTF16, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	destinationUTF16, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	// MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH. Never remove the old
	// destination first: failure must leave the previous complete file intact.
	result, _, callErr := moveFileEx.Call(uintptr(unsafe.Pointer(sourceUTF16)), uintptr(unsafe.Pointer(destinationUTF16)), 0x1|0x8)
	if result == 0 {
		return &os.LinkError{Op: "MoveFileExW", Old: source, New: destination, Err: callErr}
	}
	return nil
}

// Windows does not expose the Unix directory fsync operation. File content is
// flushed before MoveFileExW, which requests a write-through metadata move.
func syncDirectory(string) error { return nil }
