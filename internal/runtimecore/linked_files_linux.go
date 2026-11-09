package runtimecore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func lockWorkspace(workspace string, exclusive bool) (func(), error) {
	// The guest can acquire flock on its visible root. Lock the manager-owned
	// parent directory instead, using an independent open description per call.
	fd, err := syscall.Open(filepath.Dir(workspace), syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	for {
		err = syscall.Flock(fd, mode)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		syscall.Close(fd)
		return nil, err
	}
	return func() { syscall.Close(fd) }, nil
}

func openInodeFile(store, name string, metadataOnly, writable bool) (*os.File, error) {
	dir, err := syscall.Open(store, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dir)
	var st syscall.Stat_t
	if err := syscall.Fstat(dir, &st); err != nil {
		return nil, err
	}
	uid := uint32(os.Geteuid())
	if st.Uid != uid || st.Mode&0777 != 0700 {
		return nil, badInode()
	}
	flags := syscall.O_CLOEXEC | syscall.O_NOFOLLOW | syscall.O_NONBLOCK
	if metadataOnly {
		const linuxOPath = 0x200000
		flags |= linuxOPath
	} else if writable {
		flags |= syscall.O_WRONLY
	}
	fd, err := syscall.Openat(dir, name, flags, 0)
	if err != nil {
		return nil, err
	}
	if err := syscall.Fstat(fd, &st); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	// Bodies retain guest-selected access bits. Refcounts are manager-private
	// four-byte records. Neither may have a second physical link outside this store.
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Uid != uid || st.Nlink != 1 ||
		(strings.HasSuffix(name, ".refs") && (st.Mode&0077 != 0 || st.Size != 4)) {
		syscall.Close(fd)
		return nil, badInode()
	}
	return os.NewFile(uintptr(fd), name), nil
}

func fileInodeID(file *os.File) (string, error) {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(file.Fd()), &st); err != nil {
		return "", err
	}
	return fmt.Sprintf("%016x%016x", uint64(st.Dev), uint64(st.Ino)), nil
}
