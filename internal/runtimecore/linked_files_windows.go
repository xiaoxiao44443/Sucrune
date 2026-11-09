package runtimecore

import (
	"fmt"
	"os"
	"syscall"
)

func privateInodeFile(file *os.File) bool {
	// NTFS exposes file identity, physical link count and reparse state.
	// This development host uses inherited Windows ACLs for the private store.
	var info syscall.ByHandleFileInformation
	err := syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &info)
	return err == nil && info.NumberOfLinks == 1 && info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

func fileInodeID(file *os.File) (string, error) {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &info); err != nil {
		return "", err
	}
	ino := uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)
	return fmt.Sprintf("%016x%016x", uint64(info.VolumeSerialNumber), ino), nil
}
