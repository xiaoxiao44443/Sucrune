//go:build cgo

package main

/*
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"errors"
	"unsafe"

	"sucrune/internal/runtimecore"
)

// SucruneCoreCall returns an owned UTF-8 JSON string. The caller must release it
// with SucruneCoreFree. Arguments are NUL-terminated UTF-8 and remain caller-owned.
//
//export SucruneCoreCall
func SucruneCoreCall(dataDir *C.char, req *C.char) (result *C.char) {
	defer func() {
		if recover() != nil {
			result = C.CString(string(runtimecore.ErrorJSON(errors.New("unexpected core failure"))))
		}
	}()
	if dataDir == nil || req == nil {
		return C.CString(`{"ok":false,"error":{"code":"invalid_arguments","message":"dataDir and request must not be null"}}`)
	}
	requestLength := C.strnlen(req, C.size_t(runtimecore.MaxRequestBytes+1))
	if requestLength > C.size_t(runtimecore.MaxRequestBytes) {
		return C.CString(`{"ok":false,"error":{"code":"too_large","message":"request exceeds 4 MiB"}}`)
	}
	directoryLength := C.strnlen(dataDir, C.size_t(8193))
	if directoryLength > 8192 {
		return C.CString(`{"ok":false,"error":{"code":"too_large","message":"data directory path exceeds 8192 bytes"}}`)
	}
	return C.CString(string(runtimecore.SharedCallJSON(
		C.GoStringN(dataDir, C.int(directoryLength)),
		[]byte(C.GoStringN(req, C.int(requestLength))),
	)))
}

//export SucruneCoreFree
func SucruneCoreFree(value *C.char) { C.free(unsafe.Pointer(value)) }
