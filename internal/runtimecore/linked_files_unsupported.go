//go:build !windows && !linux

package runtimecore

import "os"

// No broker targets these systems. Ordinary project files remain supported,
// and an internal marker cannot resolve without a trusted file identity.
func fileInodeID(*os.File) (string, error) { return "", badInode() }
func privateInodeFile(*os.File) bool       { return false }
