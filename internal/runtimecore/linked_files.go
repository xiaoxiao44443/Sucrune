package runtimecore

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const inodeMarkerPrefix = "sucrune:inode:v1:"
const inodeStoreSuffix = ".sucrune-inodes-v1"

// The broker creates these markers only when a guest actually needs a hard
// link. The body keeps its original host inode. Its ID is scoped to this
// environment's private store, which is outside its visible workspace.
type linkedInode struct {
	store string
	id    string
	refs  uint32
	body  *os.File
}

func inodeMarkerID(target string) (string, bool) {
	id, ok := strings.CutPrefix(target, inodeMarkerPrefix)
	if !ok || len(id) != 32 {
		return "", false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", false
		}
	}
	return id, true
}

func badInode() error {
	return problem("corrupt_metadata", "invalid project inode metadata or incomplete namespace transaction")
}

// Only the final component may be an internal marker. Resolution never follows
// its text. The caller holds the workspace namespace lock for the entire use.
func inspectLeaf(root, virtual string, allowMissing, readBody bool) (string, *linkedInode, error) {
	if virtual == "/" {
		return root, nil, realDirectory(root)
	}
	parent, err := checkPath(root, path.Dir(virtual), false)
	if err != nil {
		return "", nil, err
	}
	target := filepath.Join(parent, path.Base(virtual))
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) && allowMissing {
		return target, nil, nil
	}
	if err != nil {
		return "", nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		alias, err := inspectMarker(root, target, readBody)
		return target, alias, err
	}
	if !info.IsDir() && !info.Mode().IsRegular() {
		return "", nil, problem("unsafe_path", "special files are not supported")
	}
	return target, nil, nil
}

func inspectMarker(root, target string, readBody bool) (*linkedInode, error) {
	marker, err := os.Readlink(target)
	if err != nil {
		return nil, err
	}
	id, valid := inodeMarkerID(marker)
	if !valid {
		return nil, problem("unsafe_path", "symlinks are not supported")
	}
	store := root + inodeStoreSuffix
	if err := realDirectory(store); err != nil {
		return nil, badInode()
	}
	if _, err := os.Lstat(filepath.Join(store, id+".dirty")); !errors.Is(err, os.ErrNotExist) {
		return nil, badInode()
	}
	body, err := openInodeFile(store, id, !readBody, false)
	if err != nil {
		return nil, badInode()
	}
	actualID, err := fileInodeID(body)
	if err != nil || actualID != id {
		body.Close()
		return nil, badInode()
	}
	refs, err := openInodeFile(store, id+".refs", false, false)
	if err != nil {
		body.Close()
		return nil, badInode()
	}
	data, err := io.ReadAll(io.LimitReader(refs, 5))
	refs.Close()
	if err != nil || len(data) != 4 || binary.LittleEndian.Uint32(data) == 0 {
		body.Close()
		return nil, badInode()
	}
	return &linkedInode{store: store, id: id, refs: binary.LittleEndian.Uint32(data), body: body}, nil
}

// Temp and destination share a directory. Validation, writing and fsync of
// temp finish before the namespace becomes dirty. The broker's recovery
// counts actual markers if a crash interrupts publication.
func publishWorkspaceFile(temp, destination string, alias *linkedInode) error {
	if alias == nil {
		if err := replaceFile(temp, destination); err != nil {
			return err
		}
		return syncDirectory(filepath.Dir(destination))
	}
	dirty := filepath.Join(alias.store, alias.id+".dirty")
	intent, err := os.OpenFile(dirty, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := intent.Close(); err != nil {
		return err
	}
	if err := syncDirectory(alias.store); err != nil {
		return err
	}
	if err := replaceFile(temp, destination); err != nil {
		// A failed rename leaves the old name and count intact. Failure to
		// remove the dirty flag is recoverable by the broker.
		if clearErr := os.Remove(dirty); clearErr != nil {
			return errors.Join(err, clearErr)
		}
		return errors.Join(err, syncDirectory(alias.store))
	}
	if err := syncDirectory(filepath.Dir(destination)); err != nil {
		return err
	}
	if alias.refs == 1 {
		if err := os.Remove(filepath.Join(alias.store, alias.id+".refs")); err != nil {
			return err
		}
		if err := os.Remove(filepath.Join(alias.store, alias.id)); err != nil {
			return err
		}
	} else {
		refs, err := openInodeFile(alias.store, alias.id+".refs", false, true)
		if err != nil {
			return err
		}
		var data [4]byte
		binary.LittleEndian.PutUint32(data[:], alias.refs-1)
		_, err = refs.WriteAt(data[:], 0)
		if err == nil {
			err = refs.Sync()
		}
		if err := errors.Join(err, refs.Close()); err != nil {
			return err
		}
	}
	if err := syncDirectory(alias.store); err != nil {
		return err
	}
	if err := os.Remove(dirty); err != nil {
		return err
	}
	return syncDirectory(alias.store)
}
