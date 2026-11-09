package runtimecore

import (
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
)

type FileEntry struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
	Size int64  `json:"size"`
}

// File paths use Linux-style separators, whether the manager runs on Android or
// a development host. Leading / names the environment workspace, never the host
// root. Reject suspicious components before cleaning rather than hiding '..'.
func virtualPath(input string) (string, error) {
	if len(input) > 4096 || strings.ContainsAny(input, "\\:\x00") || strings.ContainsFunc(input, unicode.IsControl) {
		return "", problem("unsafe_path", "path must use bounded Linux-style components")
	}
	for _, component := range strings.Split(input, "/") {
		if component == ".." {
			return "", problem("unsafe_path", "parent traversal is not allowed")
		}
		if component == "" || component == "." {
			continue
		}
		if len(component) > 255 || strings.HasSuffix(component, ".") || strings.HasSuffix(component, " ") {
			return "", problem("unsafe_path", "ambiguous or oversized path component")
		}
		base := strings.ToUpper(strings.SplitN(component, ".", 2)[0])
		if base == "CON" || base == "PRN" || base == "AUX" || base == "NUL" ||
			(len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) && base[3] >= '1' && base[3] <= '9') {
			return "", problem("unsafe_path", "reserved path component")
		}
	}
	return path.Clean("/" + input), nil
}

// checkPath rejects symlinks and special files at every existing component.
// Manager-owned directories are assumed: this check does not promise protection
// from a same-UID process racing a rename between check and use.
func checkPath(root, virtual string, allowMissingFinal bool) (string, error) {
	if err := realDirectory(root); err != nil {
		return "", err
	}
	components := strings.Split(strings.TrimPrefix(virtual, "/"), "/")
	current := root
	for i, component := range components {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) && allowMissingFinal && i == len(components)-1 {
			return current, nil
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return "", problem("unsafe_path", "symlinks and special files are not supported")
		}
		if i < len(components)-1 && !info.IsDir() {
			return "", problem("invalid_arguments", "path parent is not a directory")
		}
	}
	return current, nil
}

func (s *Service) fileCall(req request) (any, error) {
	paths, err := s.catalog.Paths(req.EnvID)
	if err != nil {
		return nil, err
	}
	virtual, err := virtualPath(req.Path)
	if err != nil {
		return nil, err
	}
	unlock, err := lockWorkspace(paths.Workspace, req.Op == "file.write" || req.Op == "file.mkdir")
	if err != nil {
		return nil, err
	}
	defer unlock()
	if req.Op == "file.mkdir" {
		return makeDirectories(paths.Workspace, virtual)
	}
	target, alias, err := inspectLeaf(paths.Workspace, virtual, req.Op == "file.write", req.Op == "file.read")
	if err != nil {
		return nil, err
	}
	if alias != nil && req.Op != "file.read" {
		alias.body.Close()
	}
	switch req.Op {
	case "file.write":
		if virtual == "/" {
			return nil, problem("invalid_arguments", "cannot write the workspace root as a file")
		}
		if base64.StdEncoding.DecodedLen(len(req.ContentBase64)) > MaxFileBytes+2 {
			return nil, problem("too_large", "file exceeds 1 MiB")
		}
		content, err := base64.StdEncoding.DecodeString(req.ContentBase64)
		if err != nil {
			return nil, problem("invalid_arguments", "content_base64 is not valid base64")
		}
		if len(content) > MaxFileBytes {
			return nil, problem("too_large", "file exceeds 1 MiB")
		}
		if info, err := os.Lstat(target); err == nil && alias == nil && !info.Mode().IsRegular() {
			return nil, problem("unsafe_path", "write destination is not a regular file")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if err := atomicWriteWorkspaceFile(target, content, alias); err != nil {
			return nil, err
		}
		return map[string]any{"path": virtual, "size": len(content)}, nil
	case "file.read":
		var file *os.File
		if alias != nil {
			file = alias.body
		} else {
			if virtual == "/" {
				return nil, problem("invalid_arguments", "read requires a regular file")
			}
			file, err = os.OpenInRoot(paths.Workspace, strings.TrimPrefix(virtual, "/"))
			if err != nil {
				return nil, err
			}
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, problem("invalid_arguments", "read requires a regular file")
		}
		if info.Size() > MaxFileBytes {
			return nil, problem("too_large", "file exceeds 1 MiB")
		}
		content, err := io.ReadAll(io.LimitReader(file, MaxFileBytes+1))
		if err != nil {
			return nil, err
		}
		if len(content) > MaxFileBytes {
			return nil, problem("too_large", "file exceeds 1 MiB")
		}
		return map[string]any{"path": virtual, "size": len(content), "content_base64": base64.StdEncoding.EncodeToString(content)}, nil
	case "file.list":
		if err := realDirectory(target); err != nil {
			return nil, err
		}
		relative := strings.TrimPrefix(virtual, "/")
		if relative == "" {
			relative = "."
		}
		directory, err := os.OpenInRoot(paths.Workspace, relative)
		if err != nil {
			return nil, err
		}
		defer directory.Close()
		entries, err := directory.ReadDir(4097)
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		if len(entries) > 4096 {
			return nil, problem("too_large", "directory exceeds 4096 entries")
		}
		result := make([]FileEntry, 0, len(entries))
		for _, entry := range entries {
			info, err := entry.Info()
			if err != nil {
				return nil, err
			}
			kind := "file"
			if info.IsDir() {
				kind = "directory"
			} else if info.Mode()&os.ModeSymlink != 0 {
				linked, err := inspectMarker(paths.Workspace, filepath.Join(target, entry.Name()), false)
				if err != nil {
					return nil, err
				}
				info, err = linked.body.Stat()
				linked.body.Close()
				if err != nil {
					return nil, err
				}
			} else if !info.Mode().IsRegular() {
				return nil, problem("unsafe_path", "directory contains a symlink or special file")
			}
			result = append(result, FileEntry{Name: entry.Name(), Kind: kind, Size: info.Size()})
		}
		sortFileEntries(result)
		return map[string]any{"path": virtual, "entries": result}, nil
	}
	return nil, problem("unsupported_operation", "unknown file operation")
}

func makeDirectories(root, virtual string) (any, error) {
	if err := realDirectory(root); err != nil {
		return nil, err
	}
	current := root
	for _, component := range strings.Split(strings.TrimPrefix(virtual, "/"), "/") {
		if component == "" {
			continue
		}
		parent := current
		current = filepath.Join(current, component)
		if err := os.Mkdir(current, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, err
		}
		if err := realDirectory(current); err != nil {
			return nil, err
		}
		if err := syncDirectory(parent); err != nil {
			return nil, err
		}
	}
	return map[string]string{"path": virtual}, nil
}
