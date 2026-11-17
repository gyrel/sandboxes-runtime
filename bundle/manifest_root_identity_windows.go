//go:build windows

package bundle

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// captureBundleRootIdentity obtains the Windows file ID from an open handle.
// os.Lstat's FileInfo resolves its file ID lazily through the saved pathname
// when os.SameFile is called. That can compare a replacement directory after a
// path swap, so capture identity from a handle before the caller opens Root.
func captureBundleRootIdentity(root string) (os.FileInfo, error) {
	absolute, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve bundle root for identity: %w", err)
	}
	path := absolute
	if len(path) >= 260 && !strings.HasPrefix(path, `\\?\`) {
		if strings.HasPrefix(path, `\\`) {
			path = `\\?\UNC\` + strings.TrimPrefix(path, `\\`)
		} else {
			path = `\\?\` + path
		}
	}
	pathp, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("encode bundle root path: %w", err)
	}
	h, err := syscall.CreateFile(pathp, 0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING,
		syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT,
		0)
	if err != nil {
		return nil, fmt.Errorf("open bundle root for identity: %w", err)
	}
	f := os.NewFile(uintptr(h), absolute)
	if f == nil {
		_ = syscall.CloseHandle(h)
		return nil, fmt.Errorf("open bundle root for identity: invalid handle")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat bundle root identity handle: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("bundle root must be a real directory")
	}
	attrs, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok || attrs.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, fmt.Errorf("bundle root must not be a reparse point")
	}
	return info, nil
}
