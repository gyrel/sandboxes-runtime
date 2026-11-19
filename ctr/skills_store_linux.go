//go:build linux

package ctr

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// pinSkillsStore opens the store without following any symlink component and
// keeps the descriptor for the lifetime of the sandbox. openat2 with
// RESOLVE_NO_SYMLINKS prevents both a swapped final component and a symlinked
// parent from redirecting the mount.
func pinSkillsStore(path string) (*skillsPin, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, fmt.Errorf("open store without symlinks: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.IsDir() {
		_ = file.Close()
		return nil, errors.New("store is not a directory")
	}
	return &skillsPin{store: file}, nil
}
