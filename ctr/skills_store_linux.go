//go:build linux

package ctr

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

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
	mountPoint, err := bindSkillsPin(file)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return &skillsPin{store: file, storeSource: mountPoint, mountPoint: mountPoint}, nil
}

// bindSkillsPin exposes the opened descriptor through a private bind mount.
// nerdbox exports files through virtiofs by path, and a /proc fd path can fail
// with EIO during the export; a bind mount keeps the pinned inode reachable by
// a stable path that the shim can share.
func bindSkillsPin(store *os.File) (string, error) {
	dir, err := os.MkdirTemp("", "gyrel-skills-pin-")
	if err != nil {
		return "", errors.New("create shared skills pin directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- the pin root needs owner traversal.
		_ = os.RemoveAll(dir)
		return "", errors.New("secure shared skills pin directory")
	}
	target := filepath.Join(dir, "store")
	if err := os.Mkdir(target, 0o700); err != nil {
		_ = os.RemoveAll(dir)
		return "", errors.New("create shared skills pin target")
	}
	source := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), store.Fd())
	if err := unix.Mount(source, target, "", unix.MS_BIND, ""); err != nil {
		_ = os.RemoveAll(dir)
		return "", fmt.Errorf("bind shared skills pin: %w", err)
	}
	return target, nil
}

func unmountSkillsPin(target string) error {
	err := unix.Unmount(target, unix.MNT_DETACH)
	if err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("unmount shared skills pin: %w", err)
	}
	return os.RemoveAll(filepath.Dir(target))
}

func skillsIdentity(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
}

func isSkillsPinSource(path string) bool {
	return isSkillsPinMount(path)
}

func isSkillsPinMount(path string) bool {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 4 && unescapeMountInfo(fields[4]) == path {
			return true
		}
	}
	return false
}

func unescapeMountInfo(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}
