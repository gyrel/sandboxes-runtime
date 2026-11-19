//go:build !linux

package ctr

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	maxSkillsSnapshotEntries = 10000
	maxSkillsSnapshotFile    = 8 << 20
	maxSkillsSnapshotTotal   = 64 << 20
)

// pinSkillsStore takes a private, immutable snapshot of the store on platforms
// without /proc fd pinning. This deliberately trades Docker's live-edit
// behavior for a source that cannot be swapped after validation: the guest sees
// changes only after the sandbox is recreated or restarted.
func pinSkillsStore(path string) (*skillsPin, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("store must be a real directory")
	}
	dir, err := os.MkdirTemp("", "rheic-skills-store-")
	if err != nil {
		return nil, errors.New("create private skills snapshot")
	}
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- the snapshot root needs owner traversal.
		_ = os.RemoveAll(dir)
		return nil, errors.New("secure private skills snapshot")
	}
	destination := filepath.Join(dir, "store")
	if err := copySkillsSnapshot(path, destination); err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return &skillsPin{snapshotDir: dir, storeSource: destination}, nil
}

type snapshotState struct {
	entries int
	total   int64
}

func copySkillsSnapshot(source, destination string) error {
	if err := os.Mkdir(destination, 0o700); err != nil {
		return errors.New("create private skills snapshot tree")
	}
	state := &snapshotState{}
	if err := filepath.WalkDir(source, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("read skills store during snapshot")
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return errors.New("resolve skills snapshot path")
		}
		if relative == "." {
			return nil
		}
		return state.copyEntry(destination, current, relative, entry)
	}); err != nil {
		return fmt.Errorf("snapshot skills store: %w", err)
	}
	return nil
}

func (s *snapshotState) copyEntry(destination, current, relative string, entry fs.DirEntry) error {
	s.entries++
	if s.entries > maxSkillsSnapshotEntries {
		return errors.New("skills store has too many entries")
	}
	if entry.Type()&os.ModeSymlink != 0 {
		return errors.New("skills store snapshot rejects symlinks")
	}
	target := filepath.Join(destination, relative)
	if entry.IsDir() {
		return os.Mkdir(target, 0o700)
	}
	if !entry.Type().IsRegular() {
		return errors.New("skills store snapshot rejects special files")
	}
	info, err := entry.Info()
	if err != nil || info.Size() > maxSkillsSnapshotFile {
		return errors.New("skills store file is unavailable or too large")
	}
	s.total += info.Size()
	if s.total > maxSkillsSnapshotTotal {
		return errors.New("skills store exceeds the snapshot size limit")
	}
	return copySnapshotFile(current, target, info.Size())
}

func copySnapshotFile(source, destination string, size int64) error {
	input, err := os.Open(source) // #nosec G304 -- walked from the validated store root.
	if err != nil {
		return errors.New("open skills store file")
	}
	defer func() { _ = input.Close() }()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- derived from the validated snapshot root.
	if err != nil {
		return errors.New("create snapshot file")
	}
	written, copyErr := io.Copy(output, io.LimitReader(input, size+1))
	closeErr := output.Close()
	if copyErr != nil || closeErr != nil || written != size {
		return errors.New("copy skills store file")
	}
	return nil
}

func isSkillsPinSource(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func unmountSkillsPin(path string) error {
	return os.RemoveAll(filepath.Dir(path))
}

func skillsIdentity(info os.FileInfo) string {
	return fmt.Sprintf("%d:%d", info.ModTime().UnixNano(), info.Size())
}
