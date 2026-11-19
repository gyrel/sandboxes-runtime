package ctr

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	runtime "github.com/rheic/sandboxes-runtime"
)

const skillsLabel = "io.rheic.skills"

// skillsPin holds the opened store directory used as a bind source. The path
// passed to containerd is /proc/<pid>/fd/<n>, so a rename or replacement of
// the configured path cannot redirect the mount after validation.
type skillsPin struct {
	store       *os.File
	helperDir   string
	snapshotDir string
	storeSource string
	mountPoint  string
}

// closeSkillsPin closes a pin that has not been handed to a created container.
func closeSkillsPin(p **skillsPin) {
	if *p == nil {
		return
	}
	_ = (*p).Close()
}

func (p *skillsPin) Close() error {
	if p == nil {
		return nil
	}
	var err error
	if p.store != nil {
		err = p.store.Close()
	}
	if p.helperDir != "" {
		err = errors.Join(err, os.RemoveAll(p.helperDir))
	}
	if p.mountPoint != "" {
		err = errors.Join(err, unmountSkillsPin(p.mountPoint))
	}
	if p.snapshotDir != "" {
		err = errors.Join(err, os.RemoveAll(p.snapshotDir))
	}
	return err
}

// openSkills validates the requested shared-store mode and returns the mounts
// plus labels for a read-only skills mount. Read-write delivery needs a safe
// per-agent target directory and remains unsupported.
func (b *Backend) openSkills(cfg *runtime.Config) (*skillsPin, []Mount, []string, error) {
	if cfg.Skills == nil {
		return nil, nil, nil, nil
	}
	if !cfg.Skills.ReadOnly {
		return nil, nil, nil, errors.New("shared skills read-write mode is not supported")
	}
	if cfg.Skills.AgentPath != "" {
		return nil, nil, nil, errors.New("shared skills read-only mode must not set an agent path")
	}
	if !filepath.IsAbs(cfg.Skills.StorePath) || filepath.Clean(cfg.Skills.StorePath) != cfg.Skills.StorePath || cfg.Skills.StorePath == "/" {
		return nil, nil, nil, errors.New("shared skills store must be a clean absolute non-root path")
	}
	if !filepath.IsAbs(cfg.Skills.HelperPath) || filepath.Clean(cfg.Skills.HelperPath) != cfg.Skills.HelperPath {
		return nil, nil, nil, errors.New("shared skills helper must be a clean absolute path")
	}
	helperDir, helperPath, err := stageSkillsHelper(cfg.Skills.HelperPath)
	if err != nil {
		return nil, nil, nil, err
	}
	pin, err := pinSkillsStore(cfg.Skills.StorePath)
	if err != nil {
		_ = os.RemoveAll(helperDir)
		return nil, nil, nil, fmt.Errorf("pin shared skills store: %w", err)
	}
	pin.helperDir = helperDir
	storeSource := pin.storeSource
	if storeSource == "" {
		storeSource = fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), pin.store.Fd())
	}
	mounts := []Mount{
		{
			Source:            storeSource,
			Destination:       runtime.SkillsStoreGuestPath,
			ReadOnly:          true,
			RecursiveReadOnly: true,
		},
		{
			Source:      helperPath,
			Destination: runtime.SkillsHelperGuestPath,
			ReadOnly:    true,
		},
	}
	return pin, mounts, []string{skillsLabel + "=readonly"}, nil
}

// rememberSkills records the pin only after the container exists, so a failed
// create closes it through cleanupFailedCreate -> Delete.
func (b *Backend) rememberSkills(id string, pin *skillsPin) {
	if pin == nil {
		return
	}
	b.skillsMu.Lock()
	defer b.skillsMu.Unlock()
	if b.skillsPins == nil {
		b.skillsPins = make(map[string]*skillsPin)
	}
	b.skillsPins[id] = pin
}

func (b *Backend) skillsPin(id string) *skillsPin {
	b.skillsMu.Lock()
	defer b.skillsMu.Unlock()
	return b.skillsPins[id]
}

func (b *Backend) forgetSkills(id string) error {
	b.skillsMu.Lock()
	pin := b.skillsPins[id]
	delete(b.skillsPins, id)
	b.skillsMu.Unlock()
	if pin == nil {
		return nil
	}
	return pin.Close()
}

// stageSkillsHelper copies the validated helper into a private 0700 directory.
// The nerdbox shim exports a file by sharing its parent directory with the
// guest, so mounting the installation directory directly would expose every
// neighboring file. The private directory contains only this binary.
func stageSkillsHelper(path string) (string, string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o111 == 0 {
		return "", "", errors.New("shared skills helper must be a regular executable file")
	}
	source, err := os.Open(path) // #nosec G304 -- path is validated as an absolute helper location before opening.
	if err != nil {
		return "", "", errors.New("shared skills helper is unavailable")
	}
	defer func() { _ = source.Close() }()
	opened, err := source.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", "", errors.New("shared skills helper changed while opening")
	}
	dir, err := os.MkdirTemp("", "rheic-skills-helper-")
	if err != nil {
		return "", "", errors.New("create private skills helper directory")
	}
	if err := os.Chmod(dir, 0o700); err != nil { // #nosec G302 -- a directory needs owner execute to stage the helper.
		_ = os.RemoveAll(dir)
		return "", "", errors.New("secure private skills helper directory")
	}
	destination := filepath.Join(dir, "sandbox-guest")
	target, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700) // #nosec G302,G304 -- the staged guest helper must be executable.
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", "", errors.New("create private skills helper")
	}
	written, copyErr := io.Copy(target, io.LimitReader(source, 1<<28))
	closeErr := target.Close()
	if copyErr != nil || closeErr != nil || written != opened.Size() {
		_ = os.RemoveAll(dir)
		return "", "", errors.New("copy private skills helper")
	}
	return dir, destination, nil
}
