package journal

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Writer persists the state of one create attempt.
type Writer struct {
	dir     string
	record  Record
	markers []string
	closed  bool
	inode   os.FileInfo
}

// ErrNotOwner indicates that the journal path no longer belongs to the writer.
var ErrNotOwner = errors.New("journal writer does not own record")

// journalMutation serializes checked removals and replacements in this process.
var journalMutation sync.Mutex

const initialPhase = "pending"

var errClosed = errors.New("journal writer already completed")

// New starts a durable create record in stateDir.
func New(stateDir, id string) (*Writer, error) {
	return NewWithOpID(stateDir, id, "")
}

// NewWithOpID starts a create record with an optional validated operation ID.
func NewWithOpID(stateDir, id, opID string) (*Writer, error) {
	var token [16]byte
	if _, err := rand.Read(token[:]); err != nil {
		return nil, err
	}
	w := &Writer{dir: filepath.Join(stateDir, "journal"), record: Record{Schema: 2, ID: id, OpID: opID, Token: hex.EncodeToString(token[:]), Phase: initialPhase, Resources: []Resource{}, StartedAtUnix: time.Now().Unix()}}
	if err := w.record.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(w.dir, 0700); err != nil {
		return nil, err
	}
	if err := w.writeInitial(); err != nil {
		if w.inode != nil {
			_ = w.Abort()
		}
		return nil, err
	}
	return w, nil
}

// Token returns the ownership token for this attempt.
func (w *Writer) Token() string { return w.record.Token }

// Phase persists a phase transition.
func (w *Writer) Phase(phase string) error {
	if w.closed {
		return errClosed
	}
	old := w.record.Phase
	w.record.Phase = phase
	if err := w.write(); err != nil {
		w.record.Phase = old
		return err
	}
	return nil
}

// Track records a resource before it is exposed.
func (w *Writer) Track(kind, nativeID, relPath string) error {
	if w.closed {
		return errClosed
	}
	w.record.Resources = append(w.record.Resources, Resource{Kind: kind, NativeID: nativeID, RelPath: relPath, Marked: true})
	if err := w.write(); err != nil {
		w.record.Resources = w.record.Resources[:len(w.record.Resources)-1]
		return err
	}
	return nil
}

// Marker creates a token marker exclusively and durably.
func (w *Writer) Marker(path string) error {
	if w.closed {
		return errClosed
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) // #nosec G304 -- path is a runtime-owned resource dir chosen by create(), never user input; O_EXCL prevents overwrite
	if err != nil {
		return err
	}
	_, writeErr := f.WriteString(w.record.Token)
	err = errors.Join(writeErr, f.Sync(), f.Close())
	if err != nil {
		return err
	}
	w.markers = append(w.markers, path)
	return syncDir(filepath.Dir(path))
}

// Abort retires the record for an unsuccessful create.
func (w *Writer) Abort() error {
	journalMutation.Lock()
	defer journalMutation.Unlock()

	path := w.path()
	err := w.checkOwner(path)
	if err == nil {
		err = os.Remove(path)
	}
	if errors.Is(err, os.ErrNotExist) {
		w.closed = true
		return nil
	}
	if err != nil {
		return err
	}
	w.closed = true
	return syncDir(w.dir)
}

func (w *Writer) path() string {
	return filepath.Join(w.dir, "create-"+w.record.ID+".json")
}

func (w *Writer) checkOwner(path string) error {
	record, inode, err := readPublished(path)
	if err != nil {
		return err
	}
	if w.inode == nil || !os.SameFile(w.inode, inode) || record.ID != w.record.ID || record.Token != w.record.Token {
		return fmt.Errorf("%s: %w", path, ErrNotOwner)
	}
	return nil
}

// Complete removes bookkeeping after successful transfer of ownership.
func (w *Writer) Complete() error {
	journalMutation.Lock()
	defer journalMutation.Unlock()

	if w.closed {
		return errClosed
	}
	if err := w.checkOwner(w.path()); err != nil {
		return err
	}
	for _, marker := range w.markers {
		if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := syncDir(filepath.Dir(marker)); err != nil {
			return err
		}
	}
	if err := os.Remove(w.path()); err != nil {
		return err
	}
	if err := syncDir(w.dir); err != nil {
		return err
	}
	w.closed = true
	return nil
}

// writeInitial publishes a fully synced record, reclaiming an older attempt once.
func (w *Writer) writeInitial() error {
	return w.persist(w.publishInitial)
}

func (w *Writer) publishInitial(name string, inode os.FileInfo) error {
	if err := w.linkInitial(name, os.Link); err != nil {
		return err
	}
	w.inode = inode
	return syncDir(w.dir)
}

func (w *Writer) linkInitial(name string, link func(string, string) error) error {
	path := w.path()
	err := link(name, path)
	if !errors.Is(err, os.ErrExist) || !w.reclaim(path) {
		return err
	}
	return link(name, path)
}

func (w *Writer) reclaim(path string) bool {
	journalMutation.Lock()
	defer journalMutation.Unlock()

	record, _, err := readPublished(path)
	if err != nil || record.ID != w.record.ID || record.StartedAtUnix >= w.record.StartedAtUnix {
		return false
	}
	switch record.Phase {
	case initialPhase, "network", "run":
		return os.Remove(path) == nil
	default:
		return false
	}
}

func readPublished(path string) (Record, os.FileInfo, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return Record{}, nil, err
	}
	if !before.Mode().IsRegular() {
		return Record{}, nil, fmt.Errorf("%s: %w", path, ErrNotOwner)
	}
	f, err := os.Open(path) // #nosec G304 -- runtime-owned journal path
	if err != nil {
		return Record{}, nil, err
	}
	opened, statErr := f.Stat()
	data, readErr := io.ReadAll(io.LimitReader(f, MaxRecordSize+1))
	if err := errors.Join(statErr, readErr, f.Close()); err != nil {
		return Record{}, nil, err
	}
	record, parseErr := Parse(data)
	current, err := os.Lstat(path)
	if err != nil {
		return Record{}, nil, err
	}
	if parseErr != nil || !os.SameFile(before, opened) || !os.SameFile(opened, current) {
		return Record{}, nil, fmt.Errorf("%s: %w", path, ErrNotOwner)
	}
	return record, current, nil
}

func (w *Writer) write() error {
	if err := w.record.Validate(); err != nil {
		return err
	}
	return w.persist(w.replace)
}

func (w *Writer) replace(name string, inode os.FileInfo) error {
	journalMutation.Lock()
	defer journalMutation.Unlock()

	path := w.path()
	if err := w.checkOwner(path); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	w.inode = inode
	return syncDir(w.dir)
}

func (w *Writer) persist(publish func(string, os.FileInfo) error) error {
	data, err := json.Marshal(w.record)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(w.dir, ".create-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer func() { _ = os.Remove(name) }()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	inode, statErr := f.Stat()
	if err := errors.Join(err, statErr, f.Close()); err != nil {
		return err
	}
	return publish(name, inode)
}

// syncDir flushes directory entries so the rename/link is durable. Windows
// has no fsync semantics for directory handles (the API errors), so durable
// publication there relies on the file-level Sync plus NTFS metadata
// journaling; skipping the directory flush is documented, not silent.
func syncDir(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(path) // #nosec G304 -- journal dir owned by the backend, not user input
	if err != nil {
		return err
	}
	if err := errors.Join(f.Sync(), f.Close()); err != nil {
		return fmt.Errorf("sync journal directory: %w", err)
	}
	return nil
}

// BookkeepAfterRun records the created container, advances to done and
// completes the journal in one call so callers have a single failure point to
// unwind. A failure leaves the journal on disk for recovery.
func (w *Writer) BookkeepAfterRun(nativeID string) error {
	if err := w.Track("container", nativeID, ""); err != nil {
		return err
	}
	if err := w.Phase("done"); err != nil {
		return err
	}
	return w.Complete()
}
