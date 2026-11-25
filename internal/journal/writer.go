package journal

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// Writer persists the state of one create attempt.
type Writer struct {
	dir     string
	record  Record
	markers []string
	closed  bool
}

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
	w := &Writer{dir: filepath.Join(stateDir, "journal"), record: Record{Schema: 2, ID: id, OpID: opID, Token: hex.EncodeToString(token[:]), Phase: "pending", Resources: []Resource{}, StartedAtUnix: time.Now().Unix()}}
	if err := w.record.Validate(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(w.dir, 0700); err != nil {
		return nil, err
	}
	if err := w.writeInitial(); err != nil {
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

// Complete removes bookkeeping after successful transfer of ownership.
func (w *Writer) Complete() error {
	if w.closed {
		return errClosed
	}
	for _, marker := range w.markers {
		if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := syncDir(filepath.Dir(marker)); err != nil {
			return err
		}
	}
	if err := os.Remove(filepath.Join(w.dir, "create-"+w.record.ID+".json")); err != nil {
		return err
	}
	if err := syncDir(w.dir); err != nil {
		return err
	}
	w.closed = true
	return nil
}

// writeInitial publishes a fully synced record without replacing another attempt.
func (w *Writer) writeInitial() error {
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
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err := os.Link(name, filepath.Join(w.dir, "create-"+w.record.ID+".json")); err != nil {
		return err
	}
	return syncDir(w.dir)
}

func (w *Writer) write() error {
	if err := w.record.Validate(); err != nil {
		return err
	}
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
	err = errors.Join(err, f.Close())
	if err != nil {
		return err
	}
	if err := os.Rename(name, filepath.Join(w.dir, "create-"+w.record.ID+".json")); err != nil {
		return err
	}
	return syncDir(w.dir)
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
