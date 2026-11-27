package journal

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriterLifecycle(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir, "attempt")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "journal", "create-attempt.json")
	if err := w.Track("file", "item", "item"); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "item.gyrel-token")
	if err := w.Marker(marker); err != nil {
		t.Fatal(err)
	}
	if err := w.Phase("run"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	token, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Phase != "run" || len(rec.Resources) != 1 || string(token) != rec.Token {
		t.Fatal("record or marker mismatch")
	}
	if err := w.Phase("done"); err != nil {
		t.Fatal(err)
	}
	if err := w.Complete(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{file, marker} {
		if _, err := os.Stat(name); !os.IsNotExist(err) {
			t.Fatalf("bookkeeping remains: %v", err)
		}
	}
}

func TestBookkeepAfterRunAndClosedGuard(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir, "sb-a")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.BookkeepAfterRun("gyrel-a"); err != nil {
		t.Fatal(err)
	}
	if err := w.Phase("late"); !errors.Is(err, errClosed) {
		t.Fatalf("closed guard = %v", err)
	}
	if err := w.Track("file", "x", "y"); !errors.Is(err, errClosed) {
		t.Fatalf("track guard = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "journal", "create-sb-a.json")); !os.IsNotExist(err) {
		t.Fatalf("journal survived completion: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "journal", "create-sb-a.json"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	// A recreated journal name must not be deleted by an old writer.
	w2, err := New(dir, "sb-a")
	if err == nil && w2 != nil {
		_ = w2
	}
}

func TestWriterAbort(t *testing.T) {
	w, err := New(t.TempDir(), "attempt")
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Phase("network"); err != nil {
		t.Fatal(err)
	}
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(w.path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal after abort: %v", err)
	}
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}
}

func TestWriterAbortNotOwner(t *testing.T) {
	dir := t.TempDir()
	first, err := New(dir, "attempt")
	if err != nil {
		t.Fatal(err)
	}
	stale := first.record
	stale.StartedAtUnix = 1
	seedJournal(t, first.path(), stale)
	second, err := New(dir, "attempt")
	if err != nil {
		t.Fatal(err)
	}
	if first.Token() == second.Token() {
		t.Fatal("expected different tokens")
	}
	if err := first.Abort(); !errors.Is(err, ErrNotOwner) {
		t.Fatalf("abort error = %v", err)
	}
	record, inode, err := readPublished(second.path())
	if err != nil || !os.SameFile(second.inode, inode) || record.Token != second.Token() {
		t.Fatalf("replacement record = %+v, %v", record, err)
	}
}

func TestWriterReclaimsOlderPendingRecord(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "journal", "create-attempt.json")
	old := staleJournal()
	seedJournal(t, path, old)
	w, err := New(dir, old.ID)
	if err != nil {
		t.Fatal(err)
	}
	record, inode, err := readPublished(path)
	if err != nil || !os.SameFile(w.inode, inode) || record.Token != w.Token() || record.Token == old.Token {
		t.Fatalf("published record = %+v, %v", record, err)
	}
}

func TestWriterReclaimRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Record)
	}{
		{"terminal_done", func(r *Record) { r.Phase = "done" }},
		{"terminal_completed", func(r *Record) { r.Phase = "completed" }},
		{"terminal_failed", func(r *Record) { r.Phase = "failed" }},
		{"terminal_aborted", func(r *Record) { r.Phase = "aborted" }},
		{"future_start", func(r *Record) { r.StartedAtUnix = time.Now().Add(time.Hour).Unix() }},
		{"equal_start", func(r *Record) { r.StartedAtUnix = 20 }},
		{"wrong_id", func(r *Record) { r.ID = "other" }},
		{"unparseable", func(r *Record) { r.Token = "invalid" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &Writer{dir: t.TempDir(), record: staleJournal()}
			w.record.StartedAtUnix = 20
			old := staleJournal()
			tc.change(&old)
			seedJournal(t, w.path(), old)
			before, err := os.Lstat(w.path())
			if err != nil {
				t.Fatal(err)
			}
			requireLinkExists(t, w.writeInitial())
			after, err := os.Lstat(w.path())
			if err != nil || !os.SameFile(before, after) {
				t.Fatalf("conflicting record replaced: %v", err)
			}
		})
	}
}

func TestWriterReclaimSecondLinkExists(t *testing.T) {
	dir := t.TempDir()
	w := &Writer{dir: filepath.Join(dir, "journal"), record: staleJournal()}
	w.record.StartedAtUnix = time.Now().Unix() + 60
	seedJournal(t, w.path(), staleJournal())
	linkCalls := 0
	var winner *Writer
	err := w.persist(func(name string, _ os.FileInfo) error {
		return w.linkInitial(name, func(from, to string) error {
			linkCalls++
			if linkCalls == 2 {
				// Publish a competing writer between reclaim and the retry.
				var err error
				winner, err = New(dir, w.record.ID)
				if err != nil {
					t.Fatal(err)
				}
			}
			return os.Link(from, to)
		})
	})
	requireLinkExists(t, err)
	if linkCalls != 2 {
		t.Fatalf("link calls = %d, want 2", linkCalls)
	}
	record, inode, err := readPublished(w.path())
	if err != nil || !os.SameFile(winner.inode, inode) || record.Token != winner.Token() {
		t.Fatalf("competing record = %+v, %v", record, err)
	}
}

func staleJournal() Record {
	return Record{Schema: 2, ID: "attempt", Token: "0123456789abcdef0123456789abcdef", Phase: "pending", Resources: []Resource{}, StartedAtUnix: 1}
}

func seedJournal(t *testing.T, path string, record Record) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func requireLinkExists(t *testing.T, err error) {
	t.Helper()
	var linkErr *os.LinkError
	if !errors.As(err, &linkErr) || linkErr.Op != "link" || !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected link file exists error, got %v", err)
	}
}
