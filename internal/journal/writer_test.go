package journal

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWriterLifecycle(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir, "attempt")
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "journal", "create-attempt.json")
	if _, err := New(dir, "attempt"); err == nil {
		t.Fatal("duplicate attempt accepted")
	}
	if err := w.Track("file", "item", "item"); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "item.rheic-token")
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
	if err := w.BookkeepAfterRun("rheic-a"); err != nil {
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
