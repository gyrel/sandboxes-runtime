package journal

import (
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
