//go:build linux

package ctr

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPinSkillsStoreUsesOpenedDirectory(t *testing.T) {
	store := t.TempDir()
	marker := filepath.Join(store, "marker")
	if err := os.WriteFile(marker, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	pin, err := pinSkillsStore(store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pin.Close() }()
	source := fmt.Sprintf("/proc/self/fd/%d", pin.store.Fd())
	if _, err := os.Stat(filepath.Join(source, "marker")); err != nil {
		t.Fatalf("pinned descriptor unavailable: %v", err)
	}
	moved := store + "-moved"
	if err := os.Rename(store, moved); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(source, "marker")); err != nil {
		t.Fatalf("pinned descriptor followed the rename: %v", err)
	}
}

func TestPinSkillsStoreRejectsSymlink(t *testing.T) {
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if _, err := pinSkillsStore(link); err == nil {
		t.Fatal("symlinked store was pinned")
	}
}

func TestPinnedStoreResolvesFromAnotherProcess(t *testing.T) {
	store := t.TempDir()
	if err := os.WriteFile(filepath.Join(store, "marker"), []byte("cross-process"), 0o600); err != nil {
		t.Fatal(err)
	}
	pin, err := pinSkillsStore(store)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = pin.Close() }()
	path := fmt.Sprintf("/proc/%d/fd/%d/marker", os.Getpid(), pin.store.Fd())
	out, err := exec.Command("/bin/sh", "-c", "cat "+path).Output()
	if err != nil || string(out) != "cross-process" {
		t.Fatalf("out=%q err=%v", out, err)
	}
	if err := os.Rename(store, store+"-moved"); err != nil {
		t.Fatal(err)
	}
	out, err = exec.Command("/bin/sh", "-c", "cat "+path).Output()
	if err != nil || string(out) != "cross-process" {
		t.Fatalf("after rename: out=%q err=%v", out, err)
	}
}
