package journal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T, resources ...string) string {
	t.Helper()
	d := t.TempDir()
	if err := os.Mkdir(filepath.Join(d, "journal"), 0700); err != nil {
		t.Fatal(err)
	}
	rec := Record{Schema: 1, ID: "test", Token: "0123456789abcdef0123456789abcdef", Phase: "run", Resources: []Resource{}, StartedAtUnix: 1}
	for _, p := range resources {
		rec.Resources = append(rec.Resources, Resource{Kind: "file", RelPath: p, Marked: true})
	}
	data, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(d, "journal/create-test.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	return d
}
func put(t *testing.T, d, p, content string) {
	t.Helper()
	f := filepath.Join(d, p)
	if err := os.MkdirAll(filepath.Dir(f), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
func TestRecover(t *testing.T) {
	token := "0123456789abcdef0123456789abcdef"
	t.Run("owned and idempotent", func(t *testing.T) {
		d := fixture(t, "tree")
		put(t, d, "tree/sub/file", "x")
		put(t, d, "tree.rheic-token", token)
		for i := 0; i < 2; i++ {
			f, e := RecoverDir(d, time.Now)
			if e != nil || len(f) != 0 {
				t.Fatalf("%v %v", f, e)
			}
		}
		if _, e := os.Lstat(filepath.Join(d, "tree")); !os.IsNotExist(e) {
			t.Fatal(e)
		}
		if _, e := os.Stat(filepath.Join(d, "journal/create-test.json")); !os.IsNotExist(e) {
			t.Fatal(e)
		}
	})
	t.Run("mismatch retains journal after partial cleanup", func(t *testing.T) {
		d := fixture(t, "a", "b")
		put(t, d, "a", "a")
		put(t, d, "a.rheic-token", token)
		put(t, d, "b", "b")
		put(t, d, "b.rheic-token", "wrong")
		f, e := RecoverDir(d, time.Now)
		if e != nil || len(f) != 1 || f[0].Reason != MarkerMismatch {
			t.Fatalf("%v %v", f, e)
		}
		for _, p := range []string{"b", "journal/create-test.json"} {
			if _, e := os.Stat(filepath.Join(d, p)); e != nil {
				t.Fatal(e)
			}
		}
		if _, e := os.Stat(filepath.Join(d, "a")); !os.IsNotExist(e) {
			t.Fatal(e)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		d := fixture(t, "link")
		if e := os.Symlink("target", filepath.Join(d, "link")); e != nil {
			t.Fatal(e)
		}
		put(t, d, "link.rheic-token", token)
		f, e := RecoverDir(d, time.Now)
		if e != nil || len(f) != 1 || f[0].Reason != SymlinkRefused {
			t.Fatalf("%v %v", f, e)
		}
	})
	t.Run("traversal", func(t *testing.T) {
		if _, e := Parse([]byte(strings.Replace(validRecord, "run/fifo", "../fifo", 1))); e == nil {
			t.Fatal("accepted traversal")
		}
		d := fixture(t)
		root, e := os.OpenRoot(d)
		if e != nil {
			t.Fatal(e)
		}
		defer root.Close()
		r, e := recoverResource(root, "../escape", token)
		if e != nil || r != OutsideRoot {
			t.Fatalf("%v %v", r, e)
		}
	})
	t.Run("orphan", func(t *testing.T) {
		d := fixture(t)
		put(t, d, "journal/.create-orphan", "x")
		f, e := RecoverDir(d, time.Now)
		if e != nil || len(f) != 1 || f[0].Reason != TempOrphan {
			t.Fatalf("%v %v", f, e)
		}
		if _, e := os.Stat(filepath.Join(d, "journal/.create-orphan")); e != nil {
			t.Fatal(e)
		}
	})
}
func TestRecoverConcurrentUnrelatedWriter(t *testing.T) {
	d := fixture(t)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			w, e := New(d, "other")
			if e == nil {
				_ = w.Phase("run")
				_ = w.Complete()
			}
		}
	}()
	for i := 0; i < 20; i++ {
		_, _ = RecoverDir(d, time.Now)
	}
	wg.Wait()
}
