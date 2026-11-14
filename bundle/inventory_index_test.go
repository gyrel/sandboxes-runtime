package bundle

import "testing"

func TestListedDirectoryIndexContainsOnlyRequiredAncestors(t *testing.T) {
	got := listedDirectoryIndex(map[string]FileItem{
		"bin/nerdbox/shim": {},
		"kernel":           {},
	})
	for _, name := range []string{"bin", "bin/nerdbox"} {
		if _, ok := got[name]; !ok {
			t.Errorf("directory index lacks %q", name)
		}
	}
	if _, ok := got["."]; ok {
		t.Fatal("directory index includes bundle root")
	}
	if len(got) != 2 {
		t.Fatalf("directory index has %d entries, want 2", len(got))
	}
}
