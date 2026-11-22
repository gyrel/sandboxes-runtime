package ocilayer

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func readTarNames(t *testing.T, raw []byte) []string {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(raw))
	var names []string
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return names
		}
		if err != nil {
			t.Fatalf("read tar: %v", err)
		}
		names = append(names, hdr.Name)
	}
}

func TestLayerTarEncodesAllEntryTypes(t *testing.T) {
	var buf bytes.Buffer
	entries := []DiffEntry{
		{Path: "etc", Type: "dir"},
		{Path: "etc/passwd", Type: "reg", Size: 4, Reader: strings.NewReader("root"), Mode: 0o600},
		{Path: "etc/motd", Type: "whiteout"},
		{Path: "var/lib/docker", Type: "opaque"},
		{Path: "usr/bin/tool", Type: "symlink", Link: "../share/tool"},
	}
	desc, err := LayerTar(&buf, freshEntries(entries))
	if err != nil {
		t.Fatal(err)
	}
	if !desc.Digest.Valid() || desc.MediaType != MediaLayer || desc.Size != int64(buf.Len()) {
		t.Fatalf("descriptor mismatch: %+v bytes=%d", desc, buf.Len())
	}
	names := readTarNames(t, buf.Bytes())
	want := []string{"etc/", "etc/passwd", "etc/.wh.motd", "var/lib/docker/.wh..wh..opq", "usr/bin/tool"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("names=%v want %v", names, want)
	}
	// Digest is content-addressed: same bytes, same digest.
	again := &bytes.Buffer{}
	desc2, err := LayerTar(again, freshEntries(entries))
	if err != nil || desc2.Digest != desc.Digest || again.Len() != buf.Len() {
		t.Fatalf("nondeterministic layer: %v %+v vs %+v", err, desc2, desc)
	}
}

func TestLayerTarRejectsUnsafeEntries(t *testing.T) {
	cases := []DiffEntry{
		{Path: "/etc/passwd", Type: "reg"},
		{Path: "../escape", Type: "reg"},
		{Path: "a/../b", Type: "reg"},
		{Path: "a//b", Type: "reg"},
		{Path: "a\\b", Type: "reg"},
		{Path: "a\x00b", Type: "reg"},
		{Path: "a b", Type: "dir"}, // spaces are legal guest paths
		{Path: "x", Type: "reg", Size: 5, Reader: strings.NewReader("ab")},
		{Path: "x", Type: "reg", Size: 1, Reader: strings.NewReader("abc")},
		{Path: "x", Type: "mystery"},
		{Path: "x", Type: "symlink"},
		{Path: "x", Type: "hardlink", Link: "/abs"},
		{Path: "x", Type: "hardlink", Link: "../../etc/passwd"},
		{Path: "", Type: "whiteout"},
		{Path: ".wh.x", Type: "whiteout"},
	}
	for _, e := range cases {
		if e.Path == "a b" {
			if err := ValidateDiffEntry(e); err != nil {
				t.Fatalf("space path must validate: %v", err)
			}
			continue
		}
		var buf bytes.Buffer
		if _, err := LayerTar(&buf, []DiffEntry{e}); err == nil {
			t.Fatalf("accepted unsafe entry %+v", e)
		}
	}
}

func TestAssembleProducesDualLayoutDocuments(t *testing.T) {
	diff := Descriptor{MediaType: MediaLayer, Digest: Digest("sha256:" + strings.Repeat("b", 64)), Size: 128}
	base := Descriptor{MediaType: MediaLayer, Digest: Digest("sha256:" + strings.Repeat("a", 64)), Size: 1024}
	layout, err := Assemble(Image{
		BaseLayers: []Descriptor{base}, DiffLayer: diff,
		Env: []string{"PATH=/usr/bin"}, WorkingDir: "/workspace", User: "agent",
		Tag: "mytpl:v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(layout.Manifest.Layers) != 2 || layout.Manifest.Layers[0].Digest != base.Digest || layout.Manifest.Layers[1].Digest != diff.Digest {
		t.Fatalf("layer chain broken: %+v", layout.Manifest.Layers)
	}
	if len(layout.Config.RootFS.DiffIDs) != 2 || layout.Config.RootFS.DiffIDs[0] != string(base.Digest) {
		t.Fatalf("rootfs=%+v", layout.Config.RootFS)
	}
	if got := layout.Manifest.Annotations[AnnotationImageName]; got != "docker.io/library/mytpl:v1" {
		t.Fatalf("name annotation=%q", got)
	}
	if len(layout.LayerFileNames) != 2 || !strings.HasSuffix(layout.LayerFileNames[1], "/diff") {
		t.Fatalf("layer file names=%v", layout.LayerFileNames)
	}
	// docker-save manifest lives in the blobs and references the config by
	// "<hex>.json" per the baseline fixture.
	var saveBytes []byte
	for _, b := range layout.Blobs {
		if bytes.Contains(b.Blob, []byte("RepoTags")) {
			saveBytes = b.Blob
		}
	}
	if saveBytes == nil || !strings.Contains(string(saveBytes), "docker.io/library/mytpl:v1") ||
		!strings.Contains(string(saveBytes), strings.TrimPrefix(string(layout.ConfigID), "sha256:")+".json") {
		t.Fatalf("docker-save manifest missing or wrong: %s", saveBytes)
	}
	// OCI layout documents materialize deterministically.
	buf := &bytes.Buffer{}
	if err := layout.WriteOCILayout(buf); err != nil {
		t.Fatal(err)
	}
	names := readTarNames(t, buf.Bytes())
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "oci-layout") || !strings.Contains(joined, "index.json") || !strings.Contains(joined, "blobs/sha256/") {
		t.Fatalf("layout entries=%s", joined)
	}
}

func TestAssembleRejectsBadInputs(t *testing.T) {
	good := Descriptor{MediaType: MediaLayer, Digest: Digest("sha256:" + strings.Repeat("c", 64)), Size: 10}
	if _, err := Assemble(Image{DiffLayer: Descriptor{Digest: "sha256:short"}, BaseLayers: []Descriptor{good}}); err == nil {
		t.Fatal("accepted invalid diff digest")
	}
	if _, err := Assemble(Image{DiffLayer: good, Tag: "UPPER case"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted bad tag: %v", err)
	}
	if _, err := Assemble(Image{DiffLayer: good, BaseLayers: []Descriptor{{Digest: "md5:xx", Size: 1}}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted bad base digest: %v", err)
	}
}

func TestNormalizedName(t *testing.T) {
	cases := map[string]string{
		"mytpl":             "docker.io/library/mytpl",
		"mytpl:v2":          "docker.io/library/mytpl",
		"team/tool":         "docker.io/library/team/tool",
		"team/tool:v2":      "docker.io/library/team/tool",
		"reg.example.com/x": "reg.example.com/x",
		"localhost/x":       "localhost/x",
	}
	for tag, want := range cases {
		got, err := Image{Tag: tag}.NormalizedName()
		if err != nil || got != want {
			t.Fatalf("NormalizedName(%q)=%q,%v want %q", tag, got, err, want)
		}
	}
	if _, err := (Image{}).NormalizedName(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty tag must be invalid: %v", err)
	}
}

func FuzzValidateDiffEntry(f *testing.F) {
	seeds := []string{"/etc", "a/../b", ".wh.x", "var/lib/docker", "a b", "", "..", "x\x00y", strings.Repeat("a/", 300) + "b"}
	for _, seed := range seeds {
		f.Add(seed, "reg")
		f.Add(seed, "whiteout")
		f.Add(seed, "symlink")
	}
	f.Fuzz(func(t *testing.T, p, typ string) {
		e := DiffEntry{Path: p, Type: typ, Link: "t", Size: 1, Reader: strings.NewReader("x")}
		if typ == typeWhiteout || typ == typeOpaque || typ == typeDir {
			e.Link, e.Reader, e.Size = "", nil, 0
		}
		err := ValidateDiffEntry(e)
		if err != nil {
			return
		}
		// Anything that validated must encode into a parseable tar.
		var buf bytes.Buffer
		if _, err := LayerTar(&buf, []DiffEntry{e}); err != nil {
			t.Fatalf("validated entry failed to encode: %v (%+v)", err, e)
		}
	})
}

// freshEntries rebuilds streaming readers so the same logical layer can be
// encoded more than once (each pass must produce byte-identical output).
func freshEntries(entries []DiffEntry) []DiffEntry {
	out := append([]DiffEntry(nil), entries...)
	for i := range out {
		if out[i].Path == "etc/passwd" {
			out[i].Reader = strings.NewReader("root")
		}
	}
	return out
}

func TestValidateEntryPathCharsetAllowsRealGuestPaths(t *testing.T) {
	// Regression: the charset check once treated "\\x00" as the literal
	// letters backslash-x-0-0, rejecting every path containing 'x' or '0'.
	for _, ok := range []string{
		"etc/alternatives/babeljs-external-helpers",
		"usr/local/bin/gox",
		"home/agent/file0.txt",
		"var/lib/docker/x/0",
	} {
		if err := validateEntryPath(ok); err != nil {
			t.Fatalf("legit path rejected: %q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "/abs", "back\\slash", "nul\x00inside", "ctrl\x01a"} {
		if err := validateEntryPath(bad); err == nil {
			t.Fatalf("unsafe path accepted: %q", bad)
		}
	}
	if err := validateSymlinkTarget(DiffEntry{Path: "bin/x", Link: "exe0"}); err != nil {
		t.Fatalf("symlink with x/0 refused: %v", err)
	}
	if err := validateSymlinkTarget(DiffEntry{Path: "bin/x", Link: "evil\\0"}); err == nil {
		t.Fatal("symlink with backslash accepted")
	}
}
