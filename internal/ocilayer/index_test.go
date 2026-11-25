package ocilayer

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func indexEntry(t *testing.T, raw []byte) []byte {
	t.Helper()
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			t.Fatal("archive has no index.json")
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == "index.json" {
			body, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			return body
		}
	}
}

func TestIndexCarriesRefNameAnnotation(t *testing.T) {
	layer := []byte("diff layer bytes")
	diff := Descriptor{MediaType: MediaLayer, Digest: digestOf(layer), Size: int64(len(layer))}
	layout, err := Assemble(Image{DiffLayer: diff, Tag: "gyrel-tpl-v10m4:v1"})
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := WriteDockerSave(&archive, layout, MapSource{diff.Digest: layer}); err != nil {
		t.Fatal(err)
	}
	index := indexEntry(t, archive.Bytes())
	const want = `"annotations":{"org.opencontainers.image.ref.name":"v1"}`
	if n := strings.Count(string(index), want); n != 1 {
		t.Fatalf("ref.name annotation count=%d in %s", n, index)
	}
	if n := strings.Count(string(index), `"org.opencontainers.image.ref.name"`); n != 1 {
		t.Fatalf("ref.name key count=%d in %s", n, index)
	}
	if !strings.Contains(string(index), `"manifests":[{"mediaType":"application/vnd.oci.image.manifest.v1+json"`) {
		t.Fatalf("index manifest descriptor shape changed: %s", index)
	}
}

func TestIndexRoundTripKeepsTagAndDigest(t *testing.T) {
	diff := Descriptor{MediaType: MediaLayer, Digest: digestOf([]byte("diff")), Size: 4}
	layout, err := Assemble(Image{DiffLayer: diff, Tag: "mytpl:v1.2-rc_3"})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := layout.WriteOCILayout(&buf); err != nil {
		t.Fatal(err)
	}
	var parsed Index
	if err := json.Unmarshal(indexEntry(t, buf.Bytes()), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Manifests) != 1 {
		t.Fatalf("manifests=%d", len(parsed.Manifests))
	}
	got := parsed.Manifests[0]
	if got.Annotations[AnnotationRefName] != "v1.2-rc_3" || len(got.Annotations) != 1 {
		t.Fatalf("annotations=%v", got.Annotations)
	}
	if got.Digest != layout.ManifestID {
		t.Fatalf("index digest %s, manifest %s", got.Digest, layout.ManifestID)
	}
}

func TestRefNameTagAcceptsOCIGrammar(t *testing.T) {
	cases := map[string]string{
		"mytpl":                             "latest",
		"mytpl:v1":                          "v1",
		"mytpl:v1.2-rc_3":                   "v1.2-rc_3",
		"mytpl:_private":                    "_private",
		"mytpl:" + strings.Repeat("a", 128): strings.Repeat("a", 128),
	}
	for tag, want := range cases {
		got, err := refNameTag(tag)
		if err != nil || got != want {
			t.Fatalf("refNameTag(%q)=%q, %v; want %q", tag, got, err, want)
		}
	}
}

func TestAssembleRefusesInvalidRefNameTags(t *testing.T) {
	diff := Descriptor{MediaType: MediaLayer, Digest: digestOf([]byte("diff")), Size: 4}
	for _, tag := range []string{
		"mytpl:",
		"mytpl:v1/x",
		"mytpl:.hidden",
		"mytpl:-dash",
		"mytpl:a:b",
		"mytpl:bad+plus",
		"mytpl:" + strings.Repeat("a", 129),
	} {
		t.Run(tag, func(t *testing.T) {
			if _, err := Assemble(Image{DiffLayer: diff, Tag: tag}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Assemble accepted %q: %v", tag, err)
			}
			if _, err := AssembleWithConfig(Image{DiffLayer: diff, Tag: tag}, nil); !errors.Is(err, ErrInvalid) {
				t.Fatalf("AssembleWithConfig accepted %q: %v", tag, err)
			}
		})
	}
}
