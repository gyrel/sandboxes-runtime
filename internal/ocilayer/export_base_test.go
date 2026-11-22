package ocilayer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	"github.com/klauspost/compress/zstd"
)

type mapBlobSource struct{ blobs map[Digest][]byte }

func (m *mapBlobSource) Open(d Descriptor) (io.ReadCloser, error) {
	return io.NopCloser(bytes.NewReader(m.blobs[d.Digest])), nil
}

func baseTar(t *testing.T, name string, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	hdr := &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestStreamBaseListingDecodesCompression(t *testing.T) {
	raw := baseTar(t, "etc/issue", "alpine\n")
	sum := digestOf(raw)
	gz := func(in []byte) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		if _, err := w.Write(in); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}(raw)
	zstdBytes := func(in []byte) []byte {
		var b bytes.Buffer
		w, err := zstd.NewWriter(&b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(in); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return b.Bytes()
	}(raw)

	for _, tc := range []struct {
		name string
		blob []byte
		mime string
	}{
		{"plain", raw, "application/vnd.oci.image.layer.v1.tar"},
		{"gzip", gz, "application/vnd.oci.image.layer.v1.tar+gzip"},
		{"zstd", zstdBytes, "application/vnd.oci.image.layer.v1.tar+zstd"},
		// Bytes win over a lying media type (real registries have mismatched
		// tar+gzip blobs; the listing must still read the actual content).
		{"gzip-wrong-media", gz, "application/vnd.oci.image.layer.v1.tar"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := Descriptor{MediaType: tc.mime, Digest: sum, Size: int64(len(tc.blob))}
			src := &mapBlobSource{blobs: map[Digest][]byte{sum: tc.blob}}
			listing, err := StreamBaseListing([]Descriptor{d}, src)
			if err != nil {
				t.Fatal(err)
			}
			bf, ok := listing["etc/issue"]
			if !ok || bf.Type != "reg" || bf.Mode != 0o644 {
				t.Fatalf("listing=%+v", listing)
			}
		})
	}
}

func TestStreamBaseListingRejectsMediaBytesMismatch(t *testing.T) {
	// Media claims gzip but the bytes are plain tar: refuse (fail closed).
	raw := baseTar(t, "etc/issue", "alpine\n")
	sum := digestOf(raw)
	d := Descriptor{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: sum, Size: int64(len(raw))}
	src := &mapBlobSource{blobs: map[Digest][]byte{sum: raw}}
	if _, err := StreamBaseListing([]Descriptor{d}, src); err == nil {
		t.Fatal("media/bytes mismatch accepted")
	}
}
