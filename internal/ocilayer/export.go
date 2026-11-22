package ocilayer

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
)

// BlobSource opens one content blob for streaming. The runtime wires it to
// the containerd content store (with digest verification); tests use an
// in-memory source.
type BlobSource interface {
	Open(d Descriptor) (io.ReadCloser, error)
}

// MapSource is a test helper BlobSource over an in-memory map.
type MapSource map[Digest][]byte

// Open implements BlobSource.
func (m MapSource) Open(d Descriptor) (io.ReadCloser, error) {
	raw, ok := m[d.Digest]
	if !ok {
		return nil, fmt.Errorf("%w: blob %s missing", ErrInvalid, d.Digest)
	}
	return io.NopCloser(strings.NewReader(string(raw))), nil
}

// StreamBaseListing walks base layer tars bottom-up and resolves their
// whiteouts, producing the effective file listing for diffing. Content
// digests are recorded for regular files so unchanged entries can be
// skipped exactly.
func StreamBaseListing(layers []Descriptor, src BlobSource) (map[string]BaseFile, error) {
	listing := map[string]BaseFile{}
	for _, layer := range layers {
		rc, err := src.Open(layer)
		if err != nil {
			return nil, err
		}
		if err := applyBaseLayer(listing, rc); err != nil {
			_ = rc.Close()
			return nil, fmt.Errorf("layer %s: %w", layer.Digest, err)
		}
		if err := rc.Close(); err != nil {
			return nil, fmt.Errorf("layer %s close: %w", layer.Digest, err)
		}
	}
	return listing, nil
}

func applyBaseLayer(listing map[string]BaseFile, r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}
		if hdr.Typeflag == tar.TypeReg && isMarker(hdr.Name) {
			applyBaseMarker(listing, hdr.Name)
			continue
		}
		if err := applyBaseEntry(listing, hdr, tr); err != nil {
			return err
		}
	}
}

func isMarker(name string) bool {
	base := path.Base(name)
	return base == opaqueMarkerName || strings.HasPrefix(base, whPrefix)
}

func applyBaseMarker(listing map[string]BaseFile, name string) {
	base := path.Base(name)
	dir := path.Dir(name)
	if dir == "." {
		dir = ""
	}
	if base == opaqueMarkerName {
		for p := range listing {
			if dir == "" || strings.HasPrefix(p, dir+"/") {
				delete(listing, p)
			}
		}
		return
	}
	target := path.Join(dir, strings.TrimPrefix(base, whPrefix))
	deleteSubtree(listing, strings.TrimSuffix(target, "/"))
}

func applyBaseEntry(listing map[string]BaseFile, hdr *tar.Header, tr io.Reader) error {
	name, err := normalizeCapturePath(hdr.Name)
	if err != nil {
		return err
	}
	if name == "" {
		return nil
	}
	switch hdr.Typeflag {
	case tar.TypeReg:
		listing[name] = BaseFile{Path: name, Type: typeReg, Mode: uint32(hdr.Mode & 0o7777), Digest: sha256Of(tr, hdr.Size)}
	case tar.TypeDir:
		listing[name] = BaseFile{Path: name, Type: typeDir, Mode: uint32(hdr.Mode & 0o7777)}
	case tar.TypeSymlink:
		listing[name] = BaseFile{Path: name, Type: typeSymlink, Mode: 0o777}
	case tar.TypeLink:
		listing[name] = BaseFile{Path: name, Type: typeHardlink, Mode: 0o644}
	default:
		// Devices/fifos: record occupancy so a later deletion is still
		// whiteouted; content semantics are intentionally absent.
		listing[name] = BaseFile{Path: name, Type: "special", Mode: 0}
	}
	return nil
}

func deleteSubtree(listing map[string]BaseFile, target string) {
	delete(listing, target)
	for p := range listing {
		if strings.HasPrefix(p, target+"/") {
			delete(listing, p)
		}
	}
}

// WriteDockerSave streams the complete template artifact: OCI layout
// (oci-layout, index.json, blobs), the docker-save compatibility
// manifest.json and repositories. Layer bytes exist exactly once under
// blobs/sha256 (no squash, no duplication), matching the observed baseline
// dual layout.
func WriteDockerSave(w io.Writer, layout *Layout, src BlobSource) error {
	if layout == nil || src == nil {
		return fmt.Errorf("%w: nil layout or source", ErrInvalid)
	}
	if layout.ManifestID == "" || !layout.ManifestID.Valid() {
		return fmt.Errorf("%w: manifest blob missing from layout", ErrInvalid)
	}
	name, err := layoutSaveName(layout)
	if err != nil {
		return err
	}
	indexRaw, err := json.Marshal(layout.Index)
	if err != nil {
		return err
	}
	manifestRaw, err := layoutBlob(layout, layout.ManifestID)
	if err != nil {
		return err
	}
	save := []dockerSaveEntry{{
		Config:   blobPath(layout.ConfigID),
		RepoTags: []string{name},
		Layers:   layerBlobPaths(layout.Manifest.Layers),
	}}
	saveRaw, err := json.Marshal(save)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(w)
	docs := []nameBytes{
		{"oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}` + "\n")},
		{"index.json", indexRaw},
		{"manifest.json", saveRaw},
		{"repositories", []byte(fmt.Sprintf("{%q:{%q:%q}}\n", repoOf(name), tagOf(name), hexOf(layout.ConfigID)))},
		{blobPath(layout.ManifestID), manifestRaw},
	}
	for _, b := range layout.Blobs {
		if b.Digest == layout.ManifestID {
			continue
		}
		docs = append(docs, nameBytes{blobPath(b.Digest), b.Blob})
	}
	for _, d := range docs {
		if err := writeTarBlob(tw, d.name, d.raw); err != nil {
			return err
		}
	}
	if err := streamLayerBlobs(tw, layout, src); err != nil {
		return err
	}
	return tw.Close()
}

type nameBytes struct {
	name string
	raw  []byte
}

func layerBlobPaths(layers []Descriptor) []string {
	out := make([]string, 0, len(layers))
	for _, l := range layers {
		out = append(out, blobPath(l.Digest))
	}
	return out
}

func layoutBlob(layout *Layout, d Digest) ([]byte, error) {
	for _, b := range layout.Blobs {
		if b.Digest == d {
			return b.Blob, nil
		}
	}
	return nil, fmt.Errorf("%w: blob %s missing from layout", ErrInvalid, d)
}

func streamLayerBlobs(tw *tar.Writer, layout *Layout, src BlobSource) error {
	for _, l := range layout.Manifest.Layers {
		rc, err := src.Open(l)
		if err != nil {
			return err
		}
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: blobPath(l.Digest), Mode: 0o644, Size: l.Size, Format: tar.FormatGNU}); err != nil {
			_ = rc.Close()
			return err
		}
		if _, err := io.Copy(tw, rc); err != nil {
			_ = rc.Close()
			return fmt.Errorf("stream layer %s: %w", l.Digest, err)
		}
		if err := rc.Close(); err != nil {
			return fmt.Errorf("close layer %s: %w", l.Digest, err)
		}
	}
	return nil
}

func layoutSaveName(layout *Layout) (string, error) {
	ann := layout.Manifest.Annotations
	if ann == nil {
		return "", fmt.Errorf("%w: manifest lacks image name annotation", ErrInvalid)
	}
	name := ann[AnnotationImageName]
	if name == "" {
		return "", fmt.Errorf("%w: empty image name annotation", ErrInvalid)
	}
	return name, nil
}

func blobPath(d Digest) string {
	return path.Join("blobs/sha256", strings.TrimPrefix(string(d), "sha256:"))
}

func repoOf(name string) string {
	if i := strings.LastIndexByte(name, ':'); i > 0 && !strings.Contains(name[i:], "/") {
		return name[:i]
	}
	return name
}

func tagOf(name string) string {
	if i := strings.LastIndexByte(name, ':'); i > 0 {
		return name[i+1:]
	}
	return "latest"
}

func hexOf(d Digest) string { return strings.TrimPrefix(string(d), "sha256:") }

func writeTarBytes(tw *tar.Writer, name string, raw []byte) error {
	return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(raw)), Format: tar.FormatGNU})
}

func writeTarBlob(tw *tar.Writer, name string, raw []byte) error {
	if err := writeTarBytes(tw, name, raw); err != nil {
		return err
	}
	_, err := tw.Write(raw)
	return err
}

func sha256Of(r io.Reader, size int64) Digest {
	sum := sha256.New()
	_, _ = io.CopyN(sum, r, size)
	return Digest("sha256:" + hex.EncodeToString(sum.Sum(nil)))
}
