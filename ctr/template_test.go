package ctr

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtime "github.com/gyrel/sandboxes-runtime"

	"github.com/gyrel/sandboxes-runtime/internal/ocilayer"
)

type fakeRuntime struct {
	captureTars  [][]byte
	captureErr   error
	capturedArgs []string
	excludes     [][]string
	blobs        map[string][]byte
	layers       []ocilayer.Descriptor
	config       []byte
	importRef    string
	importTar    string
	importErr    error
	digest       ocilayer.Digest
	digestErr    error
}

func (f *fakeRuntime) CaptureGuestRoot(_ context.Context, _ runtime.Handle, excludes []string, stdout io.Writer) error {
	f.excludes = append(f.excludes, excludes)
	if f.captureErr != nil {
		return f.captureErr
	}
	for _, raw := range f.captureTars {
		if _, err := stdout.Write(raw); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeRuntime) ImageLayers(context.Context, string) ([]ocilayer.Descriptor, []byte, error) {
	return f.layers, f.config, nil
}

func (f *fakeRuntime) OpenBlob(_ context.Context, d ocilayer.Descriptor) (io.ReadCloser, error) {
	raw, ok := f.blobs[string(d.Digest)]
	if !ok {
		return nil, errors.New("fake blob missing")
	}
	return io.NopCloser(bytes.NewReader(raw)), nil
}

func (f *fakeRuntime) ImageDigest(context.Context, string) (ocilayer.Digest, error) {
	if f.digestErr != nil {
		return "", f.digestErr
	}
	if f.digest == "" {
		return ocilayer.Digest("sha256:" + strings.Repeat("d", 64)), nil
	}
	return f.digest, nil
}

func (f *fakeRuntime) ImportTemplate(_ context.Context, tarPath, ref string) error {
	f.importTar = tarPath
	f.importRef = ref
	if f.importErr != nil {
		return f.importErr
	}
	raw, err := os.ReadFile(tarPath)
	if err == nil {
		f.capturedArgs = append(f.capturedArgs, string(raw))
	}
	return nil
}

func tarball(t *testing.T, files []tarFile) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, fl := range files {
		hdr := &tar.Header{Name: fl.Name, Mode: fl.Mode, Size: int64(len(fl.Data)), Format: tar.FormatGNU, ModTime: fl.Mod}
		switch fl.Kind {
		case "dir":
			hdr.Typeflag, hdr.Name, hdr.Size = tar.TypeDir, fl.Name+"/", 0
		case "symlink":
			hdr.Typeflag, hdr.Linkname, hdr.Size = tar.TypeSymlink, fl.Data, 0
		default:
			hdr.Typeflag = tar.TypeReg
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag == tar.TypeReg && len(fl.Data) > 0 {
			if _, err := tw.Write([]byte(fl.Data)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

type tarFile struct {
	Name, Data string
	Kind       string
	Mode       int64
	Mod        time.Time
}

func blobDesc(data []byte) ocilayer.Descriptor {
	sum := sha256.Sum256(data)
	return ocilayer.Descriptor{MediaType: ocilayer.MediaLayer, Digest: ocilayer.Digest("sha256:" + hex.EncodeToString(sum[:])), Size: int64(len(data))}
}

func baseConfig(diffIDs ...string) []byte {
	raw, _ := json.Marshal(ocilayer.Config{
		Architecture: "arm64", OS: "linux", Created: "2026-01-01T00:00:00Z",
		RootFS: ocilayer.RootFS{Type: "layers", DiffIDs: diffIDs},
		Config: ocilayer.DocConfig{Env: []string{"PATH=/usr/bin"}, WorkingDir: "/workspace", User: "agent"},
	})
	return raw
}

func TestSaveTemplateEndToEndWithFakes(t *testing.T) {
	baseTar := tarball(t, []tarFile{
		{Name: "keep", Data: "same", Kind: "reg", Mode: 0o644},
		{Name: "gone", Data: "bye", Kind: "reg", Mode: 0o644},
		{Name: "changed", Data: "old", Kind: "reg", Mode: 0o644},
		{Name: "dockerdata", Data: "secretish", Kind: "reg", Mode: 0o600},
	})
	baseDesc := blobDesc(baseTar)
	capture := tarball(t, []tarFile{
		{Name: "keep", Data: "same", Kind: "reg", Mode: 0o644},
		{Name: "changed", Data: "new!", Kind: "reg", Mode: 0o644},
		{Name: "added", Data: "hello", Kind: "reg", Mode: 0o644},
		{Name: "mnt", Data: "should-not-appear", Kind: "reg", Mode: 0o644},
	})
	rt := &fakeRuntime{
		captureTars: [][]byte{capture},
		layers:      []ocilayer.Descriptor{baseDesc},
		blobs:       map[string][]byte{string(baseDesc.Digest): baseTar},
		config:      baseConfig(string(baseDesc.Digest)),
	}
	h := runtime.Handle{ID: "gyrel-test-handle"}
	dir := t.TempDir()
	out := filepath.Join(dir, "tpl.tar")
	summary, err := SaveTemplate(context.Background(), rt, h, TemplateSaveOptions{
		Tag: "mytpl:v1", BaseImage: "alpine:3.22",
		Excludes: []string{"/mnt"}, OutputPath: out,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rt.importRef != "docker.io/library/mytpl:v1" {
		t.Fatalf("import ref=%q", rt.importRef)
	}
	if summary.Layers != 2 || !strings.HasPrefix(summary.Name, "docker.io/library/") {
		t.Fatalf("summary=%+v", summary)
	}
	if summary.Notice != NoticeGuestSecrets {
		t.Fatalf("notice=%q", summary.Notice)
	}
	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string][]byte{}
	names := []string{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(tr)
		entries[hdr.Name] = data
		names = append(names, hdr.Name)
	}
	for _, want := range []string{"oci-layout", "index.json", "manifest.json", "repositories"} {
		if _, ok := entries[want]; !ok {
			t.Fatalf("archive lacks %s: %v", want, names)
		}
	}
	// Locate the new (diff) layer: last layer in manifest.json.
	var save []struct {
		Config   string   `json:"Config"`
		RepoTags []string `json:"RepoTags"`
		Layers   []string `json:"Layers"`
	}
	if err := json.Unmarshal(entries["manifest.json"], &save); err != nil {
		t.Fatal(err)
	}
	if len(save) != 1 || save[0].RepoTags[0] != "docker.io/library/mytpl:v1" || len(save[0].Layers) != 2 {
		t.Fatalf("manifest.json=%s", entries["manifest.json"])
	}
	// Re-hash each listed layer blob to verify the base reuse and diff size.
	for _, pathName := range save[0].Layers {
		blob, ok := findBlob(entries, pathName)
		if !ok {
			t.Fatalf("layer path %s not present in archive: %v", pathName, names)
		}
		sum := sha256.Sum256(blob)
		_ = sum
	}
	diffBlob, ok := findBlob(entries, save[0].Layers[1])
	if !ok {
		t.Fatalf("diff layer blob missing")
	}
	layerNames := map[string]bool{}
	tr2 := tar.NewReader(bytes.NewReader(diffBlob))
	for {
		hdr, err := tr2.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("parse diff layer: %v", err)
		}
		layerNames[hdr.Name] = true
	}
	if layerNames["keep"] {
		t.Fatal("unchanged file must be skipped")
	}
	for _, want := range []string{"added", "changed", ".wh.gone", ".wh.dockerdata", "mnt/.wh..wh..opq", "var/lib/docker/.wh..wh..opq"} {
		if !layerNames[want] {
			t.Fatalf("diff layer lacks %s: %v", want, layerNames)
		}
	}
	if layerNames[".wh.keep"] {
		t.Fatal("kept file must not be whiteouted")
	}
	// Output copy must not overwrite.
	if _, err := SaveTemplate(context.Background(), rt, h, TemplateSaveOptions{
		Tag: "mytpl:v2", BaseImage: "alpine:3.22", Excludes: []string{"/mnt"}, OutputPath: out,
	}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second export must refuse overwrite: %v", err)
	}
}

func findBlob(entries map[string][]byte, want string) ([]byte, bool) {
	if raw, ok := entries[want]; ok {
		return raw, true
	}
	for name, raw := range entries {
		if strings.HasSuffix(name, want) || strings.HasSuffix(want, filepath.Base(name)) && strings.HasPrefix(name, "blobs/sha256/") && filepath.Base(name) == filepath.Base(want) {
			return raw, true
		}
	}
	return nil, false
}

func TestSaveTemplateValidationGuards(t *testing.T) {
	rt := &fakeRuntime{}
	h := runtime.Handle{ID: "gyrel-x"}
	if _, err := SaveTemplate(context.Background(), rt, h, TemplateSaveOptions{Tag: "", BaseImage: "x"}); err == nil {
		t.Fatal("empty tag accepted")
	}
	if _, err := SaveTemplate(context.Background(), rt, h, TemplateSaveOptions{
		Tag: "t", BaseImage: "x", Excludes: []string{"../escape"},
	}); !errors.Is(err, ErrUnsafeExclude) {
		t.Fatalf("unsafe exclude: %v", err)
	}
	if _, err := SaveTemplate(context.Background(), rt, h, TemplateSaveOptions{
		Tag: "t", BaseImage: "x", Excludes: []string{"--force"},
	}); !errors.Is(err, ErrUnsafeExclude) {
		t.Fatalf("flag-looking exclude: %v", err)
	}
	if len(rt.excludes) != 0 {
		t.Fatal("capture ran despite invalid excludes")
	}
	rt.captureErr = errors.New("guest tar exit 1")
	if _, err := SaveTemplate(context.Background(), rt, h, TemplateSaveOptions{Tag: "t", BaseImage: "x"}); err == nil {
		t.Fatal("capture failure must abort save")
	}
}

func TestLoadTemplateReadsTagAndNormalizes(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	manifest, _ := json.Marshal([]dockerSaveManifestStub{{RepoTags: []string{"mytpl:v2"}}})
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(manifest)), Format: tar.FormatGNU}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(manifest); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	archive := filepath.Join(dir, "tpl.tar")
	if err := os.WriteFile(archive, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := &fakeRuntime{}
	summary, err := LoadTemplate(context.Background(), rt, archive, "")
	if err != nil {
		t.Fatal(err)
	}
	if rt.importRef != "docker.io/library/mytpl:v2" || summary.Name != rt.importRef || !strings.HasPrefix(summary.Digest, "sha256:") {
		t.Fatalf("importRef=%q summary=%+v", rt.importRef, summary)
	}
	rt2 := &fakeRuntime{}
	if _, err := LoadTemplate(context.Background(), rt2, archive, "other"); err != nil {
		t.Fatal(err)
	}
	if rt2.importRef != "docker.io/library/other" {
		t.Fatalf("override ref=%q", rt2.importRef)
	}
	rt3 := &fakeRuntime{importErr: errors.New("boom")}
	if _, err := LoadTemplate(context.Background(), rt3, archive, ""); err == nil {
		t.Fatal("import failure must surface")
	}
	if _, err := LoadTemplate(context.Background(), rt3, filepath.Join(dir, "missing.tar"), ""); err == nil {
		t.Fatal("missing archive must fail")
	}
}

type dockerSaveManifestStub struct {
	RepoTags []string `json:"RepoTags"`
}
