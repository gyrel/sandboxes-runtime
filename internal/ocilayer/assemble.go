package ocilayer

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"
)

// Image is the input for assembly: the base layer descriptors (reused by
// digest, contents already in the content store), the new diff layer, and
// the runtime configuration the template must boot with.
type Image struct {
	// BaseLayers are copied verbatim into the new config/manifest history,
	// preserving digests and sizes (no squash, no re-hash).
	BaseLayers []Descriptor
	// DiffLayer is the freshly built layer from LayerTar. Required.
	DiffLayer Descriptor
	// Architecture/OS default to arm64/linux like the pinned images today;
	// the daemon passes what the sandbox actually booted.
	Architecture string
	OS           string
	// Env, WorkingDir and User reconstruct the guest launch configuration
	// from the sandbox record (ADR-0008: env/workdir rebuilt, not committed
	// container metadata).
	Env        []string
	WorkingDir string
	User       string
	// Tag is "<name>" or "<name>:<suffix>" (lowercase repo grammar; the
	// assembler normalizes to docker.io/library/<name> and defaults the
	// suffix to latest, mirroring the baseline save/load behavior).
	Tag string
	// Created timestamps the config (zero collapses to epoch for
	// deterministic fixtures).
	Created string
}

// ErrInvalid is returned for structurally invalid assembly inputs; the
// assembler refuses to run against them (fail closed, nothing is written).
var ErrInvalid = errors.New("ocilayer: invalid assembly input")

// NormalizedName returns the docker.io-prefixed repository for the tag.
func (img Image) NormalizedName() (string, error) {
	tag := strings.TrimSpace(img.Tag)
	if tag == "" {
		return "", fmt.Errorf("%w: empty tag", ErrInvalid)
	}
	name := tag
	if i := strings.IndexByte(name, ':'); i >= 0 {
		name = name[:i]
	}
	if name == "" || name != strings.ToLower(name) || strings.ContainsAny(name, " \t@") || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") {
		return "", fmt.Errorf("%w: bad repository name %q", ErrInvalid, tag)
	}
	if strings.Contains(name, "/") {
		if !strings.Contains(name, ".") && !strings.Contains(name, ":") && !strings.HasPrefix(name, "localhost/") {
			name = "docker.io/library/" + name
		}
		return name, nil
	}
	return "docker.io/library/" + name, nil
}

// Config is the OCI image configuration JSON document.
type Config struct {
	Architecture string    `json:"architecture"`
	OS           string    `json:"os"`
	Created      string    `json:"created"`
	History      []History `json:"history"`
	RootFS       RootFS    `json:"rootfs"`
	Config       DocConfig `json:"config"`
}

// History documents each layer; the diff layer records the template
// capture, base layers inherit whatever history the daemon supplies.
type History struct {
	Created    string `json:"created,omitempty"`
	CreatedBy  string `json:"created_by,omitempty"`
	EmptyLayer bool   `json:"empty_layer,omitempty"`
}

// RootFS lists layer digests in application order.
type RootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids"`
}

// DocConfig is the runtime document embedded in the image config.
type DocConfig struct {
	Env        []string `json:"Env,omitempty"`
	WorkingDir string   `json:"WorkingDir,omitempty"`
	User       string   `json:"User,omitempty"`
}

// Manifest is the OCI image manifest.
type Manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Config        Descriptor        `json:"config"`
	Layers        []Descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// Index is the OCI image index referencing manifests by tag.
type Index struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []Descriptor `json:"manifests"`
}

// dockerSaveEntry is one record of the docker-save compatibility manifest.
type dockerSaveEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

// Blob is a content-store piece produced by Assemble.
type Blob struct {
	Digest Digest
	Blob   []byte
}

// Layout is the complete assembled artifact: blobs (config, manifest,
// layers to fetch by digest from the content store are referenced only) and
// the two compatibility documents for the tar export.
type Layout struct {
	Config   Config
	ConfigID Digest
	Manifest Manifest
	Index    Index
	// Blobs contains the config and manifest documents (and, for the
	// export, the docker-save manifest.json) sized and digested.
	Blobs []Blob
	// ManifestID locates the manifest document inside Blobs.
	ManifestID Digest
	// LayerFileNames maps each layer digest to its "<hex>/diff" tar path
	// used both in the OCI layout and the docker-save layer naming.
	LayerFileNames []string
}

// Assemble validates the inputs and produces the deterministic documents.
// The diff layer descriptor must already carry its real digest/size from
// LayerTar; base layer descriptors must be valid digests. Blob reuse means
// the assembler never copies base content — the exporter resolves digests
// against the content store.
func Assemble(img Image) (*Layout, error) {
	if err := validateAssemblyInputs(img); err != nil {
		return nil, err
	}
	name, err := img.NormalizedName()
	if err != nil {
		return nil, err
	}
	suffix := tagSuffix(strings.TrimSpace(img.Tag))
	if suffix == "" {
		return nil, fmt.Errorf("%w: empty tag suffix", ErrInvalid)
	}
	arch, osName := value(img.Architecture, "arm64"), value(img.OS, "linux")
	if osName == "" || arch == "" {
		return nil, fmt.Errorf("%w: empty platform", ErrInvalid)
	}
	layers := append(append([]Descriptor{}, img.BaseLayers...), img.DiffLayer)
	root := RootFS{Type: "layers", DiffIDs: make([]string, 0, len(layers))}
	names := make([]string, 0, len(layers))
	for _, l := range layers {
		// diff_ids are the uncompressed digests; this fallback builds the
		// synthetic all-uncompressed chain used by fixtures and by the
		// empty-baseConfig path. Registry bases go through
		// AssembleWithConfig, which preserves the base config's own
		// uncompressed diff ids.
		root.DiffIDs = append(root.DiffIDs, string(l.Digest))
		hexPart := strings.TrimPrefix(string(l.Digest), "sha256:")
		names = append(names, hexPart+"/diff")
	}
	history := make([]History, 0, len(layers))
	for range img.BaseLayers {
		history = append(history, History{CreatedBy: "FROM base"})
	}
	history = append(history, History{CreatedBy: "Rheic template capture"})
	cfgDoc := Config{
		Architecture: arch, OS: osName, Created: value(img.Created, "1970-01-01T00:00:00Z"),
		History: history, RootFS: root,
		Config: DocConfig{Env: img.Env, WorkingDir: img.WorkingDir, User: img.User},
	}
	cfgRaw, err := json.Marshal(cfgDoc)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	cfgDesc := Descriptor{MediaType: MediaConfig, Digest: digestOf(cfgRaw), Size: int64(len(cfgRaw))}
	manifest := Manifest{
		SchemaVersion: 2, MediaType: MediaManifest, Config: cfgDesc, Layers: layers,
		Annotations: map[string]string{AnnotationImageName: name + ":" + tagSuffix(img.Tag)},
	}
	manRaw, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	manDesc := Descriptor{MediaType: MediaManifest, Digest: digestOf(manRaw), Size: int64(len(manRaw))}
	index := Index{SchemaVersion: 2, MediaType: "application/vnd.oci.image.index.v1+json", Manifests: []Descriptor{manDesc}}
	save := []dockerSaveEntry{{
		Config:   strings.TrimPrefix(string(cfgDesc.Digest), "sha256:") + ".json",
		RepoTags: []string{name + ":" + tagSuffix(img.Tag)},
		Layers:   names,
	}}
	saveRaw, err := json.Marshal(save)
	if err != nil {
		return nil, fmt.Errorf("marshal docker-save manifest: %w", err)
	}
	return &Layout{
		Config: cfgDoc, ConfigID: cfgDesc.Digest, Manifest: manifest, ManifestID: manDesc.Digest, Index: index,
		Blobs: []Blob{
			{Digest: cfgDesc.Digest, Blob: cfgRaw},
			{Digest: manDesc.Digest, Blob: manRaw},
			{Digest: digestOf(saveRaw), Blob: saveRaw},
		},
		LayerFileNames: names,
	}, nil
}

func tagSuffix(tag string) string {
	if i := strings.IndexByte(tag, ':'); i >= 0 {
		return strings.TrimSpace(tag[i+1:])
	}
	return "latest"
}

func value(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

func digestOf(b []byte) Digest {
	sum := sha256.Sum256(b)
	return Digest("sha256:" + hex.EncodeToString(sum[:]))
}

// WriteLayoutMaterializer helper: renders the oci-layout + index.json pair
// for stream-based exporters (the ctr import path consumes docker-save tar
// files, so the OCI-layout directory form is provided for fixture tests and
// future content-store writers).
func (l *Layout) ociDocuments() (map[string][]byte, error) {
	indexRaw, err := json.Marshal(l.Index)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{
		"oci-layout": []byte(`{"imageLayoutVersion":"1.0.0"}` + "\n"),
		"index.json": indexRaw,
	}
	for _, b := range l.Blobs {
		hexPart := strings.TrimPrefix(string(b.Digest), "sha256:")
		out[path.Join("blobs/sha256", hexPart)] = b.Blob
	}
	return out, nil
}

// WriteOCILayout writes the OCI layout documents (and every produced blob)
// into w as a deterministic in-memory test/export helper: the layout tar
// keeps entries sorted by name for reproducible bytes.
func (l *Layout) WriteOCILayout(w io.Writer) error {
	docs, err := l.ociDocuments()
	if err != nil {
		return err
	}
	names := make([]string, 0, len(docs))
	for name := range docs {
		names = append(names, name)
	}
	sortStrings(names)
	_ = bytes.MinRead
	return writeSortedTar(w, names, docs)
}

func sortStrings(x []string) {
	for i := 1; i < len(x); i++ {
		for j := i; j > 0 && x[j] < x[j-1]; j-- {
			x[j], x[j-1] = x[j-1], x[j]
		}
	}
}

func writeSortedTar(w io.Writer, names []string, docs map[string][]byte) error {
	tw := tar.NewWriter(w)
	for _, name := range names {
		content := docs[name]
		if err := tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: name, Mode: 0o644, Size: int64(len(content)),
			Format: tar.FormatGNU, ModTime: time.Unix(0, 0).UTC(),
		}); err != nil {
			return err
		}
		if _, err := tw.Write(content); err != nil {
			return err
		}
	}
	return tw.Close()
}

func validateAssemblyInputs(img Image) error {
	if img.DiffLayer.Digest == "" || !img.DiffLayer.Digest.Valid() || img.DiffLayer.Size <= 0 {
		return fmt.Errorf("%w: diff layer descriptor incomplete", ErrInvalid)
	}
	for _, l := range img.BaseLayers {
		if !l.Digest.Valid() || l.Size <= 0 {
			return fmt.Errorf("%w: base layer descriptor %q invalid", ErrInvalid, l.Digest)
		}
	}
	return nil
}

// AssembleWithConfig reuses a base image's config document verbatim
// (architecture, OS, Env, WorkingDir, User, created) and appends the new
// diff layer, matching the baseline container-commit semantics: only the
// layer chain and history change.
func AssembleWithConfig(img Image, baseConfig []byte) (*Layout, error) {
	if img.DiffLayer.Digest == "" || !img.DiffLayer.Digest.Valid() || img.DiffLayer.Size <= 0 {
		return nil, fmt.Errorf("%w: diff layer descriptor incomplete", ErrInvalid)
	}
	for _, l := range img.BaseLayers {
		if !l.Digest.Valid() || l.Size <= 0 {
			return nil, fmt.Errorf("%w: base layer descriptor %q invalid", ErrInvalid, l.Digest)
		}
	}
	name, err := img.NormalizedName()
	if err != nil {
		return nil, err
	}
	suffix := tagSuffix(strings.TrimSpace(img.Tag))
	if suffix == "" {
		return nil, fmt.Errorf("%w: empty tag suffix", ErrInvalid)
	}
	cfgDoc, err := templateConfigDoc(img, baseConfig)
	if err != nil {
		return nil, err
	}
	history := append(append([]History{}, cfgDoc.History...), History{CreatedBy: "Rheic template capture"})
	cfgDoc.History = history
	cfgRaw, err := json.Marshal(cfgDoc)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	cfgDesc := Descriptor{MediaType: MediaConfig, Digest: digestOf(cfgRaw), Size: int64(len(cfgRaw))}
	layers := append(append([]Descriptor{}, img.BaseLayers...), img.DiffLayer)
	manifest := Manifest{
		SchemaVersion: 2, MediaType: MediaManifest, Config: cfgDesc, Layers: layers,
		Annotations: map[string]string{AnnotationImageName: name + ":" + suffix},
	}
	manRaw, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("marshal manifest: %w", err)
	}
	manDesc := Descriptor{MediaType: MediaManifest, Digest: digestOf(manRaw), Size: int64(len(manRaw))}
	index := Index{SchemaVersion: 2, MediaType: "application/vnd.oci.image.index.v1+json", Manifests: []Descriptor{manDesc}}
	save := []dockerSaveEntry{{
		Config:   blobHex(cfgDesc.Digest) + ".json",
		RepoTags: []string{name + ":" + suffix},
		Layers:   layerPaths(layers),
	}}
	saveRaw, err := json.Marshal(save)
	if err != nil {
		return nil, fmt.Errorf("marshal docker-save manifest: %w", err)
	}
	return &Layout{
		Config: cfgDoc, ConfigID: cfgDesc.Digest, Manifest: manifest, ManifestID: manDesc.Digest, Index: index,
		Blobs: []Blob{
			{Digest: cfgDesc.Digest, Blob: cfgRaw},
			{Digest: manDesc.Digest, Blob: manRaw},
			{Digest: digestOf(saveRaw), Blob: saveRaw},
		},
		LayerFileNames: layerPaths(layers),
	}, nil
}

// templateConfigDoc derives the template config from the base image config.
// The base config's diff_ids are the uncompressed content digests: registry
// layers are pulled compressed, so the layer descriptor digest (the
// compressed blob) is NOT the diff id. Rebuilding the list from descriptors
// made containerd abort the template import with "wrong diff id calculated
// on extraction". The base's own diff ids are kept and only the freshly
// built (uncompressed) diff layer is appended, whose digest is its diff id.
// Without a base config the synthetic uncompressed fallback is used.
func templateConfigDoc(img Image, baseConfig []byte) (Config, error) {
	if len(baseConfig) == 0 {
		fallback, err := Assemble(img)
		if err != nil {
			return Config{}, err
		}
		return fallback.Config, nil
	}
	var cfgDoc Config
	if err := json.Unmarshal(baseConfig, &cfgDoc); err != nil {
		return Config{}, fmt.Errorf("parse base image config: %w", err)
	}
	if len(cfgDoc.RootFS.DiffIDs) != len(img.BaseLayers) {
		return Config{}, fmt.Errorf("%w: base config has %d diff_ids for %d base layers", ErrInvalid, len(cfgDoc.RootFS.DiffIDs), len(img.BaseLayers))
	}
	cfgDoc.RootFS.DiffIDs = append(append([]string{}, cfgDoc.RootFS.DiffIDs...), string(img.DiffLayer.Digest))
	return cfgDoc, nil
}

func blobHex(d Digest) string { return strings.TrimPrefix(string(d), "sha256:") }

func layerPaths(layers []Descriptor) []string {
	out := make([]string, 0, len(layers))
	for _, l := range layers {
		out = append(out, blobHex(l.Digest)+"/diff")
	}
	return out
}
