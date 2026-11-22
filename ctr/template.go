package ctr

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	runtime "github.com/rheic/sandboxes-runtime"
	"github.com/rheic/sandboxes-runtime/internal/ocilayer"
)

// TemplateRuntime is the seam SaveTemplate/LoadTemplate need from the
// backend: guest filesystem capture, content-addressed blob reads, layer
// listing and image import. The Backend implements it against containerd;
// tests substitute fakes.
type TemplateRuntime interface {
	CaptureGuestRoot(ctx context.Context, h runtime.Handle, excludes []string, stdout io.Writer) error
	ImageLayers(ctx context.Context, image string) (layers []ocilayer.Descriptor, config []byte, err error)
	OpenBlob(ctx context.Context, d ocilayer.Descriptor) (io.ReadCloser, error)
	ImportTemplate(ctx context.Context, tarPath, ref string) error
	// ImageDigest resolves the manifest digest of a locally imported
	// reference after load, so template records can be stored without a
	// second parse of the archive.
	ImageDigest(ctx context.Context, ref string) (ocilayer.Digest, error)
}

// TemplateSaveOptions carries one save request. Excludes are guest
// absolute paths (mount points and /var/lib/docker) supplied by the daemon;
// each becomes an opaque exclusion so the template never captures them.
type TemplateSaveOptions struct {
	Tag        string
	BaseImage  string
	Excludes   []string
	OutputPath string
}

// TemplateSummary reports the recorded template. Values carry no secret
// material; Notice is stable operator-facing guidance.
type TemplateSummary struct {
	Name      string
	Digest    string
	SizeBytes int64
	Layers    int
	Notice    string
}

// NoticeGuestSecrets mirrors the baseline warning that templates capture
// the guest filesystem: secrets that live inside the guest (not host
// brokered) travel with the template.
const NoticeGuestSecrets = "warning: guest-resident secrets are stored inside this template; host-brokered credentials are not"

const templateDefaultExclude = "/var/lib/docker"

// templateVirtualExcludes are guest mount points that must never enter a
// template capture. /proc, /sys and /dev are runtime virtual filesystems
// whose contents are not image state (and reading some proc files fails
// even as guest root, which aborts the archive); /run/bundles exposes the
// per-VM EROFS layer directories back into the merged root, which would
// re-walk the entire base image into the diff capture.
var templateVirtualExcludes = []string{"/proc", "/sys", "/dev", "/run/bundles"}

// templateVirtualExcludeRel is the same list in tar/exclude grammar
// (relative, no leading slash), used to suppress whiteouts for base paths
// that live under those prefixes.
var templateVirtualExcludeRel = []string{"proc", "sys", "dev", "run/bundles"}

var ErrUnsafeExclude = errors.New("unsafe template exclude path")

func validateTemplateExcludes(excludes []string) ([]string, []string, error) {
	rel := make([]string, 0, len(excludes)+1)
	seen := map[string]bool{}
	add := func(p string) error {
		p = strings.TrimSpace(p)
		if p == "" || !strings.HasPrefix(p, "/") || path.Clean(p) != p ||
			strings.ContainsAny(p, "\n\x00") || p == "/" || p == "/." ||
			strings.HasPrefix(p, "-") || !entryPathSafe(p) {
			return fmt.Errorf("%w: %q", ErrUnsafeExclude, p)
		}
		r := strings.TrimPrefix(p, "/")
		if seen[r] {
			return nil
		}
		seen[r] = true
		rel = append(rel, r)
		return nil
	}
	for _, e := range excludes {
		if err := add(e); err != nil {
			return nil, nil, err
		}
	}
	if err := add(templateDefaultExclude); err != nil {
		return nil, nil, err
	}
	return rel, relToOpaque(excludes), nil
}

func relToOpaque(excludes []string) []string {
	out := make([]string, 0, len(excludes))
	for _, e := range excludes {
		out = append(out, strings.TrimPrefix(strings.TrimSpace(e), "/"))
	}
	return out
}

func entryPathSafe(p string) bool {
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// SaveTemplate produces the ADR-0008 template artifact: one OCI diff layer
// over the base image (whiteouts for deletions, opaque markers for
// excluded directories, unchanged files skipped), assembled into a
// docker-save/OCI dual-layout tar, imported into the local image store
// under the normalized tag and optionally copied to OutputPath. It never
// squashes and never captures excluded paths.
func validateTemplateSaveOptions(opts TemplateSaveOptions) ([]string, error) {
	if strings.TrimSpace(opts.Tag) == "" || strings.TrimSpace(opts.BaseImage) == "" {
		return nil, errors.New("template save requires a tag and a base image")
	}
	opaqueDirs, _, err := validateTemplateExcludes(opts.Excludes)
	if err != nil {
		return nil, err
	}
	return opaqueDirs, nil
}

func SaveTemplate(ctx context.Context, rt TemplateRuntime, h runtime.Handle, opts TemplateSaveOptions) (TemplateSummary, error) {
	opaqueDirs, err := validateTemplateSaveOptions(opts)
	if err != nil {
		return TemplateSummary{}, err
	}
	var capturePath, layerPath, importPath string
	defer func() {
		for _, p := range []string{capturePath, layerPath, importPath} {
			if p != "" {
				_ = os.Remove(p)
			}
		}
	}()
	captured, capturePath, err := captureAndIndex(ctx, rt, h, opts)
	if err != nil {
		return TemplateSummary{}, err
	}
	baseLayers, baseConfig, baseListing, err := resolveBase(ctx, rt, opts.BaseImage)
	if err != nil {
		return TemplateSummary{}, err
	}
	plan, err := ocilayer.Diff(captured, baseListing, opaqueDirs, templateVirtualExcludeRel)
	if err != nil {
		return TemplateSummary{}, fmt.Errorf("plan template layer: %w", err)
	}
	diffDesc, layerPath, err := buildTemplateLayer(capturePath, plan)
	if err != nil {
		return TemplateSummary{}, err
	}
	layout, err := ocilayer.AssembleWithConfig(ocilayer.Image{
		BaseLayers: baseLayers, DiffLayer: diffDesc, Tag: opts.Tag,
	}, baseConfig)
	if err != nil {
		return TemplateSummary{}, fmt.Errorf("assemble template: %w", err)
	}
	normalizedName, err := layoutName(layout)
	if err != nil {
		return TemplateSummary{}, err
	}
	archiveSize, importPath, err := writeTemplateArchive(ctx, rt, layout, baseLayers, diffDesc, layerPath)
	if err != nil {
		return TemplateSummary{}, err
	}
	if err := rt.ImportTemplate(ctx, importPath, normalizedName); err != nil {
		return TemplateSummary{}, fmt.Errorf("record template: %w", err)
	}
	if opts.OutputPath != "" {
		if err := copyArchive(importPath, opts.OutputPath); err != nil {
			return TemplateSummary{}, fmt.Errorf("export template archive: %w", err)
		}
	}
	return TemplateSummary{
		Name: normalizedName, Digest: string(layout.ManifestID), SizeBytes: archiveSize,
		Layers: len(layout.Manifest.Layers), Notice: NoticeGuestSecrets,
	}, nil
}

// captureAndIndex streams the guest archive into a private temp file and
// returns its indexed contents. The caller owns removing the file.
func captureAndIndex(ctx context.Context, rt TemplateRuntime, h runtime.Handle, opts TemplateSaveOptions) ([]ocilayer.FileMeta, string, error) {
	captureFile, err := os.CreateTemp("", "rheic-template-capture-")
	if err != nil {
		return nil, "", fmt.Errorf("create capture temp: %w", err)
	}
	capturePath := captureFile.Name()
	if err := captureFile.Chmod(0o600); err != nil {
		_ = captureFile.Close()
		return nil, capturePath, fmt.Errorf("protect capture temp: %w", err)
	}
	if err := rt.CaptureGuestRoot(ctx, h, opts.Excludes, captureFile); err != nil {
		_ = captureFile.Close()
		return nil, capturePath, fmt.Errorf("capture guest filesystem: %w", err)
	}
	if err := captureFile.Sync(); err != nil {
		_ = captureFile.Close()
		return nil, capturePath, fmt.Errorf("flush capture temp: %w", err)
	}
	stat, err := captureFile.Stat()
	if err != nil || stat.Size() <= 0 {
		_ = captureFile.Close()
		return nil, capturePath, errors.New("capture produced no data")
	}
	captureSize := stat.Size()
	if err := captureFile.Close(); err != nil {
		return nil, capturePath, fmt.Errorf("close capture temp: %w", err)
	}
	captureRO, err := os.Open(capturePath) //nolint:gosec // G304: temp path owned by this flow
	if err != nil {
		return nil, capturePath, err
	}
	captured, err := func() ([]ocilayer.FileMeta, error) {
		defer func() { _ = captureRO.Close() }()
		return ocilayer.IndexCapture(captureRO, captureSize)
	}()
	if err != nil {
		return nil, capturePath, fmt.Errorf("index capture: %w", err)
	}
	return captured, capturePath, nil
}

func resolveBase(ctx context.Context, rt TemplateRuntime, image string) ([]ocilayer.Descriptor, []byte, map[string]ocilayer.BaseFile, error) {
	baseLayers, baseConfig, err := rt.ImageLayers(ctx, image)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("read base image %s: %w", image, err)
	}
	baseListing, err := ocilayer.StreamBaseListing(baseLayers, &runtimeBlobSource{ctx: ctx, rt: rt})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resolve base listing: %w", err)
	}
	return baseLayers, baseConfig, baseListing, nil
}

// buildTemplateLayer streams the planned layer into a temp file and returns
// its content descriptor. The caller owns removing the file.
func buildTemplateLayer(capturePath string, plan []ocilayer.PlannedEntry) (ocilayer.Descriptor, string, error) {
	layerFile, err := os.CreateTemp("", "rheic-template-layer-")
	if err != nil {
		return ocilayer.Descriptor{}, "", fmt.Errorf("create layer temp: %w", err)
	}
	layerPath := layerFile.Name()
	if err := layerFile.Chmod(0o600); err != nil {
		_ = layerFile.Close()
		return ocilayer.Descriptor{}, layerPath, fmt.Errorf("protect layer temp: %w", err)
	}
	if err := captureFileReopen(capturePath, layerFile, plan); err != nil {
		_ = layerFile.Close()
		return ocilayer.Descriptor{}, layerPath, fmt.Errorf("build template layer: %w", err)
	}
	if err := layerFile.Sync(); err != nil {
		_ = layerFile.Close()
		return ocilayer.Descriptor{}, layerPath, fmt.Errorf("flush template layer: %w", err)
	}
	if _, err := layerFile.Seek(0, io.SeekStart); err != nil {
		_ = layerFile.Close()
		return ocilayer.Descriptor{}, layerPath, fmt.Errorf("rewind template layer: %w", err)
	}
	diffDesc, err := streamLayerDescriptor(layerFile)
	if closeErr := layerFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return ocilayer.Descriptor{}, layerPath, fmt.Errorf("digest template layer: %w", err)
	}
	if diffDesc.Size <= 0 {
		return ocilayer.Descriptor{}, layerPath, errors.New("template layer empty")
	}
	return diffDesc, layerPath, nil
}

func writeTemplateArchive(ctx context.Context, rt TemplateRuntime, layout *ocilayer.Layout, baseLayers []ocilayer.Descriptor, diffDesc ocilayer.Descriptor, layerPath string) (int64, string, error) {
	importFile, err := os.CreateTemp("", "rheic-template-import-")
	if err != nil {
		return 0, "", fmt.Errorf("create import temp: %w", err)
	}
	importPath := importFile.Name()
	if err := importFile.Chmod(0o600); err != nil {
		_ = importFile.Close()
		return 0, importPath, fmt.Errorf("protect import temp: %w", err)
	}
	src := &templateBlobSource{ctx: ctx, rt: rt, baseLayers: baseLayers, layerPath: layerPath, layerDesc: diffDesc}
	if err := ocilayer.WriteDockerSave(importFile, layout, src); err != nil {
		_ = importFile.Close()
		return 0, importPath, fmt.Errorf("write template archive: %w", err)
	}
	if err := importFile.Sync(); err != nil {
		_ = importFile.Close()
		return 0, importPath, fmt.Errorf("flush template archive: %w", err)
	}
	stat, err := importFile.Stat()
	if err != nil {
		_ = importFile.Close()
		return 0, importPath, err
	}
	size := stat.Size()
	if err := importFile.Close(); err != nil {
		return 0, importPath, fmt.Errorf("close template archive: %w", err)
	}
	return size, importPath, nil
}

func layoutName(layout *ocilayer.Layout) (string, error) {
	if layout.Manifest.Annotations == nil || layout.Manifest.Annotations[ocilayer.AnnotationImageName] == "" {
		return "", errors.New("template layout lacks image name annotation")
	}
	return layout.Manifest.Annotations[ocilayer.AnnotationImageName], nil
}

// LoadTemplate imports a docker-save/OCI template archive into the local
// image store. When name is provided it must match the archived tag after
// normalization; the archive is otherwise recorded under its own name.
func LoadTemplate(ctx context.Context, rt TemplateRuntime, tarPath, name string) (TemplateSummary, error) {
	if tarPath == "" {
		return TemplateSummary{}, errors.New("template load requires an archive path")
	}
	file, err := os.Open(tarPath) //nolint:gosec // operator-provided artifact path
	if err != nil {
		return TemplateSummary{}, fmt.Errorf("open template archive: %w", err)
	}
	defer func() { _ = file.Close() }()
	stat, err := file.Stat()
	if err != nil {
		return TemplateSummary{}, fmt.Errorf("stat template archive: %w", err)
	}
	if !stat.Mode().IsRegular() {
		return TemplateSummary{}, fmt.Errorf("template archive must be a regular file")
	}
	archivedTag, err := readArchiveTag(file)
	if err != nil {
		return TemplateSummary{}, err
	}
	effective := archivedTag
	if strings.TrimSpace(name) != "" {
		effective = strings.TrimSpace(name)
	}
	ref := normalizeLoadRef(effective)
	if err := rt.ImportTemplate(ctx, tarPath, ref); err != nil {
		return TemplateSummary{}, fmt.Errorf("load template archive: %w", err)
	}
	digest, err := rt.ImageDigest(ctx, ref)
	if err != nil {
		return TemplateSummary{}, fmt.Errorf("resolve loaded template digest: %w", err)
	}
	return TemplateSummary{Name: ref, Digest: string(digest), SizeBytes: stat.Size(), Notice: NoticeGuestSecrets}, nil
}

func readArchiveTag(file *os.File) (string, error) {
	tr := tar.NewReader(io.NewSectionReader(fileAt(file), 0, 1<<30))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", fmt.Errorf("scan template archive: %w", err)
		}
		if hdr.Name != "manifest.json" {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil {
			return "", fmt.Errorf("read manifest.json: %w", err)
		}
		var entries []struct {
			RepoTags []string `json:"RepoTags"`
		}
		if err := json.Unmarshal(raw, &entries); err != nil {
			return "", fmt.Errorf("parse manifest.json: %w", err)
		}
		if len(entries) == 0 || len(entries[0].RepoTags) == 0 || entries[0].RepoTags[0] == "" {
			return "", errors.New("template archive carries no tag")
		}
		return entries[0].RepoTags[0], nil
	}
	return "", errors.New("template archive lacks manifest.json")
}

func fileAt(f *os.File) io.ReaderAt { return f }

func normalizeLoadRef(ref string) string {
	name := ref
	if i := strings.LastIndexByte(name, ':'); i > 0 && !strings.Contains(name[i+1:], "/") {
		name = name[:i]
	}
	if strings.Contains(name, "/") && !strings.Contains(name, ".") {
		return "docker.io/library/" + ref
	}
	if !strings.Contains(name, "/") {
		return "docker.io/library/" + ref
	}
	return ref
}

func captureFileReopen(capturePath string, layerFile io.Writer, plan []ocilayer.PlannedEntry) error {
	capture, err := os.Open(capturePath) //nolint:gosec // temp owned by this flow
	if err != nil {
		return err
	}
	defer func() { _ = capture.Close() }()
	_, err = ocilayer.LayerTarFromCapture(layerFile, plan, capture)
	return err
}

func streamLayerDescriptor(r io.Reader) (ocilayer.Descriptor, error) {
	sum := sha256.New()
	n, err := io.Copy(sum, r)
	if err != nil {
		return ocilayer.Descriptor{}, err
	}
	return ocilayer.Descriptor{
		MediaType: ocilayer.MediaLayer,
		Digest:    ocilayer.Digest("sha256:" + hex.EncodeToString(sum.Sum(nil))),
		Size:      n,
	}, nil
}

func copyArchive(src, dst string) error {
	in, err := os.Open(src) //nolint:gosec // temp owned by this flow
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644) //nolint:gosec // G304: operator-chosen export path, exclusive-create by design
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("output %s already exists; remove it explicitly first", path.Base(dst))
		}
		return err
	}
	defer func() { _ = out.Close() }()
	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Close()
}

type runtimeBlobSource struct {
	ctx context.Context
	rt  TemplateRuntime
}

func (r *runtimeBlobSource) Open(d ocilayer.Descriptor) (io.ReadCloser, error) {
	return r.rt.OpenBlob(r.ctx, d)
}

type templateBlobSource struct {
	ctx        context.Context
	rt         TemplateRuntime
	baseLayers []ocilayer.Descriptor
	layerPath  string
	layerDesc  ocilayer.Descriptor
}

func (t *templateBlobSource) Open(d ocilayer.Descriptor) (io.ReadCloser, error) {
	if d.Digest == t.layerDesc.Digest {
		f, err := os.Open(t.layerPath)
		if err != nil {
			return nil, err
		}
		info, err := f.Stat()
		if err != nil {
			_ = f.Close()
			return nil, err
		}
		if info.Size() != d.Size {
			_ = f.Close()
			return nil, fmt.Errorf("template layer size moved: %d of %d", info.Size(), d.Size)
		}
		return f, nil
	}
	return t.rt.OpenBlob(t.ctx, d)
}
