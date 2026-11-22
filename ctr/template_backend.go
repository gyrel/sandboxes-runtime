package ctr

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	containerd "github.com/containerd/containerd/v2/client"

	runtime "github.com/rheic/sandboxes-runtime"

	"github.com/rheic/sandboxes-runtime/internal/ocilayer"
)

// CaptureGuestRoot runs a guest-side `tar -cf -` of the whole root
// filesystem as root, excluding the given guest paths (validated by
// validateTemplateExcludes upstream; re-validated here defensively). The
// archive stream is written to stdout. Busybox and GNU tar share the
// --exclude/-C/. grammar used here.
func (b *Backend) CaptureGuestRoot(ctx context.Context, h runtime.Handle, excludes []string, stdout io.Writer) error {
	argv := []string{"tar", "-cf", "-"}
	for _, e := range excludes {
		rel, err := templateExcludeArg(e)
		if err != nil {
			return err
		}
		argv = append(argv, "--exclude="+rel)
	}
	relDefault, err := templateExcludeArg(templateDefaultExclude)
	if err != nil {
		return err
	}
	argv = append(argv, "--exclude="+relDefault, "-C", "/", ".")
	code, err := b.ExecNative(ctx, h, runtime.ExecRequest{Argv: argv, User: "root", Stdout: stdout})
	if err != nil {
		return fmt.Errorf("guest capture failed (code %d): %w", code, err)
	}
	if code != 0 {
		return fmt.Errorf("guest capture exited %d", code)
	}
	return nil
}

func templateExcludeArg(p string) (string, error) {
	p = strings.TrimSpace(p)
	if p == "" || !strings.HasPrefix(p, "/") || path.Clean(p) != p ||
		strings.ContainsAny(p, "\n\x00") || p == "/" || strings.HasPrefix(p, "-") {
		return "", fmt.Errorf("%w: %q", ErrUnsafeExclude, p)
	}
	return strings.TrimPrefix(p, "/"), nil
}

// ImageLayers exposes the verified manifest/config/blob listing seam for
// template assembly.
func (b *Backend) ImageLayers(ctx context.Context, image string) ([]ocilayer.Descriptor, []byte, error) {
	layers, _, config, err := b.ImageLayerDescriptors(ctx, image)
	if err != nil {
		return nil, nil, err
	}
	return layers, config, nil
}

// OpenBlob streams one verified content blob for template export.
func (b *Backend) OpenBlob(ctx context.Context, d ocilayer.Descriptor) (io.ReadCloser, error) {
	return b.OpenTemplateBlob(ctx, d.Digest, d.Size)
}

// ImportTemplate records a template archive in the local image store under
// the expected normalized reference.
func (b *Backend) ImportTemplate(ctx context.Context, tarPath, ref string) error {
	return b.client.ImportImage(ctx, tarPath, ref)
}

// RemoveTemplateImage deletes a recorded template reference from the local
// image store. Callers (the daemon) must first refuse images still
// referenced by sandboxes.
func (b *Backend) RemoveTemplateImage(ctx context.Context, ref string) error {
	return b.client.RemoveImage(ctx, ref)
}

// ExportTemplateArchive writes the named template image to tarPath as a
// docker-save archive.
func (b *Backend) ExportTemplateArchive(ctx context.Context, ref, tarPath string) error {
	if strings.TrimSpace(ref) == "" || strings.TrimSpace(tarPath) == "" {
		return errors.New("template export requires an image reference and an output path")
	}
	return b.client.ExportImage(ctx, tarPath, ref)
}

// ImageDigest resolves the manifest digest of a locally present reference.
func (b *Backend) ImageDigest(ctx context.Context, ref string) (ocilayer.Digest, error) {
	client, err := containerd.New(b.client.cfg.Socket, containerd.WithDefaultNamespace(b.client.cfg.Namespace))
	if err != nil {
		return "", fmt.Errorf("connect containerd: %w", err)
	}
	defer func() { _ = client.Close() }()
	img, err := client.GetImage(ctx, ref)
	if err != nil {
		return "", fmt.Errorf("resolve imported template %s: %w", sanitizeRef(ref), err)
	}
	return ocilayer.Digest(img.Target().Digest.String()), nil
}
