package ctr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"

	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/rheic/sandboxes-runtime/internal/ocilayer"
)

// ErrDigestMismatch is returned when a content-store blob read back does not
// match its recorded digest. The store verifies content on write, but
// template export re-reads blobs later; a same-UID path substitution in
// between must be caught here, so every streamed blob is re-hashed against
// its descriptor (fail closed).
var ErrDigestMismatch = errors.New("containerd content digest mismatch")

// ErrUnsupportedImageShape reports manifests or indexes this adapter cannot
// resolve (multi-platform ambiguity, unknown media types).
var ErrUnsupportedImageShape = errors.New("unsupported image manifest shape")

const maxTemplateBlobBytes = 1 << 30

// ImageLayerDescriptors returns the ordered layer descriptors, the config
// descriptor and the raw config document for a locally present image.
// Index indirection is followed only when exactly one child exists.
func (b *Backend) ImageLayerDescriptors(ctx context.Context, image string) (layers []ocilayer.Descriptor, config ocilayer.Descriptor, configBytes []byte, err error) {
	client, err := containerd.New(b.client.cfg.Socket, containerd.WithDefaultNamespace(b.client.cfg.Namespace))
	if err != nil {
		return nil, ocilayer.Descriptor{}, nil, fmt.Errorf("connect containerd: %w", err)
	}
	defer func() { _ = client.Close() }()
	img, err := client.GetImage(ctx, image)
	if err != nil {
		return nil, ocilayer.Descriptor{}, nil, fmt.Errorf("get image %s: %w", sanitizeRef(image), err)
	}
	store := img.ContentStore()
	manifestBytes, err := resolveManifest(ctx, store, img.Target())
	if err != nil {
		return nil, ocilayer.Descriptor{}, nil, fmt.Errorf("resolve manifest for %s: %w", sanitizeRef(image), err)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return nil, ocilayer.Descriptor{}, nil, fmt.Errorf("%w: parse manifest: %w", ErrUnsupportedImageShape, err)
	}
	if manifest.Config.Digest == "" || len(manifest.Layers) == 0 {
		return nil, ocilayer.Descriptor{}, nil, fmt.Errorf("%w: manifest lacks config or layers", ErrUnsupportedImageShape)
	}
	configBytes, err = readBlob(ctx, store, manifest.Config)
	if err != nil {
		return nil, ocilayer.Descriptor{}, nil, fmt.Errorf("read image config: %w", err)
	}
	config = descriptorOf(manifest.Config)
	layers = make([]ocilayer.Descriptor, 0, len(manifest.Layers))
	for _, l := range manifest.Layers {
		if l.Digest == "" || l.Size <= 0 {
			return nil, ocilayer.Descriptor{}, nil, fmt.Errorf("%w: layer lacks digest or size", ErrUnsupportedImageShape)
		}
		layers = append(layers, descriptorOf(l))
	}
	return layers, config, configBytes, nil
}

func resolveManifest(ctx context.Context, store content.Store, desc ocispec.Descriptor) ([]byte, error) {
	for depth := 0; depth < 8; depth++ {
		raw, err := readBlob(ctx, store, desc)
		if err != nil {
			return nil, err
		}
		if strings.Contains(desc.MediaType, "image.index") {
			var idx ocispec.Index
			if err := json.Unmarshal(raw, &idx); err != nil {
				return nil, fmt.Errorf("%w: parse index: %w", ErrUnsupportedImageShape, err)
			}
			if len(idx.Manifests) != 1 {
				return nil, fmt.Errorf("%w: index with %d manifests", ErrUnsupportedImageShape, len(idx.Manifests))
			}
			desc = idx.Manifests[0]
			continue
		}
		if !strings.Contains(desc.MediaType, "image.manifest") {
			return nil, fmt.Errorf("%w: media type %q", ErrUnsupportedImageShape, desc.MediaType)
		}
		return raw, nil
	}
	return nil, fmt.Errorf("%w: index chain too deep", ErrUnsupportedImageShape)
}

func readBlob(ctx context.Context, store content.Store, desc ocispec.Descriptor) ([]byte, error) {
	ra, err := store.ReaderAt(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("open content blob %s: %w", short(desc.Digest), err)
	}
	defer func() { _ = ra.Close() }()
	if desc.Size <= 0 || desc.Size > maxTemplateBlobBytes {
		return nil, fmt.Errorf("content blob %s has unusable size %d", short(desc.Digest), desc.Size)
	}
	data := make([]byte, desc.Size)
	n, err := ra.ReadAt(data, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("read content blob %s: %w", short(desc.Digest), err)
	}
	if int64(n) != desc.Size {
		return nil, fmt.Errorf("%w: blob %s short read (%d of %d)", ErrDigestMismatch, short(desc.Digest), n, desc.Size)
	}
	sum := sha256.Sum256(data)
	if got := digest.Digest("sha256:" + hex.EncodeToString(sum[:])); got != desc.Digest {
		return nil, fmt.Errorf("%w: blob %s recomputed as %s", ErrDigestMismatch, short(desc.Digest), short(got))
	}
	return data, nil
}

// OpenTemplateBlob exposes verified streaming reads of one content blob for
// exporters building docker-save archives without buffering it fully.
func (b *Backend) OpenTemplateBlob(ctx context.Context, d ocilayer.Digest, size int64) (io.ReadCloser, error) {
	client, err := containerd.New(b.client.cfg.Socket, containerd.WithDefaultNamespace(b.client.cfg.Namespace))
	if err != nil {
		return nil, fmt.Errorf("connect containerd: %w", err)
	}
	ra, err := client.ContentStore().ReaderAt(ctx, ocispec.Descriptor{Digest: digest.Digest(d), Size: size})
	if err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("open content blob %s: %w", short(digest.Digest(d)), err)
	}
	return &verifiedBlobReader{ra: ra, remaining: size, total: size, hasher: sha256.New(), want: digest.Digest(d), client: client}, nil
}

type verifiedBlobReader struct {
	ra        content.ReaderAt
	remaining int64
	total     int64
	hasher    hash.Hash
	want      digest.Digest
	closed    bool
	client    *containerd.Client
}

func (r *verifiedBlobReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.ra.ReadAt(p, r.readOffset())
	if n > 0 {
		_, _ = r.hasher.Write(p[:n])
		r.remaining -= int64(n)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return n, err
	}
	if r.remaining == 0 {
		return n, io.EOF
	}
	return n, nil
}

func (r *verifiedBlobReader) readOffset() int64 { return r.total - r.remaining }

func (r *verifiedBlobReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	closeErr := errors.Join(r.ra.Close(), r.client.Close())
	if closeErr != nil {
		return closeErr
	}
	got := digest.Digest("sha256:" + hex.EncodeToString(r.hasher.Sum(nil)))
	if r.remaining != 0 {
		return fmt.Errorf("%w: blob %s unread tail of %d bytes", ErrDigestMismatch, short(r.want), r.remaining)
	}
	if got != r.want {
		return fmt.Errorf("%w: blob %s recomputed as %s", ErrDigestMismatch, short(r.want), short(got))
	}
	return nil
}

func descriptorOf(d ocispec.Descriptor) ocilayer.Descriptor {
	return ocilayer.Descriptor{MediaType: d.MediaType, Digest: ocilayer.Digest(d.Digest.String()), Size: d.Size}
}

func short(d digest.Digest) string {
	s := d.String()
	if len(s) > 19 {
		return s[:19] + "…"
	}
	return s
}

func sanitizeRef(ref string) string {
	if len(ref) > 128 {
		return ref[:128]
	}
	return ref
}
