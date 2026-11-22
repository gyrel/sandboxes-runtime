package ctr

import (
	"errors"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func idxDesc(id string, p *ocispec.Platform) ocispec.Descriptor {
	return ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.Digest("sha256:" + id),
		Size:      100,
		Platform:  p,
	}
}

func TestSelectIndexManifestPacksPlatformChild(t *testing.T) {
	// Reproduces the live shell-template index: two attestations plus
	// amd64/arm64 children.
	manifests := []ocispec.Descriptor{
		idxDesc("aa", nil),
		idxDesc("bb", &ocispec.Platform{OS: "unknown", Architecture: "unknown"}),
		idxDesc("cc", &ocispec.Platform{OS: "linux", Architecture: "amd64"}),
		idxDesc("dd", &ocispec.Platform{OS: "linux", Architecture: "arm64", Variant: "v8"}),
	}
	got, err := selectIndexManifest(manifests, "linux/arm64")
	if err != nil {
		t.Fatal(err)
	}
	if got.Digest.String() != "sha256:dd" {
		t.Fatalf("selected %s want dd", got.Digest)
	}
	// Exact variant match still works.
	got, err = selectIndexManifest(manifests, "linux/arm64/v8")
	if err != nil || got.Digest.String() != "sha256:dd" {
		t.Fatalf("variant exact: %v %s", err, got.Digest)
	}
}

func TestSelectIndexManifestRefusesAmbiguity(t *testing.T) {
	manifests := []ocispec.Descriptor{
		idxDesc("aa", &ocispec.Platform{OS: "linux", Architecture: "arm", Variant: "v6"}),
		idxDesc("bb", &ocispec.Platform{OS: "linux", Architecture: "arm", Variant: "v7"}),
	}
	if _, err := selectIndexManifest(manifests, "linux/arm"); !errors.Is(err, ErrUnsupportedImageShape) {
		t.Fatalf("ambiguous bare arm must be refused, got %v", err)
	}
	if _, err := selectIndexManifest(manifests, "linux/arm/v7"); err != nil {
		t.Fatalf("exact variant must resolve: %v", err)
	}
	if _, err := selectIndexManifest([]ocispec.Descriptor{idxDesc("cc", &ocispec.Platform{OS: "linux", Architecture: "amd64"})}, "linux/arm64"); !errors.Is(err, ErrUnsupportedImageShape) {
		t.Fatalf("missing platform must be refused, got %v", err)
	}
	if _, err := selectIndexManifest(manifests, ""); !errors.Is(err, ErrUnsupportedImageShape) {
		t.Fatalf("empty platform must be refused, got %v", err)
	}
}

func TestSelectIndexManifestSingleAndArm64VsArm(t *testing.T) {
	// "linux/arm64" must not match the "linux/arm/v8" spelling used by
	// some indexes (architecture arm64 has no separate variant namespace).
	manifests := []ocispec.Descriptor{
		idxDesc("aa", &ocispec.Platform{OS: "linux", Architecture: "arm", Variant: "v8"}),
		idxDesc("bb", &ocispec.Platform{OS: "linux", Architecture: "arm64"}),
	}
	got, err := selectIndexManifest(manifests, "linux/arm64")
	if err != nil || got.Digest.String() != "sha256:bb" {
		t.Fatalf("arm64 vs arm/v8: %v %s", err, got.Digest)
	}
}
