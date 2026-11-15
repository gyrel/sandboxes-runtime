package artifact

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/rheic/sandboxes-runtime/internal/manifest"
)

const digestFileVersion = 1

// Digests is the checked-in record of trusted digests. It binds the runtime to
// one build/manifest.yaml revision and records the patch digests from that
// manifest together with the digests of the runtime-shipped executables.
type Digests struct {
	Version        int               `yaml:"version"`
	ManifestSHA256 string            `yaml:"manifest_sha256"`
	Patches        map[string]Patch  `yaml:"patches"`
	Artifacts      map[string]string `yaml:"artifacts"`
	// Path is the file this record was loaded from; it is not serialized.
	Path string `yaml:"-"`
}

// Patch is one manifest patch whose file content is verified at startup.
type Patch struct {
	File   string `yaml:"file"`
	SHA256 string `yaml:"sha256"`
}

// LoadDigests reads and validates a runtime digest file.
func LoadDigests(path string) (Digests, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- digest path is an explicit runtime input
	if err != nil {
		return Digests{}, fmt.Errorf("read runtime digest file %s: %w", path, err)
	}
	var digests Digests
	if err := yaml.Unmarshal(data, &digests); err != nil {
		return Digests{}, fmt.Errorf("parse runtime digest file %s: %w", path, err)
	}
	digests.Path = path
	if err := digests.normalize(); err != nil {
		return Digests{}, fmt.Errorf("invalid runtime digest file %s: %w", path, err)
	}
	return digests, nil
}

func (d *Digests) normalize() error {
	if d.Version != digestFileVersion {
		return fmt.Errorf("unsupported version %d", d.Version)
	}
	manifestDigest, err := ParseDigest(d.ManifestSHA256)
	if err != nil {
		return fmt.Errorf("manifest_sha256: %w", err)
	}
	d.ManifestSHA256 = manifestDigest.Hex()
	for name, patch := range d.Patches {
		if strings.TrimSpace(name) == "" {
			return errors.New("patch name is empty")
		}
		if _, err := safeRelativePath(patch.File); err != nil {
			return fmt.Errorf("patch %s: %w", name, err)
		}
		digest, err := ParseDigest(patch.SHA256)
		if err != nil {
			return fmt.Errorf("patch %s: %w", name, err)
		}
		patch.SHA256 = digest.Hex()
		d.Patches[name] = patch
	}
	for name, value := range d.Artifacts {
		if err := validateArtifactName(name); err != nil {
			return err
		}
		digest, err := ParseDigest(value)
		if err != nil {
			return fmt.Errorf("artifact %s: %w", name, err)
		}
		d.Artifacts[name] = digest.String()
	}
	return nil
}

// String returns the canonical "sha256:<hex>" form.
func (d Digest) String() string { return string(d) }

// VerifyBuild checks the manifest file and every patch listed in the digest
// file. Paths are resolved relative to the directory containing the digest
// file, which is expected to be build/ next to manifest.yaml.
func (d Digests) VerifyBuild(root string) error {
	manifestPath := filepath.Join(root, "manifest.yaml")
	expectedManifest := Digest(digestPrefix + d.ManifestSHA256)
	actualManifest, err := digestFile("manifest.yaml", manifestPath)
	if err != nil {
		return withDigestPath(err, d.Path)
	}
	if actualManifest != expectedManifest {
		return &VerifyError{
			Artifact:    "manifest.yaml",
			Path:        manifestPath,
			Expected:    expectedManifest,
			Actual:      actualManifest,
			Reason:      ReasonMismatch,
			DigestsPath: d.Path,
		}
	}
	names := make([]string, 0, len(d.Patches))
	for name := range d.Patches {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		patch := d.Patches[name]
		relative, err := safeRelativePath(patch.File)
		if err != nil {
			return fmt.Errorf("patch %s: %w", name, err)
		}
		patchPath := filepath.Join(root, relative)
		actual, err := digestFile("patch "+name, patchPath)
		if err != nil {
			return withDigestPath(err, d.Path)
		}
		if expected := Digest(digestPrefix + patch.SHA256); actual != expected {
			return &VerifyError{
				Artifact:    "patch " + name,
				Path:        patchPath,
				Expected:    expected,
				Actual:      actual,
				Reason:      ReasonMismatch,
				DigestsPath: d.Path,
			}
		}
	}
	return nil
}

// VerifyArtifacts checks every configured artifact path against its recorded
// digest. It fails when a path has no digest entry, when the file is missing or
// unreadable, and when the SHA-256 differs.
func (d Digests) VerifyArtifacts(paths map[string]string) error {
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		expected, ok := d.Artifacts[name]
		if !ok {
			return &VerifyError{
				Artifact:    name,
				Path:        paths[name],
				Reason:      ReasonMissingEntry,
				DigestsPath: d.Path,
			}
		}
		digest, err := ParseDigest(expected)
		if err != nil {
			return &VerifyError{
				Artifact:    name,
				Path:        paths[name],
				Reason:      ReasonMissingEntry,
				DigestsPath: d.Path,
				Err:         err,
			}
		}
		if err := VerifyFile(name, paths[name], digest); err != nil {
			return withDigestPath(err, d.Path)
		}
	}
	return nil
}

// Config configures a startup verifier.
type Config struct {
	// DigestsPath is the digest file, normally build/digests.yaml.
	DigestsPath string
	// Artifacts maps logical names of runtime-shipped binaries to absolute
	// host paths. Every entry must have a digest in DigestsPath.
	Artifacts map[string]string
}

// Verifier hashes the manifest, patches, and configured runtime artifacts.
type Verifier struct {
	digests   Digests
	artifacts map[string]string
}

// NewVerifier validates the digest file and artifact configuration without
// hashing the artifacts yet. Verify does the hashing on each launch.
func NewVerifier(cfg Config) (*Verifier, error) {
	if cfg.DigestsPath == "" || len(cfg.Artifacts) == 0 {
		return nil, ErrNotConfigured
	}
	digestsPath, err := filepath.Abs(cfg.DigestsPath)
	if err != nil {
		return nil, fmt.Errorf("resolve digest file path: %w", err)
	}
	paths := make(map[string]string, len(cfg.Artifacts))
	for name, path := range cfg.Artifacts {
		if err := validateArtifactName(name); err != nil {
			return nil, err
		}
		if !filepath.IsAbs(path) {
			return nil, fmt.Errorf("artifact %s path must be absolute: %s", name, path)
		}
		paths[name] = path
	}
	digests, err := LoadDigests(digestsPath)
	if err != nil {
		return nil, err
	}
	return &Verifier{digests: digests, artifacts: paths}, nil
}

// Verify hashes the manifest, its patches, and every configured artifact. It is
// called once per runtime start and returns the first verification failure.
func (v *Verifier) Verify() error {
	if v == nil {
		return ErrNotConfigured
	}
	root := filepath.Dir(v.digests.Path)
	if err := v.digests.VerifyBuild(root); err != nil {
		return err
	}
	return v.digests.VerifyArtifacts(v.artifacts)
}

// Generate hashes a verified artifact set and writes a digest file next to
// manifestPath. It verifies the manifest's component pins, patch digests, and
// image pins before recording the computed digests.
func Generate(manifestPath, digestsPath string, artifacts map[string]string) error {
	absManifest, err := filepath.Abs(manifestPath)
	if err != nil {
		return fmt.Errorf("resolve manifest path: %w", err)
	}
	root := filepath.Dir(absManifest)
	pins, err := manifest.Load(absManifest)
	if err != nil {
		return err
	}
	if err := pins.Verify(root); err != nil {
		return fmt.Errorf("manifest verification failed: %w", err)
	}
	manifestDigest, err := digestFile("manifest.yaml", absManifest)
	if err != nil {
		return err
	}
	patches, err := recordPatches(root, pins)
	if err != nil {
		return err
	}
	recorded, err := recordArtifacts(artifacts)
	if err != nil {
		return err
	}
	digests := Digests{
		Version:        digestFileVersion,
		ManifestSHA256: manifestDigest.Hex(),
		Patches:        patches,
		Artifacts:      recorded,
	}
	if err := digests.normalize(); err != nil {
		return err
	}
	data, err := yaml.Marshal(digests)
	if err != nil {
		return fmt.Errorf("encode runtime digest file: %w", err)
	}
	header := "# Code generated by scripts/update-artifact-digests.sh; DO NOT EDIT.\n" +
		"# Regenerate from a verified artifact set after every manifest or artifact change.\n"
	absOut, err := filepath.Abs(digestsPath)
	if err != nil {
		return fmt.Errorf("resolve digest output path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absOut), 0o750); err != nil {
		return fmt.Errorf("create digest output directory: %w", err)
	}
	// #nosec G306 -- the digest file is public build metadata.
	if err := os.WriteFile(absOut, append([]byte(header), data...), 0o644); err != nil {
		return fmt.Errorf("write runtime digest file %s: %w", absOut, err)
	}
	return nil
}

func recordPatches(root string, pins manifest.Manifest) (map[string]Patch, error) {
	patches := make(map[string]Patch, len(pins.Patches))
	for name, patch := range pins.Patches {
		path, err := safeRelativePath(patch.File)
		if err != nil {
			return nil, fmt.Errorf("patch %s: %w", name, err)
		}
		digest, err := digestFile("patch "+name, filepath.Join(root, path))
		if err != nil {
			return nil, err
		}
		patches[name] = Patch{File: filepath.ToSlash(patch.File), SHA256: digest.Hex()}
	}
	return patches, nil
}

func recordArtifacts(artifacts map[string]string) (map[string]string, error) {
	recorded := make(map[string]string, len(artifacts))
	for name, path := range artifacts {
		if err := validateArtifactName(name); err != nil {
			return nil, err
		}
		digest, err := digestFile(name, path)
		if err != nil {
			return nil, err
		}
		recorded[name] = digest.String()
	}
	return recorded, nil
}

func validateArtifactName(name string) error {
	if name == "" || len(name) > 128 {
		return fmt.Errorf("invalid artifact name %q", name)
	}
	for _, char := range name {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || char == '-' || char == '_' || char == '.' {
			continue
		}
		return fmt.Errorf("invalid artifact name %q", name)
	}
	return nil
}

func safeRelativePath(value string) (string, error) {
	if value == "" || filepath.IsAbs(value) {
		return "", fmt.Errorf("path must be relative: %q", value)
	}
	clean := filepath.Clean(filepath.FromSlash(value))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes the build directory: %q", value)
	}
	return clean, nil
}

func withDigestPath(err error, digestsPath string) error {
	var verifyErr *VerifyError
	if errors.As(err, &verifyErr) {
		verifyErr.DigestsPath = digestsPath
	}
	return err
}
