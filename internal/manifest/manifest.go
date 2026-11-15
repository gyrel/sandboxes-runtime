// Package manifest validates pinned runtime inputs.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest describes native runtime pins.
type Manifest struct {
	Version    int                  `yaml:"version"`
	Platforms  []string             `yaml:"platforms"`
	Components map[string]Component `yaml:"components"`
	Patches    map[string]Patch     `yaml:"patches"`
	Images     map[string]Image     `yaml:"images"`
}

// Component is a pinned runtime dependency.
type Component struct {
	Version string `yaml:"version,omitempty"`
	Commit  string `yaml:"commit,omitempty"`
	Source  string `yaml:"source"`
	SHA256  string `yaml:"sha256,omitempty"`
	SHA512  string `yaml:"sha512,omitempty"`
}

// Patch is a checked-in patch against an open-source component.
type Patch struct {
	File   string `yaml:"file"`
	SHA256 string `yaml:"sha256"`
	Status string `yaml:"status"`
}

// Image is a pinned container image.
type Image struct {
	Ref    string `yaml:"ref"`
	Digest string `yaml:"digest"`
}

// Load reads a manifest from path.
func Load(path string) (Manifest, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- manifest path is an explicit build input
	if err != nil {
		return Manifest{}, err
	}
	return parseManifest(data)
}

func parseManifest(data []byte) (Manifest, error) {
	var m Manifest
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("parse manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return Manifest{}, fmt.Errorf("parse manifest trailing document: %w", err)
		}
		return Manifest{}, fmt.Errorf("parse manifest: multiple YAML documents")
	}
	return m, nil
}

// Verify checks required fields and patch digests relative to root.
func (m Manifest) Verify(root string) error {
	if m.Version != 1 {
		return fmt.Errorf("unsupported manifest version %d", m.Version)
	}
	if err := m.verifyComponents(); err != nil {
		return err
	}
	if err := m.verifyPatches(root); err != nil {
		return err
	}
	return m.verifyImages()
}

func (m Manifest) verifyComponents() error {
	for _, name := range []string{"containerd", "nerdbox", "libkrun", "libkrunfw", "linux-kernel-arm64", "gvisor-tap-vsock"} {
		c, ok := m.Components[name]
		if !ok || c.Source == "" || (c.Version == "" && c.Commit == "") {
			return fmt.Errorf("component %s is not pinned", name)
		}
	}
	for name, component := range m.Components {
		if err := verifyComponent(name, component); err != nil {
			return err
		}
	}
	return nil
}

func verifyComponent(name string, component Component) error {
	if component.Commit != "" && !validLowerHex(component.Commit, 40) {
		return fmt.Errorf("component %s has invalid git commit", name)
	}
	if component.Source == "" || (component.Version == "" && component.Commit == "") {
		return fmt.Errorf("component %s is not pinned", name)
	}
	if !isGitRepository(component.Source) && component.SHA256 == "" && component.SHA512 == "" {
		return fmt.Errorf("component %s has no artifact digest", name)
	}
	if component.SHA256 != "" && !validLowerHex(component.SHA256, 64) {
		return fmt.Errorf("component %s has invalid SHA-256 pin", name)
	}
	if component.SHA512 != "" && !validLowerHex(component.SHA512, 128) {
		return fmt.Errorf("component %s has invalid SHA-512 pin", name)
	}
	return nil
}

func validLowerHex(value string, length int) bool {
	if len(value) != length || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// Bare GitHub repository URLs identify source repositories, not release assets.
func isGitRepository(source string) bool {
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Host != "github.com" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	return len(parts) == 2 && parts[0] != "" && parts[1] != ""
}

func (m Manifest) verifyPatches(root string) (result error) {
	base, err := os.OpenRoot(root)
	if err != nil {
		return fmt.Errorf("open patch root: %w", err)
	}
	defer func() { result = errors.Join(result, base.Close()) }()
	names := make([]string, 0, len(m.Patches))
	for name := range m.Patches {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := m.Patches[name]
		if p.File == "" || p.SHA256 == "" {
			return fmt.Errorf("patch %s is incomplete", name)
		}
		data, err := base.ReadFile(p.File)
		if err != nil {
			return fmt.Errorf("read patch %s: %w", name, err)
		}
		sum := sha256.Sum256(data)
		if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, p.SHA256) {
			return fmt.Errorf("patch %s digest mismatch: got %s", name, got)
		}
	}
	return nil
}

func (m Manifest) verifyImages() error {
	for name, image := range m.Images {
		if image.Ref == "" || !strings.HasPrefix(image.Digest, "sha256:") || !validLowerHex(strings.TrimPrefix(image.Digest, "sha256:"), 64) {
			return fmt.Errorf("image %s is not pinned by digest", name)
		}
	}
	return nil
}
