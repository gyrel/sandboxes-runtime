package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifyPartialBundle(t *testing.T) {
	root := writeTestBundle(t, "linux/arm64", Partial, map[string]string{"shim": "test shim"})
	if _, err := Verify(root, Options{ExpectedPlatform: "linux/arm64", AllowPartial: true}); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if _, err := Verify(root, Options{ExpectedPlatform: "linux/arm64"}); err == nil || !strings.Contains(err.Error(), "partial") {
		t.Fatalf("Verify() error = %v, want partial bundle rejection", err)
	}
}

func TestVerifyRejectsDeclaredPlatformMismatch(t *testing.T) {
	root := writeTestBundle(t, "linux/arm64", Partial, map[string]string{"shim": "test shim"})
	if _, err := Verify(root, Options{ExpectedPlatform: "darwin/arm64", AllowPartial: true}); err == nil {
		t.Fatal("Verify() accepted a bundle for the wrong platform")
	}
}

func TestVerifyUsesDeclaredPlatformLabelOnly(t *testing.T) {
	root := writeTestBundle(t, "linux/arm64", Partial, map[string]string{"shim": "payload bytes are not inspected for ABI"})
	if _, err := Verify(root, Options{ExpectedPlatform: "linux/arm64", AllowPartial: true}); err != nil {
		t.Fatalf("Verify() error = %v, want declared-platform match", err)
	}
}

func TestVerifyFailsClosedForModifiedArtifact(t *testing.T) {
	root := writeTestBundle(t, "linux/arm64", Partial, map[string]string{"shim": "test shim"})
	if err := os.WriteFile(filepath.Join(root, "bin/shim"), []byte("modified shim"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, Options{ExpectedPlatform: "linux/arm64", AllowPartial: true}); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Verify() error = %v, want digest mismatch", err)
	}
}

func TestManifestAloneDoesNotAuthenticateArtifact(t *testing.T) {
	root := writeTestBundle(t, "linux/arm64", Partial, map[string]string{"shim": "original shim"})
	data := []byte("changed shim")
	if err := os.WriteFile(filepath.Join(root, "bin/shim"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	writeManifest(t, root, Manifest{
		SchemaVersion: SchemaV1,
		Platform:      "linux/arm64",
		Completeness:  Partial,
		Files:         []FileItem{{Component: "shim", Path: "bin/shim", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(data))}},
	})
	if _, err := Verify(root, Options{ExpectedPlatform: "linux/arm64", AllowPartial: true}); err != nil {
		t.Fatalf("Verify() error = %v, want rewritten manifest consistency to pass", err)
	}
}

func TestVerifyFailsClosedForMissingArtifact(t *testing.T) {
	root := writeTestBundle(t, "linux/arm64", Partial, map[string]string{"shim": "test shim"})
	if err := os.Remove(filepath.Join(root, "bin/shim")); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, Options{ExpectedPlatform: "linux/arm64", AllowPartial: true}); err == nil {
		t.Fatal("Verify() accepted a missing artifact")
	}
}

func TestVerifyFailsClosedForUndeclaredArtifact(t *testing.T) {
	root := writeTestBundle(t, "linux/arm64", Partial, map[string]string{"shim": "test shim"})
	if err := os.WriteFile(filepath.Join(root, "bin/extra"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, Options{ExpectedPlatform: "linux/arm64", AllowPartial: true}); err == nil {
		t.Fatal("Verify() accepted an undeclared artifact")
	}
}

func TestVerifyRequiredRolesRequiresMinimumRoleSubset(t *testing.T) {
	root := writeTestBundle(t, "linux/arm64", Partial, map[string]string{"shim": "test shim"})
	data, err := os.ReadFile(filepath.Join(root, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Completeness = RequiredRoles
	writeManifest(t, root, manifest)
	if _, err := Verify(root, Options{ExpectedPlatform: "linux/arm64"}); err == nil || !strings.Contains(err.Error(), "containerd") {
		t.Fatalf("Verify() error = %v, want incomplete role rejection", err)
	}
}

func TestVerifyAcceptsRequiredRoleSubset(t *testing.T) {
	files := make(map[string]string, len(requiredComponents))
	for _, component := range requiredComponents {
		files[component] = "synthetic " + component
	}
	root := writeTestBundle(t, "linux/arm64", RequiredRoles, files)
	if _, err := Verify(root, Options{ExpectedPlatform: "linux/arm64"}); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
}

func TestWriteManifestRejectsUnlistedFilesAndDoesNotLeaveManifest(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin/shim"), []byte("shim"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "unexpected"), []byte("extra"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := WriteManifest(root, "linux/arm64", Partial, []FileItem{{Component: "shim", Path: "bin/shim"}})
	if err == nil || !strings.Contains(err.Error(), "undeclared") {
		t.Fatalf("WriteManifest() error = %v, want undeclared artifact rejection", err)
	}
	if _, err := os.Lstat(filepath.Join(root, ManifestName)); !os.IsNotExist(err) {
		t.Fatalf("failed manifest generation left bundle.json: %v", err)
	}
}

func TestVerifyRejectsPathTraversal(t *testing.T) {
	root := t.TempDir()
	content := []byte("outside")
	if err := os.WriteFile(filepath.Join(root, "outside"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	writeManifest(t, root, Manifest{
		SchemaVersion: SchemaV1,
		Platform:      "linux/arm64",
		Completeness:  Partial,
		Files:         []FileItem{{Component: "shim", Path: "../outside", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(content))}},
	})
	if _, err := Verify(root, Options{ExpectedPlatform: "linux/arm64", AllowPartial: true}); err == nil {
		t.Fatal("Verify() accepted a traversal path")
	}
}

func TestVerifyRejectsDuplicateJSONKeys(t *testing.T) {
	root := t.TempDir()
	data := []byte(`{"schema_version":1,"platform":"linux/arm64","platform":"darwin/arm64","completeness":"partial","files":[{"component":"shim","path":"bin/shim","sha256":"0000000000000000000000000000000000000000000000000000000000000000","size":0}]}`)
	if err := os.WriteFile(filepath.Join(root, ManifestName), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(root, Options{ExpectedPlatform: "darwin/arm64", AllowPartial: true}); err == nil || !strings.Contains(err.Error(), "duplicate JSON") {
		t.Fatalf("Verify() error = %v, want duplicate-key rejection", err)
	}
}

func TestVerifyRejectsSymlinkArtifact(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "real"), []byte("test shim"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../real", filepath.Join(root, "bin/shim")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink creation unavailable: %v", err)
		}
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("test shim"))
	writeManifest(t, root, Manifest{
		SchemaVersion: SchemaV1,
		Platform:      "linux/arm64",
		Completeness:  Partial,
		Files:         []FileItem{{Component: "shim", Path: "bin/shim", SHA256: hex.EncodeToString(digest[:]), Size: int64(len("test shim"))}},
	})
	if _, err := Verify(root, Options{ExpectedPlatform: "linux/arm64", AllowPartial: true}); err == nil {
		t.Fatal("Verify() accepted a symlink artifact")
	}
}

func writeTestBundle(t *testing.T, platform, completeness string, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	declarations := make([]FileItem, 0, len(files))
	for component, content := range files {
		name := "bin/" + component
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, name)), 0o700); err != nil {
			t.Fatal(err)
		}
		data := []byte(content)
		if err := os.WriteFile(filepath.Join(root, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
		declarations = append(declarations, FileItem{Component: component, Path: name})
	}
	if err := WriteManifest(root, platform, completeness, declarations); err != nil {
		t.Fatal(err)
	}
	return root
}

func writeManifest(t *testing.T, root string, manifest Manifest) {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ManifestName), data, 0o600); err != nil {
		t.Fatal(err)
	}
}
