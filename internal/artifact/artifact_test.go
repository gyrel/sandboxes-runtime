package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifierTable(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.yaml")
	manifestData := []byte("version: 1\n")
	writeFile(t, manifestPath, manifestData, 0o600)
	shimPath := filepath.Join(dir, "containerd-shim-nerdbox-v1")
	shimData := []byte("verified synthetic shim")
	writeFile(t, shimPath, shimData, 0o700)
	otherPath := filepath.Join(dir, "replaced-shim")
	writeFile(t, otherPath, []byte("tampered synthetic shim"), 0o700)
	directoryPath := filepath.Join(dir, "not-a-file")
	if err := os.Mkdir(directoryPath, 0o700); err != nil {
		t.Fatal(err)
	}
	digestsPath := writeDigestsFile(t, dir, digestOf(manifestData), map[string][]byte{
		"containerd-shim-nerdbox-v1": shimData,
	})
	verifier := func(t *testing.T, artifacts map[string]string) *Verifier {
		t.Helper()
		value, err := NewVerifier(Config{DigestsPath: digestsPath, Artifacts: artifacts})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	tests := []struct {
		name       string
		artifacts  map[string]string
		wantReason string
	}{
		{name: "match", artifacts: map[string]string{"containerd-shim-nerdbox-v1": shimPath}},
		{
			name:       "mismatch",
			artifacts:  map[string]string{"containerd-shim-nerdbox-v1": otherPath},
			wantReason: ReasonMismatch,
		},
		{
			name:       "missing file",
			artifacts:  map[string]string{"containerd-shim-nerdbox-v1": filepath.Join(dir, "absent")},
			wantReason: ReasonMissingFile,
		},
		{
			name:       "missing entry",
			artifacts:  map[string]string{"gvproxy": shimPath},
			wantReason: ReasonMissingEntry,
		},
		{
			name:       "not a regular file",
			artifacts:  map[string]string{"containerd-shim-nerdbox-v1": directoryPath},
			wantReason: ReasonNotRegular,
		},
		{
			name:       "relative path",
			artifacts:  map[string]string{"containerd-shim-nerdbox-v1": "relative/shim"},
			wantReason: ReasonInvalidPath,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "relative path" {
				if _, err := NewVerifier(Config{DigestsPath: digestsPath, Artifacts: test.artifacts}); err == nil {
					t.Fatal("NewVerifier accepted a relative artifact path")
				}
				return
			}
			err := verifier(t, test.artifacts).Verify()
			if test.wantReason == "" {
				if err != nil {
					t.Fatalf("verification failed: %v", err)
				}
				return
			}
			requireVerifyError(t, err, test.wantReason)
		})
	}
}

func TestVerifierReportsExpectedAndActualDigest(t *testing.T) {
	dir := t.TempDir()
	manifestData := []byte("version: 1\n")
	writeFile(t, filepath.Join(dir, "manifest.yaml"), manifestData, 0o600)
	good := []byte("verified binary")
	bad := []byte("replaced binary")
	path := filepath.Join(dir, "gvproxy")
	writeFile(t, path, bad, 0o700)
	digestsPath := writeDigestsFile(t, dir, digestOf(manifestData), map[string][]byte{"gvproxy": good})
	value, err := NewVerifier(Config{DigestsPath: digestsPath, Artifacts: map[string]string{"gvproxy": path}})
	if err != nil {
		t.Fatal(err)
	}
	err = value.Verify()
	requireVerifyError(t, err, ReasonMismatch)
	for _, want := range []string{
		"gvproxy",
		"expected sha256:" + digestOf(good),
		"actual sha256:" + digestOf(bad),
		"refusing to launch",
		"make artifact-digests",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not contain %q", err, want)
		}
	}
}

func TestVerifierRejectsUnreadableArtifact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not express unreadable files with POSIX permissions")
	}
	if os.Geteuid() == 0 {
		t.Skip("root can read files regardless of POSIX permissions")
	}
	dir := t.TempDir()
	manifestData := []byte("version: 1\n")
	writeFile(t, filepath.Join(dir, "manifest.yaml"), manifestData, 0o600)
	path := filepath.Join(dir, "qemu")
	writeFile(t, path, []byte("verified qemu"), 0o700)
	digestsPath := writeDigestsFile(t, dir, digestOf(manifestData), map[string][]byte{"qemu": []byte("verified qemu")})
	value, err := NewVerifier(Config{DigestsPath: digestsPath, Artifacts: map[string]string{"qemu": path}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	requireVerifyError(t, value.Verify(), ReasonUnreadable)
}

func TestVerifierRejectsChangedManifest(t *testing.T) {
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "manifest.yaml")
	writeFile(t, manifestPath, []byte("version: 1\n"), 0o600)
	shimData := []byte("verified shim")
	shimPath := filepath.Join(dir, "shim")
	writeFile(t, shimPath, shimData, 0o700)
	digestsPath := writeDigestsFile(t, dir, digestOf([]byte("version: 1\n")), map[string][]byte{"shim": shimData})
	value, err := NewVerifier(Config{DigestsPath: digestsPath, Artifacts: map[string]string{"shim": shimPath}})
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, manifestPath, []byte("version: 1\n# modified\n"), 0o600)
	err = value.Verify()
	requireVerifyError(t, err, ReasonMismatch)
	if !strings.Contains(err.Error(), "manifest.yaml") {
		t.Fatalf("manifest mismatch error does not name the manifest: %v", err)
	}
}

func TestGenerateAndVerifyBuildInputs(t *testing.T) {
	dir := t.TempDir()
	patchData := []byte("synthetic patch\n")
	patchDir := filepath.Join(dir, "patches")
	if err := os.Mkdir(patchDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(patchDir, "p.patch"), patchData, 0o600)
	manifestData := []byte(fmt.Sprintf(`version: 1
platforms: [linux/arm64]
components:
  containerd: {version: "1", source: "x"}
  nerdbox: {version: "1", source: "x"}
  libkrun: {version: "1", source: "x"}
  libkrunfw: {version: "1", source: "x"}
  linux-kernel-arm64: {version: "1", source: "x"}
  gvisor-tap-vsock: {version: "1", source: "x"}
patches:
  p:
    file: patches/p.patch
    sha256: %s
    status: experimental
images:
  default: {ref: "x", digest: "sha256:%s"}
`, digestOf(patchData), strings.Repeat("0", 64)))
	manifestPath := filepath.Join(dir, "manifest.yaml")
	writeFile(t, manifestPath, manifestData, 0o600)
	shimPath := filepath.Join(dir, "shim")
	shimData := []byte("verified shim")
	writeFile(t, shimPath, shimData, 0o700)
	digestsPath := filepath.Join(dir, "digests.yaml")
	if err := Generate(manifestPath, digestsPath, map[string]string{"shim": shimPath}); err != nil {
		t.Fatal(err)
	}
	value, err := NewVerifier(Config{DigestsPath: digestsPath, Artifacts: map[string]string{"shim": shimPath}})
	if err != nil {
		t.Fatal(err)
	}
	if err := value.Verify(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(patchDir, "p.patch"), []byte("tampered patch\n"), 0o600)
	err = value.Verify()
	requireVerifyError(t, err, ReasonMismatch)
	if !strings.Contains(err.Error(), "patch p") {
		t.Fatalf("patch mismatch error does not name the patch: %v", err)
	}
}

func TestRepositoryDigestsVerify(t *testing.T) {
	if runtime.GOOS == "windows" {
		// Git rewrites the pinned sources with CRLF on windows runners, which
		// changes their bytes; the digest gate is exercised by the table tests.
		t.Skip("git autocrlf rewrites pinned sources on windows runners")
	}
	digests, err := LoadDigests(filepath.Join("..", "..", "build", "digests.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := digests.VerifyBuild(filepath.Join("..", "..", "build")); err != nil {
		t.Fatal(err)
	}
}

func TestParseDigest(t *testing.T) {
	hexDigest := strings.Repeat("ab", 32)
	for _, value := range []string{hexDigest, "sha256:" + hexDigest, "SHA256:" + strings.ToUpper(hexDigest)} {
		digest, err := ParseDigest(value)
		if err != nil {
			t.Fatalf("ParseDigest(%q): %v", value, err)
		}
		if digest.Hex() != hexDigest {
			t.Fatalf("ParseDigest(%q) = %s", value, digest)
		}
	}
	for _, value := range []string{"", "abc", "sha256:", strings.Repeat("zz", 32)} {
		if _, err := ParseDigest(value); err == nil {
			t.Fatalf("ParseDigest accepted %q", value)
		}
	}
}

func writeDigestsFile(t *testing.T, dir, manifestDigest string, artifacts map[string][]byte) string {
	t.Helper()
	var body strings.Builder
	body.WriteString("version: 1\n")
	fmt.Fprintf(&body, "manifest_sha256: %s\n", manifestDigest)
	body.WriteString("patches: {}\nartifacts:\n")
	for name, data := range artifacts {
		fmt.Fprintf(&body, "  %s: \"sha256:%s\"\n", name, digestOf(data))
	}
	path := filepath.Join(dir, "digests.yaml")
	writeFile(t, path, []byte(body.String()), 0o600)
	return path
}

func digestOf(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func writeFile(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
}

func requireVerifyError(t *testing.T, err error, reason string) {
	t.Helper()
	if err == nil {
		t.Fatalf("verification succeeded; want %s", reason)
	}
	var verifyErr *VerifyError
	if !errors.As(err, &verifyErr) {
		t.Fatalf("error %v is not a *VerifyError", err)
	}
	if verifyErr.Reason != reason {
		t.Fatalf("verification reason = %q, want %q: %v", verifyErr.Reason, reason, err)
	}
}
