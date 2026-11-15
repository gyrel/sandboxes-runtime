package ctr

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	runtime "github.com/rheic/sandboxes-runtime"
	"github.com/rheic/sandboxes-runtime/internal/artifact"
)

const testShimArtifact = "containerd-shim-nerdbox-v1"

func testArtifactOptions(t *testing.T) BackendOptions {
	t.Helper()
	opts, _ := testArtifactOptionsWithPath(t)
	return opts
}

func testArtifactOptionsWithPath(t *testing.T) (BackendOptions, string) {
	t.Helper()
	dir := t.TempDir()
	manifestData := []byte("version: 1\n")
	manifestPath := filepath.Join(dir, "manifest.yaml")
	if err := os.WriteFile(manifestPath, manifestData, 0o600); err != nil {
		t.Fatal(err)
	}
	shimPath := filepath.Join(dir, testShimArtifact)
	shimData := []byte("verified synthetic shim")
	if err := os.WriteFile(shimPath, shimData, 0o700); err != nil {
		t.Fatal(err)
	}
	manifestSum := sha256.Sum256(manifestData)
	shimSum := sha256.Sum256(shimData)
	digests := fmt.Sprintf(`version: 1
manifest_sha256: %s
patches: {}
artifacts:
  %s: "sha256:%s"
`, hex.EncodeToString(manifestSum[:]), testShimArtifact, hex.EncodeToString(shimSum[:]))
	digestsPath := filepath.Join(dir, "digests.yaml")
	if err := os.WriteFile(digestsPath, []byte(digests), 0o600); err != nil {
		t.Fatal(err)
	}
	return BackendOptions{
		Artifacts:   map[string]string{testShimArtifact: shimPath},
		DigestsPath: digestsPath,
	}, shimPath
}

func testArtifactVerifier(t *testing.T) *artifact.Verifier {
	t.Helper()
	opts := testArtifactOptions(t)
	verifier, err := artifact.NewVerifier(artifact.Config{
		DigestsPath: opts.DigestsPath,
		Artifacts:   opts.Artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func TestCreateRefusesLaunchWhenArtifactVerificationFails(t *testing.T) {
	opts, shimPath := testArtifactOptionsWithPath(t)
	if err := os.WriteFile(shimPath, []byte("replaced synthetic shim"), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	backend, err := NewBackend(Config{Socket: "/tmp/containerd.sock", CTR: "ctr"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	backend.client.runner = runner
	_, err = backend.Create(t.Context(), runtime.Config{Name: "dev"})
	if err == nil {
		t.Fatal("Create launched an artifact that failed verification")
	}
	requireArtifactMismatch(t, err)
	if len(runner.calls) != 0 {
		t.Fatalf("Create invoked ctr before verification: %v", runner.calls)
	}
}

func TestCreateRefusesWhenArtifactVerificationIsNotConfigured(t *testing.T) {
	runner := &fakeRunner{}
	backend := &Backend{client: newTestClient(t, runner), image: "img"}
	_, err := backend.Create(t.Context(), runtime.Config{Name: "dev"})
	if !errors.Is(err, artifact.ErrNotConfigured) {
		t.Fatalf("Create error = %v, want ErrNotConfigured", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("Create invoked ctr without a verification policy: %v", runner.calls)
	}
}

func TestStartRefusesWhenArtifactVerificationFails(t *testing.T) {
	opts, shimPath := testArtifactOptionsWithPath(t)
	verifier, err := artifact.NewVerifier(artifact.Config{
		DigestsPath: opts.DigestsPath,
		Artifacts:   opts.Artifacts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shimPath, []byte("replaced synthetic shim"), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	network := &fakeNetwork{}
	backend := &Backend{client: newTestClient(t, runner), network: network, verifier: verifier}
	if err := backend.Start(t.Context(), runtime.Handle{ID: "rheic-dev"}); err == nil {
		t.Fatal("Start launched an artifact that failed verification")
	} else {
		requireArtifactMismatch(t, err)
	}
	if network.started != 0 || len(runner.calls) != 0 {
		t.Fatalf("Start launched network=%d ctr-calls=%v before verification", network.started, runner.calls)
	}
}

func requireArtifactMismatch(t *testing.T, err error) {
	t.Helper()
	var verifyErr *artifact.VerifyError
	if !errors.As(err, &verifyErr) {
		t.Fatalf("error %v is not an artifact verification error", err)
	}
	if verifyErr.Reason != artifact.ReasonMismatch {
		t.Fatalf("verification reason = %q, want mismatch: %v", verifyErr.Reason, err)
	}
}
