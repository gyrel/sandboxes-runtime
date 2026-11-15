// Package artifact verifies runtime-shipped executables against recorded
// SHA-256 digests before the runtime launches them.
package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const digestPrefix = "sha256:"

// Reasons reported by VerifyError. Callers can compare with errors.As to
// distinguish a missing digest entry from a tampered binary.
const (
	ReasonMismatch     = "sha256 digest mismatch"
	ReasonMissingEntry = "no digest entry"
	ReasonMissingFile  = "artifact file is missing"
	ReasonUnreadable   = "artifact file is unreadable"
	ReasonNotRegular   = "artifact is not a regular file"
	ReasonChanged      = "artifact changed during verification"
	ReasonInvalidPath  = "artifact path is invalid"
)

// ErrNotConfigured is returned when the runtime launch path has no artifact
// verification policy. The runtime never launches an artifact in that case.
var ErrNotConfigured = errors.New(
	"runtime artifact verification is not configured: set the runtime-managed artifact paths and the digest file; " +
		"host-provided containerd and ctr binaries are intentionally unmanaged and are not verified by this runtime")

// Digest is a canonical SHA-256 digest in the form "sha256:<lowercase hex>".
type Digest string

// ParseDigest validates a SHA-256 digest written as 64 hexadecimal characters
// with an optional "sha256:" prefix and returns its canonical form.
func ParseDigest(value string) (Digest, error) {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(strings.ToLower(value), digestPrefix)
	if len(value) != sha256.Size*2 {
		return "", fmt.Errorf("invalid SHA-256 digest %q: want 64 hexadecimal characters", value)
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("invalid SHA-256 digest %q: %w", value, err)
	}
	return Digest(digestPrefix + hex.EncodeToString(decoded)), nil
}

// Hex returns the digest without the "sha256:" prefix.
func (d Digest) Hex() string {
	return strings.TrimPrefix(string(d), digestPrefix)
}

// VerifyError describes a failed artifact verification. Error messages name
// the artifact, the expected and actual digests, and the next operator action.
type VerifyError struct {
	Artifact    string
	Path        string
	Expected    Digest
	Actual      Digest
	Reason      string
	DigestsPath string
	Err         error
}

func (e *VerifyError) Error() string {
	var message strings.Builder
	fmt.Fprintf(&message, "runtime artifact %q", e.Artifact)
	if e.Path != "" {
		fmt.Fprintf(&message, " (%s)", e.Path)
	}
	message.WriteString(": ")
	switch e.Reason {
	case ReasonMismatch:
		fmt.Fprintf(&message, "SHA-256 mismatch: expected %s, actual %s", e.Expected, e.Actual)
	case ReasonMissingEntry:
		fmt.Fprintf(&message, "has no SHA-256 digest recorded in %s", e.DigestsPath)
	default:
		message.WriteString(e.Reason)
		if e.Expected != "" {
			fmt.Fprintf(&message, " (expected %s)", e.Expected)
		}
	}
	if e.Err != nil {
		fmt.Fprintf(&message, ": %v", e.Err)
	}
	message.WriteString("; refusing to launch an unverified artifact")
	if e.Reason == ReasonMismatch || e.Reason == ReasonMissingEntry ||
		e.Reason == ReasonMissingFile || e.Reason == ReasonUnreadable ||
		e.Reason == ReasonNotRegular || e.Reason == ReasonChanged {
		message.WriteString(`; restore or rebuild the artifact from the pinned inputs and regenerate the digests with "make artifact-digests"`)
	}
	return message.String()
}

// Unwrap exposes the underlying filesystem error.
func (e *VerifyError) Unwrap() error { return e.Err }

// DigestOfFile hashes path with SHA-256. It rejects symlinks and non-regular
// files and re-checks that the opened file is the one that was inspected.
func DigestOfFile(path string) (Digest, error) {
	return digestFile("", path)
}

func digestFile(name, path string) (Digest, error) {
	info, err := os.Lstat(path)
	if err != nil {
		reason := ReasonUnreadable
		if errors.Is(err, os.ErrNotExist) {
			reason = ReasonMissingFile
		}
		return "", &VerifyError{Artifact: name, Path: path, Reason: reason, Err: err}
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", &VerifyError{Artifact: name, Path: path, Reason: ReasonNotRegular}
	}
	file, err := os.Open(path) // #nosec G304 -- path is an operator-configured runtime artifact
	if err != nil {
		return "", &VerifyError{Artifact: name, Path: path, Reason: ReasonUnreadable, Err: err}
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil {
		return "", &VerifyError{Artifact: name, Path: path, Reason: ReasonUnreadable, Err: err}
	}
	if !os.SameFile(info, opened) {
		return "", &VerifyError{Artifact: name, Path: path, Reason: ReasonChanged}
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", &VerifyError{Artifact: name, Path: path, Reason: ReasonUnreadable, Err: err}
	}
	return Digest(digestPrefix + hex.EncodeToString(hash.Sum(nil))), nil
}

// VerifyFile checks one artifact path against its expected digest.
func VerifyFile(name, path string, expected Digest) error {
	if name == "" {
		return errors.New("artifact name is required")
	}
	if !filepath.IsAbs(path) {
		return &VerifyError{Artifact: name, Path: path, Reason: ReasonInvalidPath}
	}
	actual, err := digestFile(name, path)
	if err != nil {
		var verifyErr *VerifyError
		if errors.As(err, &verifyErr) {
			verifyErr.Expected = expected
		}
		return err
	}
	if actual != expected {
		return &VerifyError{
			Artifact: name,
			Path:     path,
			Expected: expected,
			Actual:   actual,
			Reason:   ReasonMismatch,
		}
	}
	return nil
}
