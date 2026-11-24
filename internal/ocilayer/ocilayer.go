// Package ocilayer builds OCI-conformant template images from a guest
// filesystem diff capture, per ADR-0008. It never squashes layers: the
// captured diff becomes exactly one new layer, and the base image layers are
// referenced by their original digests (blob reuse), structurally matching
// the container-commit + docker-save artifact shape of the baseline.
//
// Whiteout semantics follow the OCI image spec: a file removal is encoded as
// a zero-byte regular entry named ".wh.<name>" inside the containing
// directory; whole-directory exclusion (mount points, /var/lib/docker) is
// encoded with the opaque marker ".wh..wh..opq". Paths are validated fail
// closed: absolute paths, ".." segments, backslash spellings, NULs and
// escaping cleanups are rejected before anything reaches a tar.
package ocilayer

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"
)

// Digest is a lowercase sha256 digest string ("sha256:...").
type Digest string

// Descriptor points at a blob in the content store or an assembled layout.
type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      Digest            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// Valid reports whether the digest is a well-formed lowercase sha256.
func (d Digest) Valid() bool { return digestRe.MatchString(string(d)) }

const (
	// MediaLayer is the uncompressed tar layer media type, matching the
	// baseline fixture layers.
	MediaLayer = "application/vnd.oci.image.layer.v1.tar"
	// MediaConfig is the OCI image config media type.
	MediaConfig = "application/vnd.oci.image.config.v1+json"
	// MediaManifest is the OCI image manifest media type.
	MediaManifest = "application/vnd.oci.image.manifest.v1+json"
	// AnnotationImageName carries the normalized docker.io/library tag on
	// manifests written by the assembler.
	AnnotationImageName = "io.containerd.image.name"
	// AnnotationRefName is the OCI index manifest annotation that `ctr images
	// import` reads as the bare tag, joined with --base-name. Without it the
	// import registers the image under a generated import-<date> name.
	AnnotationRefName = "org.opencontainers.image.ref.name"

	// Entry types accepted by ValidateDiffEntry and LayerTar.
	typeReg      = "reg"
	typeDir      = "dir"
	typeSymlink  = "symlink"
	typeHardlink = "hardlink"
	typeWhiteout = "whiteout"
	typeOpaque   = "opaque"

	whPrefix         = ".wh."
	opaqueMarkerName = ".wh..wh..opq"
	maxPathDepth     = 256
	// MaxPathLen bounds a single entry path (guest FS practical limit with
	// margin); longer is refused fail closed.
	MaxPathLen = 4096
)

// DiffEntry is one captured filesystem change relative to the base layers.
type DiffEntry struct {
	// Path is the guest-root-relative cleaned path (no leading slash).
	Path string
	// Type is one of "reg", "dir", "symlink", "hardlink", "whiteout",
	// "opaque". Whiteout and opaque entries carry no payload.
	Type string
	// Mode carries permission bits for regular/dir/symlink entries.
	Mode uint32
	// Size is the exact payload size for regular entries.
	Size int64
	// Link targets symlink/hardlink entries (guest-root-relative, cleaned).
	Link string
	// Reader streams regular file content; Layer consumes exactly Size
	// bytes and fails on early EOF or trailing data.
	Reader io.Reader
	// Modified timestamps the entry (UTC-normalized on write).
	Modified time.Time
}

// ErrUnsafePath reports a diff entry that cannot be encoded safely.
var ErrUnsafePath = errors.New("ocilayer: unsafe path")

var digestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// ValidateDiffEntry enforces the fail-closed path grammar before encoding.
func ValidateDiffEntry(e DiffEntry) error {
	if err := validateEntryPath(e.Path); err != nil {
		return err
	}
	switch e.Type {
	case typeReg:
		return validateRegular(e)
	case typeDir, typeOpaque:
		return validateNoLinkNoPayload(e)
	case typeSymlink:
		if err := validateNoLinkNoPayload(e); err != nil {
			return err
		}
		return validateSymlinkTarget(e)
	case typeHardlink:
		if err := validateNoLinkNoPayload(e); err != nil {
			return err
		}
		return validateHardlinkTarget(e)
	case typeWhiteout:
		if err := validateNoLinkNoPayload(e); err != nil {
			return err
		}
		_, _, err := whiteoutName(e.Path)
		return err
	default:
		return fmt.Errorf("unknown entry type %q for %q", e.Type, e.Path)
	}
}

func validateEntryPath(p string) error {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsRune(p, '\\') || strings.ContainsRune(p, 0) {
		return fmt.Errorf("%w: %q", ErrUnsafePath, p)
	}
	if !entryPathCharset(p) {
		return fmt.Errorf("%w: path characters outside the guest FS grammar %q", ErrUnsafePath, p)
	}
	if len(p) > MaxPathLen {
		return fmt.Errorf("%w: path too long", ErrUnsafePath)
	}
	if cleaned := path.Clean(p); cleaned != p || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return fmt.Errorf("%w: uncleaned or escaping path %q", ErrUnsafePath, p)
	}
	if parts := strings.Split(p, "/"); len(parts) > maxPathDepth || slices.Contains(parts, "..") || slices.Contains(parts, ".") {
		return fmt.Errorf("%w: bad components in %q", ErrUnsafePath, p)
	}
	return nil
}

func validateRegular(e DiffEntry) error {
	if e.Link != "" {
		return fmt.Errorf("regular entry %q must not carry a link", e.Path)
	}
	if e.Size < 0 {
		return fmt.Errorf("regular entry %q has negative size", e.Path)
	}
	if e.Size > 0 && e.Reader == nil {
		return fmt.Errorf("regular entry %q requires a reader", e.Path)
	}
	return nil
}

func validateNoLinkNoPayload(e DiffEntry) error {
	if e.Reader != nil {
		return fmt.Errorf("entry %q of type %q must not carry a reader", e.Path, e.Type)
	}
	return nil
}

// validateSymlinkTarget: the link text is stored verbatim and resolved by
// the guest kernel at use time; a symlink is not a reference into the
// archive, so relative ".." hops are legitimate. Absolute links, control
// characters and escaping syntaxes outside the path charset stay refused.
func validateSymlinkTarget(e DiffEntry) error {
	if e.Link == "" || !entryPathCharset(e.Link) || strings.HasPrefix(e.Link, "/") {
		return fmt.Errorf("%w: bad symlink target on %q", ErrUnsafePath, e.Path)
	}
	return nil
}

// validateHardlinkTarget: a hardlink header references another entry inside
// the same layer stream, so the target must be a clean relative path that
// cannot escape the captured tree.
func validateHardlinkTarget(e DiffEntry) error {
	if e.Link == "" || !entryPathCharset(e.Link) || strings.HasPrefix(e.Link, "/") ||
		path.Clean(e.Link) != e.Link || strings.HasPrefix(path.Clean(e.Link), "../") ||
		slices.Contains(strings.Split(e.Link, "/"), "..") {
		return fmt.Errorf("%w: bad hardlink target on %q", ErrUnsafePath, e.Path)
	}
	return nil
}

func whiteoutName(p string) (dir, name string, err error) {
	base := path.Base(p)
	if base == "." || base == "/" || base == "" || strings.HasPrefix(base, whPrefix) {
		return "", "", fmt.Errorf("%w: cannot whiteout %q", ErrUnsafePath, p)
	}
	dir = path.Dir(p)
	if dir == "." {
		dir = ""
	}
	return dir, whPrefix + base, nil
}

// LayerTar writes one OCI diff layer from the entries and returns its
// descriptor over the uncompressed tar stream. Entries must be supplied in
// a deterministic order (the capture layer sorts them); opaque markers
// belong to excluded directories and are validated like everything else.
func LayerTar(w io.Writer, entries []DiffEntry) (Descriptor, error) {
	digester := sha256.New()
	size := &countingWriter{}
	// Headers and payloads share one sink so the digest and size cover the
	// exact produced stream.
	tw := tar.NewWriter(io.MultiWriter(w, digester, size))
	for _, e := range entries {
		if err := writeEntry(tw, e); err != nil {
			return Descriptor{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return Descriptor{}, fmt.Errorf("close layer tar: %w", err)
	}
	return Descriptor{
		MediaType: MediaLayer,
		Digest:    Digest("sha256:" + hex.EncodeToString(digester.Sum(nil))),
		Size:      size.n,
	}, nil
}

func writeEntry(tw *tar.Writer, e DiffEntry) error {
	if err := ValidateDiffEntry(e); err != nil {
		return err
	}
	mod := normalized(e.Modified)
	switch e.Type {
	case typeWhiteout:
		return writeWhiteout(tw, e, mod)
	case typeOpaque:
		return tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeReg, Name: path.Join(e.Path, opaqueMarkerName),
			Mode: 0o644, Size: 0, Format: tar.FormatGNU, ModTime: mod,
		})
	case typeDir:
		return tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeDir, Name: e.Path + "/", Mode: perm(e.Mode, 0o755),
			Format: tar.FormatGNU, ModTime: mod,
		})
	case typeSymlink:
		return tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeSymlink, Name: e.Path, Linkname: e.Link,
			Mode: 0o777, Format: tar.FormatGNU, ModTime: mod,
		})
	case typeHardlink:
		return tw.WriteHeader(&tar.Header{
			Typeflag: tar.TypeLink, Name: e.Path, Linkname: e.Link,
			Mode: 0o644, Format: tar.FormatGNU, ModTime: mod,
		})
	default:
		return writeRegular(tw, e, mod)
	}
}

func writeOpaque(tw *tar.Writer, e DiffEntry, mod time.Time) error {
	return tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg, Name: path.Join(e.Path, opaqueMarkerName),
		Mode: 0o644, Size: 0, Format: tar.FormatGNU, ModTime: mod,
	})
}

func writeWhiteout(tw *tar.Writer, e DiffEntry, mod time.Time) error {
	dir, name, err := whiteoutName(e.Path)
	if err != nil {
		return err
	}
	return tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg, Name: path.Join(dir, name),
		Mode: 0o644, Size: 0, Format: tar.FormatGNU, ModTime: mod,
	})
}

func writeRegular(tw *tar.Writer, e DiffEntry, mod time.Time) error {
	if err := tw.WriteHeader(&tar.Header{
		Typeflag: tar.TypeReg, Name: e.Path, Mode: perm(e.Mode, 0o644),
		Size: e.Size, Format: tar.FormatGNU, ModTime: mod,
	}); err != nil {
		return err
	}
	if e.Size == 0 {
		return nil
	}
	n, err := io.Copy(tw, io.LimitReader(e.Reader, e.Size))
	if err != nil {
		return fmt.Errorf("payload %q: %w", e.Path, err)
	}
	if n != e.Size {
		return fmt.Errorf("payload %q: short copy (%d of %d bytes)", e.Path, n, e.Size)
	}
	return probeOverflow(e)
}

func probeOverflow(e DiffEntry) error {
	var extra [1]byte
	read, err := e.Reader.Read(extra[:])
	if read > 0 {
		return fmt.Errorf("payload %q: reader produced more than the declared size", e.Path)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("payload %q: overflow probe failed: %w", e.Path, err)
	}
	return nil
}

type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

func perm(mode uint32, def uint32) int64 {
	if mode == 0 {
		return int64(def)
	}
	return int64(mode & 0o7777)
}

func normalized(t time.Time) time.Time {
	if t.IsZero() {
		return time.Unix(0, 0).UTC()
	}
	return t.UTC()
}

// entryPathCharset allows the printable guest path grammar (no control
// characters, spaces allowed, no backslashes, no NUL); it mirrors what a
// Linux filesystem can actually contain while excluding anything a tar
// reader could misinterpret.
func entryPathCharset(p string) bool {
	// NUL and backslash are the disallowed characters; "\\x00" here once
	// meant the literal letters x/0 and rejected every ordinary guest path
	// (e.g. "external"), which broke real captures.
	if p == "" || strings.ContainsAny(p, "\x00\\") {
		return false
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}
