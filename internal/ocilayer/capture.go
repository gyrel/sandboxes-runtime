package ocilayer

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// FileMeta is one indexed entry of a guest filesystem capture tar. The
// capture is produced by a guest-side `tar -cf -` run and materialized on
// the host (temporary file), so the index can hash payloads and a later
// pass can re-read any entry by offset without buffering the whole archive
// in memory.
type FileMeta struct {
	Path     string
	Type     string
	Mode     uint32
	Size     int64
	Link     string
	Modified time.Time
	// Digest is the payload content hash for regular files (empty for the
	// rest). It powers exact-content skipping during diffing.
	Digest Digest
	// Offset locates the payload inside the capture stream.
	Offset int64
}

// ErrMalformedCapture reports a capture archive that cannot be indexed.
var ErrMalformedCapture = errors.New("ocilayer: malformed capture archive")

// maxCaptureEntries bounds indexed entries; larger captures indicate a
// broken or hostile stream and are refused (fail closed).
const maxCaptureEntries = 4 << 20

// IndexCapture scans a random-access tar stream (USTAR/GNU/PAX headers with
// payload blocks) and returns entries sorted by path. Global PAX headers
// are consumed transparently; unsupported record types abort indexing.
func IndexCapture(ra io.ReaderAt, size int64) ([]FileMeta, error) {
	var out []FileMeta
	tr := tar.NewReader(io.NewSectionReader(ra, 0, size))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedCapture, err)
		}
		meta, present, err := metaFromHeader(hdr, tr)
		if err != nil {
			return nil, err
		}
		if present {
			out = append(out, meta)
			if len(out) > maxCaptureEntries {
				return nil, fmt.Errorf("%w: too many entries", ErrMalformedCapture)
			}
		}
	}
	slices.SortFunc(out, func(a, b FileMeta) int { return strings.Compare(a.Path, b.Path) })
	return out, nil
}

func metaFromHeader(hdr *tar.Header, tr *tar.Reader) (FileMeta, bool, error) {
	name, err := normalizeCapturePath(hdr.Name)
	if err != nil {
		return FileMeta{}, false, err
	}
	if name == "" {
		// Archive root marker ("./"): not a filesystem entry. The base
		// listing skips it the same way; indexing it here made the plan
		// reference a member the stream layer never emits.
		return FileMeta{}, false, nil
	}
	kind, known, global := captureType(hdr.Typeflag)
	if global {
		return FileMeta{}, false, nil
	}
	if !known {
		return FileMeta{}, false, fmt.Errorf("%w: unsupported record %q on %q", ErrMalformedCapture, string(hdr.Typeflag), hdr.Name)
	}
	meta := &FileMeta{Path: name, Type: kind, Mode: uint32(hdr.Mode & 0o7777), Size: hdr.Size, Link: hdr.Linkname, Modified: hdr.ModTime.UTC()}
	if kind == typeHardlink {
		link, err := normalizeLinkTarget(hdr.Linkname)
		if err != nil {
			return FileMeta{}, false, fmt.Errorf("%w: %w on %q", ErrMalformedCapture, err, hdr.Name)
		}
		meta.Link = link
	}
	if kind == typeReg {
		// Current position of the section reader is header+payload start;
		// tar data begins right after the 512-byte block grid consumed so
		// far. Recompute from tr's underlying reader is unreliable, so we
		// hash by consuming the entry here; the caller keeps the same
		// archive open for the second (payload) pass.
		sum := sha256.New()
		n, err := io.Copy(sum, io.LimitReader(tr, hdr.Size))
		if err != nil {
			return FileMeta{}, false, fmt.Errorf("%w: payload %q: %w", ErrMalformedCapture, hdr.Name, err)
		}
		if n != hdr.Size {
			return FileMeta{}, false, fmt.Errorf("%w: short payload for %q", ErrMalformedCapture, hdr.Name)
		}
		meta.Digest = Digest("sha256:" + hex.EncodeToString(sum.Sum(nil)))
	}
	return *meta, true, nil
}

func captureType(flag byte) (string, bool, bool) {
	switch flag {
	case tar.TypeReg:
		return typeReg, true, false
	case tar.TypeDir:
		return "dir", true, false
	case tar.TypeSymlink:
		return "symlink", true, false
	case tar.TypeLink:
		return "hardlink", true, false
	case tar.TypeXGlobalHeader:
		// Stream-wide metadata, not a filesystem entry.
		return "", false, true
	default:
		// Character devices, FIFOs and sparse maps cannot be part of a
		// template layer; indexing stops instead of guessing semantics.
		return "", false, false
	}
}

// normalizeCapturePath strips "./" and "/" prefixes produced by `tar -cf -
// .` runs and validates the remainder against the entry grammar.
// normalizeLinkTarget canonicalizes a hardlink target to the clean
// relative grammar used by entry paths. GNU tar records the target of a
// hardlink with the same "./" prefix it gave the member itself, while
// registry base layers store plain relative names; comparing or re-emitting
// the raw strings produced spurious "changed" hardlinks that then failed
// path validation ("bad hardlink target"). Symlink targets intentionally
// keep their raw text: they are resolved by the guest kernel at use time.
func normalizeLinkTarget(name string) (string, error) {
	p := strings.TrimPrefix(strings.TrimPrefix(name, "./"), "/")
	if p == "" {
		return "", fmt.Errorf("%w: empty hardlink target", ErrUnsafePath)
	}
	cleaned := path.Clean(p)
	if cleaned != p || cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", fmt.Errorf("%w: uncleaned or escaping hardlink target %q", ErrUnsafePath, name)
	}
	return cleaned, nil
}

func normalizeCapturePath(name string) (string, error) {
	p := strings.TrimPrefix(name, "./")
	p = strings.TrimPrefix(p, "/")
	if p == "" || p == "." {
		return "", nil // archive root marker, not an entry
	}
	if strings.ContainsAny(p, "\x00\\") || !utf8OK(p) {
		return "", fmt.Errorf("%w: bad capture path %q", ErrMalformedCapture, name)
	}
	if cleaned := strings.TrimSuffix(p, "/"); cleaned != p {
		p = cleaned
	}
	if err := validateEntryPath(p); err != nil {
		return "", fmt.Errorf("%w: %w", ErrMalformedCapture, err)
	}
	return p, nil
}

func utf8OK(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == 0x7f || (r < 0x20 && r != '\n' && r != '\t') {
			return false
		}
	}
	return true
}

// PlannedEntry is one diff layer instruction: either emit the captured
// entry (Payload must be re-read from the capture by the exporter) or a
// synthesized whiteout/opaque removal.
type PlannedEntry struct {
	// Emit carries the encoded entry (payload attached by the caller for
	// regular files).
	Emit DiffEntry
	// CaptureIndex points back into the captured index for payload
	// re-reading (-1 for synthesized removals).
	CaptureIndex int
}

// BaseFile is one known entry of the template's base image layers.
type BaseFile struct {
	Path   string
	Type   string
	Mode   uint32
	Digest Digest
	// Link is the stored target for symlink/hardlink base entries; it lets
	// the diff skip unchanged links instead of re-emitting every base link
	// (alpine's bin/ is a symlink, and re-emitting it broke the capture
	// stream, which cannot carry payloads for link types).
	Link string
}

// Diff compares an indexed capture with the base listing and returns the
// deterministic layer plan. Identical entries (type, mode and content
// digest for regular files) are skipped. Removals become per-file
// whiteouts, except under opaque directories, which receive a single
// opaque marker and suppress descendant whiteouts.
// Diff plans one OCI diff layer. opaqueDirs mark excluded live directories
// (their lower content is hidden); virtualDirs (proc, sys, dev, bundle
// mounts) are capture-time-only prefixes: entries under them never become
// additions, never become whiteouts and receive no opaque marker, because
// their runtime contents are not image state.
func Diff(captured []FileMeta, base map[string]BaseFile, opaqueDirs, virtualDirs []string) ([]PlannedEntry, error) {
	if err := validateOpaqueDirs(opaqueDirs); err != nil {
		return nil, err
	}
	plans := additions(captured, base, opaqueDirs, virtualDirs)
	plans, err := includeHardlinkTargets(plans, captured, opaqueDirs, virtualDirs)
	if err != nil {
		return nil, err
	}
	plans = append(plans, removals(captured, base, opaqueDirs, virtualDirs)...)
	for _, dir := range opaqueDirs {
		plans = append(plans, PlannedEntry{Emit: DiffEntry{Path: dir, Type: "opaque"}, CaptureIndex: -1})
	}
	return plans, nil
}

// includeHardlinkTargets guarantees layer self-containment: a hardlink
// member references another member by name inside the same tar, so every
// emitted hardlink drags its target in even when the target alone would
// have been skipped as unchanged. A target that is not a captured member,
// or that lives under an excluded (opaque or virtual) prefix, cannot be
// represented in the layer and is refused (fail closed) instead of
// producing a template that breaks at apply or boot.
func includeHardlinkTargets(plans []PlannedEntry, captured []FileMeta, opaqueDirs, virtualDirs []string) ([]PlannedEntry, error) {
	index := make(map[string]int, len(captured))
	for i, m := range captured {
		index[m.Path] = i
	}
	planned := make(map[string]bool, len(plans))
	for _, pl := range plans {
		planned[pl.Emit.Path] = true
	}
	out := plans
	var pending []string
	for _, pl := range plans {
		if pl.Emit.Type == typeHardlink {
			pending = append(pending, pl.Emit.Link)
		}
	}
	for len(pending) > 0 {
		target := pending[0]
		pending = pending[1:]
		if planned[target] {
			continue
		}
		if underAnyOpaque(target, virtualDirs) {
			return nil, fmt.Errorf("%w: hardlink target %q is under a virtual prefix", ErrInvalid, target)
		}
		i, ok := index[target]
		if !ok {
			return nil, fmt.Errorf("%w: hardlink target %q is not a captured member", ErrInvalid, target)
		}
		m := captured[i]
		if underAnyOpaque(m.Path, opaqueDirs) {
			return nil, fmt.Errorf("%w: hardlink target %q is inside an excluded directory", ErrInvalid, target)
		}
		planned[target] = true
		out = append(out, PlannedEntry{
			Emit:         DiffEntry{Path: m.Path, Type: m.Type, Mode: m.Mode, Size: m.Size, Link: m.Link, Modified: m.Modified},
			CaptureIndex: i,
		})
		if m.Type == typeHardlink {
			pending = append(pending, m.Link)
		}
	}
	return out, nil
}

func validateOpaqueDirs(dirs []string) error {
	for _, dir := range dirs {
		if err := validateEntryPath(dir); err != nil {
			return err
		}
	}
	return nil
}

// additions keeps captured entries that are new or changed relative to the
// base listing and skips untouched duplicates (type+mode+content digest).
func additions(captured []FileMeta, base map[string]BaseFile, opaqueDirs, virtualDirs []string) []PlannedEntry {
	plans := make([]PlannedEntry, 0, len(captured))
	for i, m := range captured {
		if underAnyOpaque(m.Path, opaqueDirs) || underAnyOpaque(m.Path, virtualDirs) {
			continue
		}
		old, existed := base[m.Path]
		if existed && unchangedBase(m, old) {
			continue
		}
		plans = append(plans, PlannedEntry{
			Emit:         DiffEntry{Path: m.Path, Type: m.Type, Mode: m.Mode, Size: m.Size, Link: m.Link, Modified: m.Modified},
			CaptureIndex: i,
		})
	}
	return plans
}

// unchangedBase reports whether a captured entry is identical to its base
// record by the comparison each type supports: regular files by mode and
// content digest, directories by mode, links by target (hardlinks also by
// mode), specials by presence only (no payload semantics are stored).
func unchangedBase(m FileMeta, old BaseFile) bool {
	if m.Type != old.Type {
		return false
	}
	switch m.Type {
	case typeReg:
		return old.Mode == m.Mode && old.Digest == m.Digest
	case typeDir:
		return old.Mode == m.Mode
	case typeSymlink:
		return old.Link == m.Link
	case typeHardlink:
		return old.Link == m.Link && old.Mode == m.Mode
	case "special":
		return true
	default:
		return false
	}
}

// removals whiteouts base paths missing from the capture. Whiteouting a
// base directory path removes the directory and its subtree on overlay
// apply, so one entry per missing base path is sufficient.
func removals(captured []FileMeta, base map[string]BaseFile, opaqueDirs, virtualDirs []string) []PlannedEntry {
	capturedSet := make(map[string]struct{}, len(captured))
	for _, m := range captured {
		capturedSet[m.Path] = struct{}{}
	}
	var paths []string
	for p := range base {
		if underAnyOpaque(p, opaqueDirs) || underAnyOpaque(p, virtualDirs) {
			continue
		}
		if _, ok := capturedSet[p]; !ok {
			paths = append(paths, p)
		}
	}
	slices.Sort(paths)
	plans := make([]PlannedEntry, 0, len(paths))
	for _, p := range paths {
		plans = append(plans, PlannedEntry{Emit: DiffEntry{Path: p, Type: "whiteout"}, CaptureIndex: -1})
	}
	return plans
}

func underAnyOpaque(p string, dirs []string) bool {
	for _, d := range dirs {
		if p == d || strings.HasPrefix(p, strings.TrimSuffix(d, "/")+"/") {
			return true
		}
	}
	return false
}

// FindCapturePayload re-reads one regular entry's payload by scanning the
// capture stream to its position, so exporters can stream layer bytes
// without holding the whole archive in memory. The returned reader yields
// exactly FileMeta.Size bytes.
func FindCapturePayload(ra io.ReaderAt, size int64, want FileMeta) (io.Reader, error) {
	tr := tar.NewReader(io.NewSectionReader(ra, 0, size))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: capture payload %q not found", ErrMalformedCapture, want.Path)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrMalformedCapture, err)
		}
		name, err := normalizeCapturePath(hdr.Name)
		if err != nil {
			return nil, err
		}
		if name != want.Path || hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Size != want.Size {
			return nil, fmt.Errorf("%w: capture payload %q size moved", ErrMalformedCapture, want.Path)
		}
		if want.Size == 0 {
			return bytes.NewReader(nil), nil
		}
		return io.LimitReader(tr, want.Size), nil
	}
}
