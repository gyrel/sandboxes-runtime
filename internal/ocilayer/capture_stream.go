package ocilayer

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sort"
)

// LayerTarFromCapture streams the layer tar for a diff plan while scanning
// the capture archive exactly once. Planned additions are re-emitted
// byte-for-byte from the live capture stream (no random access, no full
// buffering); whiteouts and opaque markers are appended afterwards. The
// plan must come from Diff so its ordering is deterministic.
func LayerTarFromCapture(w io.Writer, plan []PlannedEntry, capture io.Reader) (Descriptor, error) {
	additions, trailing, err := splitPlan(plan)
	if err != nil {
		return Descriptor{}, err
	}
	digester := sha256.New()
	counter := &countingWriter{}
	tw := tar.NewWriter(io.MultiWriter(w, digester, counter))
	if err := streamAdditions(tw, additions, capture); err != nil {
		return Descriptor{}, err
	}
	for _, e := range trailing {
		if err := writeEntryNoProbe(tw, e); err != nil {
			return Descriptor{}, err
		}
	}
	if err := tw.Close(); err != nil {
		return Descriptor{}, fmt.Errorf("close layer tar: %w", err)
	}
	return Descriptor{MediaType: MediaLayer, Digest: Digest("sha256:" + hex.EncodeToString(digester.Sum(nil))), Size: counter.n}, nil
}

func splitPlan(plan []PlannedEntry) (map[string]DiffEntry, []DiffEntry, error) {
	additions := map[string]DiffEntry{}
	var trailing []DiffEntry
	for _, pl := range plan {
		switch pl.Emit.Type {
		case typeWhiteout, typeOpaque:
			if err := ValidateDiffEntry(pl.Emit); err != nil {
				return nil, nil, err
			}
			trailing = append(trailing, pl.Emit)
		default:
			if _, dup := additions[pl.Emit.Path]; dup {
				return nil, nil, fmt.Errorf("%w: duplicate addition %q", ErrInvalid, pl.Emit.Path)
			}
			additions[pl.Emit.Path] = pl.Emit
		}
	}
	return additions, trailing, nil
}

func streamAdditions(tw *tar.Writer, additions map[string]DiffEntry, capture io.Reader) error {
	tr := tar.NewReader(capture)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("%w: scan capture: %w", ErrMalformedCapture, err)
		}
		name, err := normalizeCapturePath(hdr.Name)
		if err != nil {
			return err
		}
		if name == "" {
			continue
		}
		want, ok := additions[name]
		if !ok {
			continue
		}
		e, err := plannedFromHeader(hdr, want, tr)
		if err != nil {
			return err
		}
		if err := writeEntryNoProbe(tw, e); err != nil {
			return err
		}
		delete(additions, name)
	}
	if len(additions) > 0 {
		missing := make([]string, 0, len(additions))
		for p := range additions {
			missing = append(missing, p)
		}
		sort.Strings(missing)
		if len(missing) > 8 {
			missing = missing[:8]
		}
		return fmt.Errorf("%w: plan references %d entries absent from capture (first: %v)", ErrMalformedCapture, len(additions), missing)
	}
	return nil
}

func writeEntryNoProbe(tw *tar.Writer, e DiffEntry) error {
	if err := ValidateDiffEntry(e); err != nil {
		return err
	}
	mod := normalized(e.Modified)
	switch e.Type {
	case typeWhiteout:
		return writeWhiteout(tw, e, mod)
	case typeOpaque:
		return writeOpaque(tw, e, mod)
	case typeDir:
		return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: e.Path + "/", Mode: perm(e.Mode, 0o755), Format: tar.FormatGNU, ModTime: mod})
	case typeSymlink:
		return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeSymlink, Name: e.Path, Linkname: e.Link, Mode: 0o777, Format: tar.FormatGNU, ModTime: mod})
	case typeHardlink:
		return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeLink, Name: e.Path, Linkname: e.Link, Mode: 0o644, Format: tar.FormatGNU, ModTime: mod})
	default:
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: e.Path, Mode: perm(e.Mode, 0o644), Size: e.Size, Format: tar.FormatGNU, ModTime: mod}); err != nil {
			return err
		}
		if e.Size == 0 {
			return nil
		}
		n, err := io.Copy(tw, e.Reader)
		if err != nil {
			return fmt.Errorf("payload %q: %w", e.Path, err)
		}
		if n != e.Size {
			return fmt.Errorf("payload %q: short copy (%d of %d bytes)", e.Path, n, e.Size)
		}
		return nil
	}
}

func plannedFromHeader(hdr *tar.Header, want DiffEntry, tr io.Reader) (DiffEntry, error) {
	flag, ok, _ := captureType(hdr.Typeflag)
	if !ok || flag != want.Type {
		return DiffEntry{}, fmt.Errorf("%w: capture entry %q changed shape mid-plan", ErrMalformedCapture, hdr.Name)
	}
	e := DiffEntry{Path: want.Path, Type: want.Type, Mode: uint32(hdr.Mode & 0o7777), Size: hdr.Size, Link: hdr.Linkname, Modified: hdr.ModTime.UTC()}
	if hdr.Typeflag == tar.TypeLink {
		link, err := normalizeLinkTarget(hdr.Linkname)
		if err != nil {
			return DiffEntry{}, err
		}
		e.Link = link
	}
	// Only regular files carry payloads; links, dirs and specials must not
	// hold a reader (validation refuses it, and the tar writer must not be
	// advanced past a header with no data).
	if hdr.Typeflag == tar.TypeReg {
		e.Reader = io.LimitReader(tr, hdr.Size)
	}
	return e, nil
}
