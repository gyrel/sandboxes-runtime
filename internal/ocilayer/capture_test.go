package ocilayer

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func buildCaptureTar(t *testing.T, files []DiffEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	if _, err := LayerTar(&buf, files); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestIndexCaptureSortsAndDigests(t *testing.T) {
	raw := buildCaptureTar(t, []DiffEntry{
		{Path: "zeta", Type: "reg", Size: 2, Reader: strings.NewReader("z1"), Mode: 0o600},
		{Path: "alpha", Type: "reg", Size: 3, Reader: strings.NewReader("a12"), Mode: 0o644},
		{Path: "etc", Type: "dir"},
		{Path: "bin/sh", Type: "symlink", Link: "../usr/bin/sh"},
	})
	br := bytes.NewReader(raw)
	metas, err := IndexCapture(br, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 4 || metas[0].Path != "alpha" || metas[1].Path != "bin/sh" || metas[2].Path != "etc" || metas[3].Path != "zeta" {
		t.Fatalf("metas=%+v", metas)
	}
	if metas[0].Digest == "" || !metas[0].Digest.Valid() {
		t.Fatalf("regular entry must be hashed: %+v", metas[0])
	}
	if metas[1].Link != "../usr/bin/sh" {
		t.Fatalf("symlink target lost: %+v", metas[1])
	}
}

func TestIndexCaptureRejectsHostileStreams(t *testing.T) {
	cases := [][]byte{
		[]byte("not a tar at all"),
		func() []byte {
			var b bytes.Buffer
			tw := tar.NewWriter(&b)
			_ = tw.WriteHeader(&tar.Header{Name: "../escape", Typeflag: tar.TypeReg, Size: 0})
			_ = tw.Close()
			return b.Bytes()
		}(),
		func() []byte {
			var b bytes.Buffer
			tw := tar.NewWriter(&b)
			_ = tw.WriteHeader(&tar.Header{Name: "fifo", Typeflag: tar.TypeFifo})
			_ = tw.Close()
			return b.Bytes()
		}(),
	}
	for i, raw := range cases {
		br := bytes.NewReader(raw)
		if _, err := IndexCapture(br, int64(len(raw))); err == nil {
			t.Fatalf("case %d accepted hostile capture", i)
		}
	}
}

func TestDiffVirtualDirsSuppressPlannedEntries(t *testing.T) {
	captured := []FileMeta{
		{Path: "etc/hosts", Type: "reg", Mode: 0o644, Digest: Digest("sha256:" + strings.Repeat("a", 64))},
		// Defensive: a capture that still contains virtual paths (older
		// guests, unexpected mounts) must not emit them as additions.
		{Path: "proc/self/exe", Type: "lnk", Link: "../busybox"},
	}
	base := map[string]BaseFile{
		"etc/hosts":   {Path: "etc/hosts", Type: "reg", Mode: 0o644, Digest: Digest("sha256:" + strings.Repeat("a", 64))},
		"proc/kmsg":   {Path: "proc/kmsg", Type: "reg", Mode: 0o600, Digest: Digest("sha256:" + strings.Repeat("b", 64))},
		"dev/console": {Path: "dev/console", Type: "chr", Mode: 0o620},
	}
	plans, err := Diff(captured, base, nil, []string{"proc", "dev"})
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 0 {
		t.Fatalf("virtual paths must plan no entries: %+v", plans)
	}
	// Without virtualDirs the old semantics stay (regression guard).
	if plans, err = Diff(captured, base, nil, nil); err != nil {
		t.Fatal(err)
	} else if len(plans) == 0 {
		t.Fatal("expected whiteouts/additions when no virtualDirs are supplied")
	}
}

func TestDiffPlanSemantics(t *testing.T) {
	added := DiffEntry{Path: "new", Type: "reg", Size: 1, Reader: strings.NewReader("n")}
	kept := DiffEntry{Path: "keep", Type: "reg", Size: 3, Reader: strings.NewReader("abc"), Mode: 0o644}
	capturedRaw := buildCaptureTar(t, []DiffEntry{added, kept})
	captured, err := IndexCapture(bytes.NewReader(capturedRaw), int64(len(capturedRaw)))
	if err != nil {
		t.Fatal(err)
	}
	var keptMeta FileMeta
	for _, m := range captured {
		if m.Path == "keep" {
			keptMeta = m
		}
	}
	base := map[string]BaseFile{
		"keep":     {Path: "keep", Type: "reg", Mode: 0o644, Digest: keptMeta.Digest},
		"gone":     {Path: "gone", Type: "reg", Mode: 0o644, Digest: Digest("sha256:" + strings.Repeat("f", 64))},
		"secret/x": {Path: "secret/x", Type: "reg", Mode: 0o600, Digest: Digest("sha256:" + strings.Repeat("e", 64))},
	}
	plans, err := Diff(captured, base, []string{"secret"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, pl := range plans {
		switch pl.Emit.Type {
		case "whiteout":
			kinds = append(kinds, "whiteout:"+pl.Emit.Path)
		case "opaque":
			kinds = append(kinds, "opaque:"+pl.Emit.Path)
		default:
			kinds = append(kinds, pl.Emit.Type+":"+pl.Emit.Path)
		}
	}
	got := strings.Join(kinds, ",")
	want := "reg:new,whiteout:gone,opaque:secret"
	if got != want {
		t.Fatalf("plan=%q want %q", got, want)
	}
	// Modified base entry must re-appear (digest mismatch).
	base2 := map[string]BaseFile{"keep": {Path: "keep", Type: "reg", Mode: 0o644, Digest: Digest("sha256:" + strings.Repeat("0", 64))}}
	plans, err = Diff(captured, base2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, pl := range plans {
		if pl.Emit.Path == "keep" && pl.Emit.Type == "reg" {
			found = true
		}
	}
	if !found {
		t.Fatalf("modified entry must be re-added: %+v", plans)
	}
}

func TestFindCapturePayload(t *testing.T) {
	e1 := DiffEntry{Path: "a", Type: "reg", Size: 3, Reader: strings.NewReader("aaa")}
	e2 := DiffEntry{Path: "b", Type: "reg", Size: 5, Reader: strings.NewReader("bbbbb")}
	raw := buildCaptureTar(t, []DiffEntry{e1, e2})
	br := bytes.NewReader(raw)
	metas, err := IndexCapture(br, int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range metas {
		if m.Path != "b" {
			continue
		}
		r, err := FindCapturePayload(br, int64(len(raw)), m)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r)
		if err != nil || string(data) != "bbbbb" {
			t.Fatalf("payload=%q err=%v", data, err)
		}
		return
	}
	t.Fatal("entry b missing")
}

func TestDiffRejectsBadOpaqueDirectory(t *testing.T) {
	if _, err := Diff(nil, map[string]BaseFile{"x": {Path: "x", Type: "reg"}}, []string{"../escape"}, nil); err == nil {
		t.Fatal("escaping opaque dir accepted")
	}
}

func TestDiffSkipsUnchangedNonRegularEntries(t *testing.T) {
	captured := []FileMeta{
		{Path: "bin", Type: "symlink", Link: "usr/bin", Mode: 0o777},
		{Path: "etc", Type: "dir", Mode: 0o755},
		{Path: "home/agent/link", Type: "symlink", Link: "../escape-changed"},
		{Path: "usr/bin/sh", Type: "hardlink", Link: "busybox", Mode: 0o755},
	}
	base := map[string]BaseFile{
		"bin":             {Path: "bin", Type: "symlink", Mode: 0o777, Link: "usr/bin"},
		"etc":             {Path: "etc", Type: "dir", Mode: 0o755},
		"home/agent/link": {Path: "home/agent/link", Type: "symlink", Mode: 0o777, Link: "old-target"},
		"usr/bin/sh":      {Path: "usr/bin/sh", Type: "hardlink", Mode: 0o755, Link: "busybox"},
	}
	plans, err := Diff(captured, base, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 1 || plans[0].Emit.Path != "home/agent/link" {
		t.Fatalf("unchanged links/dirs must be skipped, got %+v", plans)
	}
}

func TestLayerTarFromCaptureEmitsSymlinkWithoutPayload(t *testing.T) {
	capture := buildCaptureTar(t, []DiffEntry{
		{Path: "bin", Type: "symlink", Link: "usr/bin"},
		{Path: "home/agent/marker", Type: "reg", Size: 2, Reader: strings.NewReader("ok"), Mode: 0o644},
	})
	captureReader := bytes.NewReader(capture)
	metas, err := IndexCapture(captureReader, int64(len(capture)))
	if err != nil {
		t.Fatal(err)
	}
	plan := make([]PlannedEntry, 0, len(metas))
	for i, m := range metas {
		plan = append(plan, PlannedEntry{
			Emit:         DiffEntry{Path: m.Path, Type: m.Type, Mode: m.Mode, Size: m.Size, Link: m.Link, Modified: m.Modified},
			CaptureIndex: i,
		})
	}
	var layer bytes.Buffer
	if _, err := LayerTarFromCapture(&layer, plan, bytes.NewReader(capture)); err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(bytes.NewReader(layer.Bytes()))
	seen := map[string]byte{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		seen[hdr.Name] = hdr.Typeflag
	}
	if seen["bin"] != tar.TypeSymlink {
		t.Fatalf("symlink lost from layer: %+v", seen)
	}
	if seen["home/agent/marker"] != tar.TypeReg {
		t.Fatalf("regular lost from layer: %+v", seen)
	}
}
