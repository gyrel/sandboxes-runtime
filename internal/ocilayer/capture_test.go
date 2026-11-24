package ocilayer

import (
	"archive/tar"
	"bytes"
	"errors"
	"io"
	"slices"
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

func TestIndexCaptureNormalizesHardlinkTarget(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	body := "perl\n"
	if err := tw.WriteHeader(&tar.Header{Name: "./usr/bin/perl", Typeflag: tar.TypeReg, Mode: 0o755, Size: int64(len(body)), Format: tar.FormatGNU}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "./usr/bin/perl5.40.1", Typeflag: tar.TypeLink, Linkname: "./usr/bin/perl", Mode: 0o755, Format: tar.FormatGNU}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := b.Bytes()
	metas, err := IndexCapture(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 2 {
		t.Fatalf("metas=%d", len(metas))
	}
	if metas[1].Path != "usr/bin/perl5.40.1" || metas[1].Type != "hardlink" || metas[1].Link != "usr/bin/perl" {
		t.Fatalf("hardlink not normalized: %+v", metas[1])
	}
}

func TestDiffIncludesUnchangedHardlinkTarget(t *testing.T) {
	captured := []FileMeta{
		{Path: "usr/bin/perl", Type: "reg", Mode: 0o755, Size: 5, Digest: Digest("sha256:" + strings.Repeat("a", 64))},
		{Path: "usr/bin/perl5.40.1", Type: "hardlink", Mode: 0o755, Link: "usr/bin/perl"},
	}
	base := map[string]BaseFile{
		"usr/bin/perl": {Path: "usr/bin/perl", Type: "reg", Mode: 0o755, Digest: Digest("sha256:" + strings.Repeat("a", 64))},
	}
	plans, err := Diff(captured, base, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 2 {
		t.Fatalf("hardlink target must be dragged into the layer: %+v", plans)
	}
	seen := map[string]bool{}
	for _, pl := range plans {
		seen[pl.Emit.Path] = true
	}
	if !seen["usr/bin/perl"] || !seen["usr/bin/perl5.40.1"] {
		t.Fatalf("plan=%+v", plans)
	}
}

func TestDiffRejectsDanglingHardlinkTargets(t *testing.T) {
	captured := []FileMeta{
		{Path: "bin/x", Type: "hardlink", Mode: 0o755, Link: "nowhere/x"},
	}
	if _, err := Diff(captured, map[string]BaseFile{}, nil, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing target accepted: %v", err)
	}
	virtual := []FileMeta{
		{Path: "bin/x", Type: "hardlink", Mode: 0o755, Link: "proc/self/foo"},
	}
	if _, err := Diff(virtual, map[string]BaseFile{}, nil, []string{"proc"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("virtual-prefix target accepted: %v", err)
	}
	opaque := []FileMeta{
		{Path: "bin/x", Type: "hardlink", Mode: 0o755, Link: "work/secret"},
		{Path: "work/secret", Type: "reg", Mode: 0o600, Digest: Digest("sha256:" + strings.Repeat("b", 64))},
	}
	if _, err := Diff(opaque, map[string]BaseFile{}, []string{"work"}, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("opaque-dir target accepted: %v", err)
	}
}

func TestNormalizeLinkTarget(t *testing.T) {
	for in, want := range map[string]string{
		"./usr/bin/perl": "usr/bin/perl",
		"usr/bin/perl":   "usr/bin/perl",
		"/usr/bin/perl":  "usr/bin/perl",
	} {
		got, err := normalizeLinkTarget(in)
		if err != nil || got != want {
			t.Fatalf("normalize(%q)=%q,%v want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "../escape", "./", "a/./b", "a//b", "a/"} {
		if _, err := normalizeLinkTarget(bad); err == nil {
			t.Fatalf("normalize(%q) accepted", bad)
		}
	}
}

func TestIndexCaptureSkipsArchiveRootMarker(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	if err := tw.WriteHeader(&tar.Header{Name: "./", Typeflag: tar.TypeDir, Mode: 0o755, Format: tar.FormatGNU}); err != nil {
		t.Fatal(err)
	}
	body := "x"
	if err := tw.WriteHeader(&tar.Header{Name: "./etc/hosts", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)), Format: tar.FormatGNU}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	raw := b.Bytes()
	metas, err := IndexCapture(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	if len(metas) != 1 || metas[0].Path != "etc/hosts" {
		t.Fatalf("root marker indexed: %+v", metas)
	}
	plans, err := Diff(metas, map[string]BaseFile{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var layer bytes.Buffer
	if _, err := LayerTarFromCapture(&layer, plans, bytes.NewReader(raw)); err != nil {
		t.Fatalf("root marker leaked into plan: %v", err)
	}
}

func planKinds(plans []PlannedEntry) []string {
	out := make([]string, 0, len(plans))
	for _, pl := range plans {
		out = append(out, pl.Emit.Type+":"+pl.Emit.Path)
	}
	return out
}

func baseFromMetas(metas []FileMeta) map[string]BaseFile {
	base := make(map[string]BaseFile, len(metas))
	for _, m := range metas {
		base[m.Path] = BaseFile{Path: m.Path, Type: m.Type, Mode: m.Mode, Digest: m.Digest, Link: m.Link}
	}
	return base
}

func TestRemovalsFoldMissingAncestors(t *testing.T) {
	dig := Digest("sha256:" + strings.Repeat("c", 64))
	dir := func(p string) BaseFile { return BaseFile{Path: p, Type: "dir", Mode: 0o755} }
	reg := func(p string) BaseFile { return BaseFile{Path: p, Type: "reg", Mode: 0o755, Digest: dig} }
	cases := []struct {
		name     string
		captured []FileMeta
		base     map[string]BaseFile
		virtual  []string
		want     []string
	}{
		{
			name:     "missing directory folds its subtree into one whiteout",
			captured: []FileMeta{{Path: "opt", Type: "dir", Mode: 0o755}},
			base: map[string]BaseFile{
				"opt":              dir("opt"),
				"opt/tool":         dir("opt/tool"),
				"opt/tool/bin":     dir("opt/tool/bin"),
				"opt/tool/bin/x":   reg("opt/tool/bin/x"),
				"opt/tool/share":   dir("opt/tool/share"),
				"opt/tool/share/y": reg("opt/tool/share/y"),
			},
			want: []string{"whiteout:opt/tool"},
		},
		{
			name:     "tmpfs run keeps present directory and folds its missing subtree",
			captured: []FileMeta{{Path: "run", Type: "dir", Mode: 0o755}},
			base: map[string]BaseFile{
				"run":                   dir("run"),
				"run/adduser":           reg("run/adduser"),
				"run/lock":              reg("run/lock"),
				"run/systemd":           dir("run/systemd"),
				"run/systemd/container": reg("run/systemd/container"),
			},
			want: []string{"whiteout:run/adduser", "whiteout:run/lock", "whiteout:run/systemd"},
		},
		{
			name:     "run is virtual and plans nothing",
			captured: []FileMeta{{Path: "run", Type: "dir", Mode: 0o755}},
			base: map[string]BaseFile{
				"run":         dir("run"),
				"run/adduser": reg("run/adduser"),
				"run/systemd": dir("run/systemd"),
			},
			virtual: []string{"run"},
			want:    nil,
		},
		{
			name:     "directory replaced by symlink suppresses base descendants",
			captured: []FileMeta{{Path: "a", Type: "symlink", Link: "x"}},
			base: map[string]BaseFile{
				"a":       dir("a"),
				"a/b":     dir("a/b"),
				"a/b/c":   dir("a/b/c"),
				"a/b/c/d": reg("a/b/c/d"),
			},
			want: []string{"symlink:a"},
		},
		{
			name: "capture entries beneath a symlink are unreachable and dropped",
			captured: []FileMeta{
				{Path: "a", Type: "symlink", Link: "x"},
				{Path: "a/x", Type: "reg", Mode: 0o644, Digest: dig},
			},
			base: map[string]BaseFile{},
			want: []string{"symlink:a"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			plans, err := Diff(tc.captured, tc.base, nil, tc.virtual)
			if err != nil {
				t.Fatal(err)
			}
			got := planKinds(plans)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("plan=%v want %v", got, tc.want)
			}
		})
	}
}

func TestNestedSystemDirectoryNamesAreNotVirtual(t *testing.T) {
	tree := []DiffEntry{
		{Path: "usr", Type: "dir"},
		{Path: "usr/include", Type: "dir"},
		{Path: "usr/include/aarch64-linux-gnu", Type: "dir"},
		{Path: "usr/include/aarch64-linux-gnu/x.h", Type: "reg", Size: 1, Reader: strings.NewReader("x"), Mode: 0o644},
		{Path: "usr/include/aarch64-linux-gnu/sys", Type: "dir"},
		{Path: "usr/include/aarch64-linux-gnu/sys/acct.h", Type: "reg", Size: 2, Reader: strings.NewReader("ac"), Mode: 0o644},
		{Path: "usr/include/aarch64-linux-gnu/sys/auxv.h", Type: "reg", Size: 2, Reader: strings.NewReader("av"), Mode: 0o644},
	}
	raw := buildCaptureTar(t, tree)
	captured, err := IndexCapture(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		t.Fatal(err)
	}
	base := baseFromMetas(captured)
	base["sys"] = BaseFile{Path: "sys", Type: "dir", Mode: 0o755}
	base["sys/exe"] = BaseFile{Path: "sys/exe", Type: "reg", Mode: 0o755, Digest: Digest("sha256:" + strings.Repeat("d", 64))}
	virtual := []string{"proc", "sys", "dev", "run"}

	plans, err := Diff(captured, base, nil, virtual)
	if err != nil {
		t.Fatal(err)
	}
	if len(plans) != 0 {
		t.Fatalf("nested sys captured and unchanged must plan nothing: %v", planKinds(plans))
	}

	// The old unanchored capture dropped the nested directory. The fold must
	// keep that to one whiteout at the nested directory, never the per-file
	// whiteouts inside a whiteout directory that erofs rejects.
	var withoutNested []FileMeta
	for _, m := range captured {
		if !strings.HasPrefix(m.Path, "usr/include/aarch64-linux-gnu/sys") {
			withoutNested = append(withoutNested, m)
		}
	}
	plans, err = Diff(withoutNested, base, nil, virtual)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"whiteout:usr/include/aarch64-linux-gnu/sys"}
	if got := planKinds(plans); !slices.Equal(got, want) {
		t.Fatalf("plan=%v want %v", got, want)
	}
}

func TestDiffRejectsHardlinkTargetBeneathSymlink(t *testing.T) {
	captured := []FileMeta{
		{Path: "bin/x", Type: "hardlink", Mode: 0o755, Link: "a/x"},
		{Path: "a", Type: "symlink", Link: "usr/lib"},
		{Path: "a/x", Type: "reg", Mode: 0o755, Digest: Digest("sha256:" + strings.Repeat("e", 64))},
	}
	if _, err := Diff(captured, map[string]BaseFile{}, nil, nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("hardlink target beneath symlink accepted: %v", err)
	}
}
