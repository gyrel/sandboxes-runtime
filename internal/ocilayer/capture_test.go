package ocilayer

import (
	"archive/tar"
	"bytes"
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
	plans, err := Diff(captured, base, []string{"secret"})
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
	plans, err = Diff(captured, base2, nil)
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
	if _, err := Diff(nil, map[string]BaseFile{"x": {Path: "x", Type: "reg"}}, []string{"../escape"}); err == nil {
		t.Fatal("escaping opaque dir accepted")
	}
}
