package ctr

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestImportImageVerifiesReference(t *testing.T) {
	var seen [][]string
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		seen = append(seen, append([]string(nil), args...))
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "images import"):
			return nil, nil
		case strings.Contains(joined, "images ls"):
			return []byte("alpine:3.22\ndocker.io/library/mytpl:v1\n"), nil
		}
		return nil, nil
	}}
	c := newTestClient(t, runner)
	if err := c.ImportImage(context.Background(), "/tmp/x.tar", "docker.io/library/mytpl:v1"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(seen[0], " ")
	if !strings.HasSuffix(joined, "images import --platform "+c.cfg.Platform+" --snapshotter "+c.cfg.Snapshotter+" --base-name docker.io/library/mytpl /tmp/x.tar") {
		t.Fatalf("import argv must mirror the pull platform/snapshotter flags and carry the base name, got %v", seen[0])
	}
	if last := seen[0][len(seen[0])-1]; last != "/tmp/x.tar" {
		t.Fatalf("tar path must stay final: %v", seen[0])
	}
	runner.fn = func(args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "images ls") {
			return []byte("alpine:3.22\n"), nil
		}
		return nil, nil
	}
	err := c.ImportImage(context.Background(), "/tmp/x.tar", "docker.io/library/absent:v1")
	if err == nil || !strings.Contains(err.Error(), "did not provide") {
		t.Fatalf("missing reference must fail: %v", err)
	}
}

func TestImportImageBaseNameExcludesTag(t *testing.T) {
	for _, tc := range []struct {
		ref      string
		wantBase string
		wantErr  bool
	}{
		{ref: "docker.io/library/gyrel-tpl-x:v1", wantBase: "docker.io/library/gyrel-tpl-x"},
		{ref: "docker.io/library/gyrel-tpl-x:v1.2-rc_3", wantBase: "docker.io/library/gyrel-tpl-x"},
		{ref: "localhost:5000/team/tpl:v1", wantBase: "localhost:5000/team/tpl"},
		{ref: "docker.io/library/gyrel-tpl-x", wantErr: true},
		{ref: "localhost:5000/team/tpl", wantErr: true},
		{ref: "docker.io/library/gyrel-tpl-x:", wantErr: true},
		{ref: ":v1", wantErr: true},
		{ref: "docker.io/library/x@sha256:" + strings.Repeat("a", 64), wantErr: true},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			var calls [][]string
			runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
				calls = append(calls, append([]string(nil), args...))
				if strings.Contains(strings.Join(args, " "), "images ls") {
					return []byte(tc.ref + "\n"), nil
				}
				return nil, nil
			}}
			err := newTestClient(t, runner).ImportImage(context.Background(), "/tmp/x.tar", tc.ref)
			if tc.wantErr {
				if err == nil || len(calls) != 0 {
					t.Fatalf("ref %q must be refused before ctr runs: err=%v calls=%v", tc.ref, err, calls)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			argv := calls[0]
			idx := -1
			for i, a := range argv {
				if a == "--base-name" {
					idx = i
				}
			}
			if idx < 0 || idx+1 >= len(argv) || argv[idx+1] != tc.wantBase {
				t.Fatalf("base-name must be %q, argv %v", tc.wantBase, argv)
			}
			if strings.Contains(argv[idx+1], ":v1") || strings.Contains(argv[idx+1], "rc_3") {
				t.Fatalf("base-name carries the tag: %v", argv)
			}
			if argv[len(argv)-1] != "/tmp/x.tar" {
				t.Fatalf("tar path must stay final: %v", argv)
			}
		})
	}
}

func TestImportExportRejectIncompleteArguments(t *testing.T) {
	runner := &fakeRunner{fn: func([]string) ([]byte, error) { return nil, errors.New("must not run") }}
	c := newTestClient(t, runner)
	if err := c.ImportImage(context.Background(), "", "x"); err == nil ||
		err.Error() != "import requires an archive path and an image name" {
		t.Fatalf("import empty: %v", err)
	}
	if err := c.ExportImage(context.Background(), "x", ""); err == nil ||
		err.Error() != "export requires an archive path and an image name" {
		t.Fatalf("export empty: %v", err)
	}
}

func TestExportImageBuildsArgv(t *testing.T) {
	var got []string
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		got = append([]string(nil), args...)
		return nil, nil
	}}
	c := newTestClient(t, runner)
	if err := c.ExportImage(context.Background(), "/state/out.tar", "docker.io/library/mytpl:v1"); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "images export /state/out.tar docker.io/library/mytpl:v1") {
		t.Fatalf("export argv=%q", joined)
	}
}
