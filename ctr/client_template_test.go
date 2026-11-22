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
	if !strings.Contains(strings.Join(seen[0], " "), "images import /tmp/x.tar") {
		t.Fatalf("import argv=%v", seen[0])
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
