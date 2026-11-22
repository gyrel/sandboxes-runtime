package ctr

import (
	"strings"
	"testing"
)

func TestCaptureArgvIncludesVirtualExcludes(t *testing.T) {
	argv, err := captureArgv([]string{"/tmp/ws"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv, " ")
	for _, want := range []string{
		"--exclude=tmp/ws", "--exclude=proc", "--exclude=sys",
		"--exclude=dev", "--exclude=run/bundles", "--exclude=var/lib/docker",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("argv missing %q: %s", want, joined)
		}
	}
	if got := argv[len(argv)-3:]; strings.Join(got, " ") != "-C / ." {
		t.Fatalf("argv tail=%v", got)
	}
	if strings.Contains(joined, "--exclude=/") {
		t.Fatalf("excludes must be relative: %s", joined)
	}
}

func TestCaptureArgvDedupesOverlappingExcludes(t *testing.T) {
	argv, err := captureArgv([]string{"/proc", "/var/lib/docker"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(strings.Join(argv, " "), "--exclude=proc"); got != 1 {
		t.Fatalf("proc excludes=%d want 1 (%v)", got, argv)
	}
	if got := strings.Count(strings.Join(argv, " "), "--exclude=var/lib/docker"); got != 1 {
		t.Fatalf("default excludes=%d want 1 (%v)", got, argv)
	}
}

func TestCaptureArgvRejectsUnsafeExclude(t *testing.T) {
	if _, err := captureArgv([]string{"relative/path"}); err == nil {
		t.Fatal("relative exclude must be refused")
	}
	if _, err := captureArgv([]string{"/.."}); err == nil {
		t.Fatal("traversal exclude must be refused")
	}
}

func TestTailBufferKeepsBoundedTail(t *testing.T) {
	var buf tailBuffer
	chunk := strings.Repeat("x", 8<<10) + "MARKER\n"
	for i := 0; i < 16; i++ {
		if _, err := buf.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}
	if len(buf.String()) > maxCaptureTailBytes {
		t.Fatalf("tail grew past bound: %d", len(buf.String()))
	}
	if !strings.HasSuffix(buf.String(), "MARKER\n") {
		t.Fatal("tail must keep the most recent bytes")
	}
}
