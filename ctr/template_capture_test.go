package ctr

import (
	"slices"
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
		"--exclude=tmp/ws", "--exclude=./proc", "--exclude=./sys",
		"--exclude=./dev", "--exclude=./run", "--exclude=var/lib/docker",
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

// TestCaptureArgvAnchorsVirtualMountsOnly pins the exact argv. Bare
// component patterns (proc, sys, dev, run, run/bundles) matched at any depth
// and dropped nested directories with the same names: a guest probe showed
// `--exclude=sys` removing ./usr/include/aarch64-linux-gnu/sys/ from the
// capture, which produced the phantom whiteout directory in the diff layer
// (difflayer.bin of roundtrip v9). Root-anchored ./ patterns exclude only the
// root mount points; nested sys/dev/proc/run stay in the capture.
func TestCaptureArgvAnchorsVirtualMountsOnly(t *testing.T) {
	argv, err := captureArgv(nil)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"tar", "-cf", "-",
		"--exclude=./proc", "--exclude=./sys", "--exclude=./dev", "--exclude=./run",
		"--exclude=var/lib/docker",
		"-C", "/", ".",
	}
	if !slices.Equal(argv, want) {
		t.Fatalf("argv=%v\nwant=%v", argv, want)
	}
	for _, bare := range []string{"proc", "sys", "dev", "run", "run/bundles"} {
		if slices.Contains(argv, "--exclude="+bare) {
			t.Fatalf("bare virtual pattern %q would match nested directories: %v", bare, argv)
		}
	}
}

func TestCaptureArgvDedupesOverlappingExcludes(t *testing.T) {
	argv, err := captureArgv([]string{"/var/lib/docker", "/proc"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(strings.Join(argv, " "), "--exclude=var/lib/docker"); got != 1 {
		t.Fatalf("default excludes=%d want 1 (%v)", got, argv)
	}
	if got := strings.Count(strings.Join(argv, " "), "--exclude=./proc"); got != 1 {
		t.Fatalf("virtual proc excludes=%d want 1 (%v)", got, argv)
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
