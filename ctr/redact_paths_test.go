package ctr

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRedactHostPathsMasksRootsKeepsBasename(t *testing.T) {
	roots := []string{"/Users/tester/.sandboxes", "/Users/tester"}
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "socket exact",
			in:   "--address /Users/tester/.sandboxes/containerd.sock images",
			want: "--address <host-path>/containerd.sock images",
		},
		{
			name: "deep state path",
			in:   "extract /Users/tester/.sandboxes/containerd-root/tmp/layer.bin failed",
			want: "extract <host-path>/layer.bin failed",
		},
		{
			name: "home workspace",
			in:   "src=/Users/tester/projects/repo,dst=/home/agent/workspace",
			want: "src=<host-path>/repo,dst=/home/agent/workspace",
		},
		{
			name: "no host paths untouched",
			in:   "ctr: failed to copy: read tcp 10.0.0.1:443: connection reset",
			want: "ctr: failed to copy: read tcp 10.0.0.1:443: connection reset",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := redactHostPaths(test.in, roots); got != test.want {
				t.Fatalf("redactHostPaths() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRedactHostPathsTerminatesWhenTokenEqualsRoot(t *testing.T) {
	// Regression: a replacement that itself contains the root ("/tmp" ->
	// "<host-path>/tmp") must not be rescanned, or the loop never ends.
	got := redactHostPaths("read tcp 10.0.0.1:65427->1.2.3.4:443 /tmp /tmp/mid/end.sock", []string{"/tmp"})
	want := "read tcp 10.0.0.1:65427->1.2.3.4:443 <host-path>/tmp <host-path>/end.sock"
	if got != want {
		t.Fatalf("redactHostPaths() = %q, want %q", got, want)
	}
}

func TestOutputTailKeepsLastMeaningfulLines(t *testing.T) {
	out := "line 1 progress\n\nline 2 progress\nlayer downloading\nctr: failed to copy: connection reset\n"
	got := outputTail(out)
	if !strings.Contains(got, "ctr: failed to copy: connection reset") {
		t.Fatalf("tail must keep the actionable last line: %q", got)
	}
	if strings.Contains(got, "line 1") {
		t.Fatalf("tail must drop early progress lines: %q", got)
	}
	if strings.Contains(outputTail("  \n \n"), "\n") {
		t.Fatal("empty output must stay empty")
	}
}

func TestRunErrorRedactsHostPathsAndKeepsCause(t *testing.T) {
	progress := strings.Repeat("downloading layer ...\n", 200) +
		"ctr: failed extract: /Users/tester/.sandboxes/containerd-root/work/extract.bin: no space left on device"
	exit := errors.New("exit status 1")
	runner := &fakeRunner{fn: func([]string) ([]byte, error) { return []byte(progress), exit }}
	client := newTestClient(t, runner)
	client.cfg.Socket = "/Users/tester/.sandboxes/containerd.sock"
	client.cfg.CTR = "/Users/tester/.local/bin/ctr"

	_, err := client.run(context.Background(), "images", "pull", "docker.io/library/alpine:3.22")
	if err == nil {
		t.Fatal("run() must report the failure")
	}
	message := err.Error()
	if strings.Contains(message, "/Users/tester") {
		t.Fatalf("error leaked host path: %q", message)
	}
	// The 200-line progress log must collapse to the bounded tail, not be
	// embedded verbatim.
	if progress := strings.Count(message, "downloading layer"); progress > 3 {
		t.Fatalf("error must keep only a bounded output tail (%d progress lines): %q", progress, message)
	}
	for _, want := range []string{
		"images pull docker.io/library/alpine:3.22",
		"<host-path>/containerd.sock",
		"<host-path>/extract.bin",
		"no space left on device",
		"exit status 1",
	} {
		if !strings.Contains(message, want) {
			t.Fatalf("error must keep actionable context %q: %q", want, message)
		}
	}
	if !errors.Is(err, exit) {
		t.Fatalf("cause chain must survive redaction: %v", err)
	}
	var target *redactedError
	if !errors.As(err, &target) {
		t.Fatal("run() must return *redactedError")
	}
}

func TestRunErrorRedactsBinaryPathInExecFailure(t *testing.T) {
	runner := &fakeRunner{fn: func([]string) ([]byte, error) {
		return nil, errors.New("fork/exec /Users/tester/.local/bin/ctr: permission denied")
	}}
	client := newTestClient(t, runner)
	client.cfg.CTR = "/Users/tester/.local/bin/ctr"
	client.cfg.Socket = "/Users/tester/.sandboxes/containerd.sock"

	_, err := client.run(context.Background(), "version")
	if err == nil {
		t.Fatal("run() must report the failure")
	}
	if strings.Contains(err.Error(), "/Users/tester") {
		t.Fatalf("exec error must not expose the host binary path: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "<host-path>/ctr: permission denied") {
		t.Fatalf("error must keep the failure reason: %q", err.Error())
	}
}
