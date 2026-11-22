package ctr

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	runtime "github.com/rheic/sandboxes-runtime"
)

func TestPullTrackerCountsDistinctLayersAcrossFrames(t *testing.T) {
	var got []Progress
	tracker := newPullTracker(func(p Progress) { got = append(got, p) })
	tracker.observe([]byte("   ├──layer (aaa111111111)           \tdownloading\t|++++--|\t 9.2 MiB/38.9 MiB\r\n"))
	tracker.observe([]byte("   ├──layer (bbb222222222)           \twaiting    \t|------|\r\n"))
	tracker.observe([]byte("   ├──layer (aaa111111111)           \tcomplete   \t|++++++|\r\n   ├──manifest (ccc333333333)          \tcomplete"))
	tracker.finish()
	if len(got) == 0 {
		t.Fatal("tracker emitted no progress")
	}
	last := got[len(got)-1]
	if last.Phase != "pulling" || last.Total != 2 || last.Completed != 1 {
		t.Fatalf("last=%+v, want pulling 1/2 (manifest lines do not count)", last)
	}
}

func TestPullTrackerSurvivesSplitFramesAndRedraws(t *testing.T) {
	var mu sync.Mutex
	var last Progress
	tracker := newPullTracker(func(p Progress) { mu.Lock(); last = p; mu.Unlock() })
	line := " │  ├──layer (ddd44444444)          \tcomplete   \t|++++++++++|\r\n"
	for i := 0; i < len(line); i += 3 {
		end := min(i+3, len(line))
		tracker.observe([]byte(line[i:end]))
	}
	tracker.finish()
	if last.Total != 1 || last.Completed != 1 {
		t.Fatalf("split-frame tracking=%+v, want 1/1", last)
	}
}

func TestPullTrackerIgnoresMalformedLayerLines(t *testing.T) {
	var emits int
	tracker := newPullTracker(func(Progress) { emits++ })
	tracker.observe([]byte("layer (missing-close\r\nlayer ()\r\nnothing here\r\n"))
	tracker.finish()
	if emits != 0 {
		t.Fatalf("malformed frames must not emit, got %d", emits)
	}
}

// streamFake implements Runner and StreamRunner with per-command behavior:
// the images ls probe succeeds; the pull path replays pullChunks and fails
// with streamErr. A plainCombinedRunner below omits Stream entirely to cover
// the fallback.
type streamFake struct {
	pullChunks []string
	streamErr  error
	calls      [][]string
}

func (f *streamFake) CombinedOutput(_ context.Context, name string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{name}, args...))
	if !containsPull(args) {
		return nil, nil
	}
	return []byte(strings.Join(f.pullChunks, "")), f.streamErr
}

func (f *streamFake) Stream(_ context.Context, name string, args []string, onChunk func([]byte)) error {
	f.calls = append(f.calls, append([]string{name}, args...))
	for _, chunk := range f.pullChunks {
		onChunk([]byte(chunk))
	}
	return f.streamErr
}

type plainCombinedRunner struct{ calls int }

func (p *plainCombinedRunner) CombinedOutput(_ context.Context, _ string, _ ...string) ([]byte, error) {
	p.calls++
	return nil, nil
}

func containsPull(args []string) bool {
	for _, a := range args {
		if a == "pull" {
			return true
		}
	}
	return false
}

func newStreamTestClient(t *testing.T, runner Runner) *Client {
	t.Helper()
	client, err := New(Config{Socket: "/tmp/containerd.sock", CTR: "ctr"})
	if err != nil {
		t.Fatal(err)
	}
	client.runner = runner
	return client
}

func TestEnsureImageProgressStreamsLayerCounts(t *testing.T) {
	runner := &streamFake{pullChunks: []string{
		" ├──layer (a1) 	complete	|++|\r\n ├──layer (b2) 	downloading	|--|\r\n ├──layer (b2) 	complete	|++|\r\n",
	}}
	client := newStreamTestClient(t, runner)
	var updates []Progress
	if err := client.EnsureImageProgress(context.Background(), "docker.io/x/y", func(p Progress) {
		updates = append(updates, p)
	}); err != nil {
		t.Fatal(err)
	}
	if len(updates) == 0 || updates[len(updates)-1].Completed != 2 || updates[len(updates)-1].Total != 2 {
		t.Fatalf("updates=%+v, want final 2/2", updates)
	}
}

func TestEnsureImageProgressFailureStaysRedacted(t *testing.T) {
	runner := &streamFake{
		pullChunks: []string{" ├──layer (a1) 	downloading\r\nctr: failed to copy: /Users/tester/.sandboxes/x/read err"},
		streamErr:  errors.New("exit status 1"),
	}
	client := newStreamTestClient(t, runner)
	client.cfg.Socket = "/Users/tester/.sandboxes/containerd.sock"
	client.cfg.CTR = "/Users/tester/.local/bin/ctr"
	err := client.EnsureImageProgress(context.Background(), "docker.io/x/y", func(Progress) {})
	if err == nil {
		t.Fatal("expected failure")
	}
	if strings.Contains(err.Error(), "/Users/tester") {
		t.Fatalf("streaming path leaked host paths: %v", err)
	}
	if !strings.Contains(err.Error(), "pull docker.io/x/y") || !strings.Contains(err.Error(), "failed to copy") {
		t.Fatalf("streaming path lost actionable context: %v", err)
	}
}

func TestEnsureImageProgressFallsBackWithoutStream(t *testing.T) {
	runner := &plainCombinedRunner{}
	client := newStreamTestClient(t, runner)
	var seen []Progress
	if err := client.EnsureImageProgress(context.Background(), "docker.io/x/y", func(p Progress) { seen = append(seen, p) }); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 0 {
		t.Fatalf("fallback must not emit progress: %+v", seen)
	}
	if runner.calls != 2 {
		t.Fatalf("fallback must use combined output for ls+pull, calls=%d", runner.calls)
	}
}

func TestPullProgressForwarderNil(t *testing.T) {
	if pullProgressForwarder(nil) != nil {
		t.Fatal("nil cfg must disable the forwarder")
	}
	if pullProgressForwarder(&runtime.Config{Name: "x"}) != nil {
		t.Fatal("cfg without OnProgress must disable the forwarder")
	}
}
