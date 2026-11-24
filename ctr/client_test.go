package ctr

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	runtime "github.com/rheic/sandboxes-runtime"
	"github.com/rheic/sandboxes-runtime/internal/journal"
)

type fakeRunner struct {
	calls [][]string
	fn    func(args []string) ([]byte, error)
}

func TestStartTaskHandlesExistingTask(t *testing.T) {
	for _, tc := range []struct {
		name       string
		status     string
		wantDelete bool
		wantStart  bool
		wantErr    bool
	}{
		{name: "absent", wantStart: true},
		{name: "running", status: "RUNNING"},
		{name: "stopped", status: "STOPPED", wantDelete: true, wantStart: true},
		{name: "paused", status: "PAUSED", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
				if strings.Contains(strings.Join(args, " "), "tasks ls") {
					result := "TASK PID STATUS\n"
					if tc.status != "" {
						result += "rheic-dev 12 " + tc.status + "\n"
					}
					return []byte(result), nil
				}
				return nil, nil
			}}
			err := newTestClient(t, runner).StartTask(context.Background(), "rheic-dev", "/tmp/fifo")
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected error: %v", err)
			}
			calls := fmt.Sprint(runner.calls)
			if strings.Contains(calls, "tasks delete -f rheic-dev") != tc.wantDelete ||
				strings.Contains(calls, "tasks start -d --fifo-dir /tmp/fifo rheic-dev") != tc.wantStart {
				t.Fatalf("unexpected calls: %s", calls)
			}
		})
	}
}

func TestStartTaskStopsOnInspectionOrDeleteFailure(t *testing.T) {
	for _, failDelete := range []bool{false, true} {
		runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
			if failDelete && strings.Contains(strings.Join(args, " "), "tasks ls") {
				return []byte("TASK PID STATUS\nrheic-dev 12 STOPPED\n"), nil
			}
			return nil, errors.New("containerd unavailable")
		}}
		if err := newTestClient(t, runner).StartTask(context.Background(), "rheic-dev", ""); err == nil {
			t.Fatal("failure was ignored")
		}
		if strings.Contains(fmt.Sprint(runner.calls), "tasks start") {
			t.Fatal("started after failure")
		}
	}
}

func TestStopTaskReportsContainerdFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		fn   func([]string) ([]byte, error)
	}{
		{"list", func([]string) ([]byte, error) { return nil, errors.New("containerd unavailable") }},
		{"signal", func(args []string) ([]byte, error) {
			if strings.Contains(strings.Join(args, " "), "tasks ls") {
				return []byte("TASK PID STATUS\nrheic-dev 12 RUNNING\n"), nil
			}
			return nil, errors.New("signal failed")
		}},
		{"delete", func(args []string) ([]byte, error) {
			if strings.Contains(strings.Join(args, " "), "tasks ls") {
				return []byte("TASK PID STATUS\nrheic-dev 12 STOPPED\n"), nil
			}
			return nil, errors.New("delete failed")
		}},
		{"unknown state", func([]string) ([]byte, error) {
			return []byte("TASK PID STATUS\nrheic-dev 12 PAUSED\n"), nil
		}},
		{"malformed", func([]string) ([]byte, error) {
			return []byte("TASK PID STATUS\nrheic-dev\n"), nil
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newTestClient(t, &fakeRunner{fn: test.fn})
			if err := client.StopTask(context.Background(), "rheic-dev", time.Second); err == nil {
				t.Fatal("failure was reported as successful stop")
			}
		})
	}
}

func TestStopTaskSignalsAndDeletesStoppedTask(t *testing.T) {
	lists := 0
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "tasks ls") {
			lists++
			if lists == 1 {
				return []byte("TASK PID STATUS\nrheic-dev 12 RUNNING\n"), nil
			}
			return []byte("TASK PID STATUS\nrheic-dev 12 STOPPED\n"), nil
		}
		return nil, nil
	}}
	client := newTestClient(t, runner)
	if err := client.StopTask(context.Background(), "rheic-dev", time.Second); err != nil {
		t.Fatal(err)
	}
	calls := make([]string, 0, len(runner.calls))
	for _, call := range runner.calls {
		calls = append(calls, strings.Join(call, " "))
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "tasks kill -s SIGTERM rheic-dev") || !strings.Contains(joined, "tasks delete -f rheic-dev") || strings.Contains(joined, "SIGKILL") {
		t.Fatalf("unexpected stop commands: %s", joined)
	}
}

func TestCreateDoesNotProceedWhenContainerListFails(t *testing.T) {
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "images ls") {
			return []byte("alpine:3.22\n"), nil
		}
		return nil, errors.New("containerd unavailable")
	}}
	client := newTestClient(t, runner)
	backend := &Backend{stateDir: t.TempDir(), client: client, image: "alpine:3.22", verifier: testArtifactVerifier(t)}
	if _, err := backend.Create(context.Background(), runtime.Config{Name: "dev"}); err == nil {
		t.Fatal("container list failure was ignored")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("runtime continued after failed list: %d calls", len(runner.calls))
	}
}

func TestBackendDeleteAfterTaskHasStopped(t *testing.T) {
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		switch {
		case strings.Contains(strings.Join(args, " "), "tasks ls"):
			return []byte("TASK PID STATUS\n"), nil
		case strings.Contains(strings.Join(args, " "), "containers ls"):
			return []byte("rheic-dev\n"), nil
		case strings.Contains(strings.Join(args, " "), "containers info"):
			return []byte("{}"), nil
		case strings.Contains(strings.Join(args, " "), "containers delete"):
			return nil, nil
		default:
			return nil, errors.New("unexpected command")
		}
	}}
	backend := &Backend{client: newTestClient(t, runner)}
	if err := backend.Delete(context.Background(), runtime.Handle{ID: "rheic-dev"}); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 4 {
		t.Fatalf("unexpected delete sequence: %v", runner.calls)
	}
}

func TestBackendDeleteFailsWhenTaskListUnavailable(t *testing.T) {
	runner := &fakeRunner{fn: func([]string) ([]byte, error) {
		return nil, errors.New("containerd unavailable")
	}}
	backend := &Backend{client: newTestClient(t, runner)}
	if err := backend.Delete(context.Background(), runtime.Handle{ID: "rheic-dev"}); err == nil {
		t.Fatal("task inspection failure ignored")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("delete proceeded after inspection failure: %v", runner.calls)
	}
}

func (f *fakeRunner) CombinedOutput(_ context.Context, name string, args ...string) ([]byte, error) {
	call := append([]string{name}, args...)
	f.calls = append(f.calls, call)
	if f.fn == nil {
		return nil, nil
	}
	return f.fn(call)
}

func newTestClient(t *testing.T, runner Runner) *Client {
	t.Helper()
	client, err := New(Config{Socket: "/tmp/containerd.sock", CTR: "ctr"})
	if err != nil {
		t.Fatal(err)
	}
	client.runner = runner
	return client
}

func TestRunBuildsCommand(t *testing.T) {
	runner := &fakeRunner{}
	client := newTestClient(t, runner)
	err := client.Run(context.Background(), RunSpec{
		ContainerID: "rheic-dev",
		Name:        "dev",
		Image:       "alpine:3.22",
		CPUs:        2,
		MemoryMiB:   512,
		FIFODir:     "/tmp/fifo",
		Mounts:      []Mount{{Source: "/work", Destination: "/work"}},
		Env:         []string{"PARITY=1"},
		Privileged:  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %d", len(runner.calls))
	}
	args := strings.Join(runner.calls[0], " ")
	for _, want := range []string{
		"ctr --address /tmp/containerd.sock --namespace rheic run --detach",
		"--runtime io.containerd.nerdbox.v1",
		"--snapshotter erofs",
		"--fifo-dir /tmp/fifo",
		"type=bind,src=/work,dst=/work,options=rbind:rw",
		"--env PARITY=1",
		"--cap-add CAP_SYS_ADMIN",
		"--cap-add CAP_NET_ADMIN",
		"--cap-add CAP_NET_RAW",
		"alpine:3.22 rheic-dev /bin/sh -c",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("missing %q in %q", want, args)
		}
	}
}

func TestMountSpecRendering(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mount Mount
		want  string
	}{
		{
			name:  "writable",
			mount: Mount{Source: "/host", Destination: "/guest"},
			want:  "type=bind,src=/host,dst=/guest,options=rbind:rw",
		},
		{
			name:  "read only",
			mount: Mount{Source: "/host", Destination: "/guest", ReadOnly: true},
			want:  "type=bind,src=/host,dst=/guest,options=rbind:ro",
		},
		{
			name:  "recursive read only",
			mount: Mount{Source: "/host", Destination: "/guest", ReadOnly: true, RecursiveReadOnly: true},
			want:  "type=bind,src=/host,dst=/guest,options=rbind:ro:rro",
		},
		{
			name:  "non bind",
			mount: Mount{Type: "ext4", Source: "/vol.img", Destination: "/data"},
			want:  "type=ext4,src=/vol.img,dst=/data",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mountSpec(tc.mount); got != tc.want {
				t.Fatalf("mountSpec() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEnsureImage(t *testing.T) {
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "images ls") {
			return []byte("alpine:3.22\n"), nil
		}
		return nil, nil
	}}
	client := newTestClient(t, runner)
	if err := client.EnsureImage(context.Background(), "alpine:3.22"); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("unexpected pull: %d calls", len(runner.calls))
	}

	runner.calls = nil
	runner.fn = func(args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "images ls") {
			return nil, nil
		}
		if strings.Contains(strings.Join(args, " "), "images pull") {
			return nil, nil
		}
		return nil, errors.New("unexpected")
	}
	if err := client.EnsureImage(context.Background(), "alpine:3.22"); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 2 {
		t.Fatalf("calls = %d", len(runner.calls))
	}
}

func TestBackendCreate(t *testing.T) {
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "images ls") || strings.Contains(joined, "containers ls") {
			return nil, nil
		}
		return nil, nil
	}}
	client := newTestClient(t, runner)
	backend := &Backend{stateDir: t.TempDir(), client: client, image: "alpine:3.22", fifoDir: "/tmp/fifo", verifier: testArtifactVerifier(t)}
	handle, err := backend.Create(context.Background(), runtime.Config{
		Name:      "dev",
		Workspace: "/work",
		CPUs:      2,
		MemoryMiB: 512,
		Env:       []string{"PARITY=1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(runner.calls[len(runner.calls)-1], " "), "--env PARITY=1") {
		t.Fatalf("env missing in %v", runner.calls)
	}
	if handle.ID != "rheic-dev" || handle.FIFODir != "/tmp/fifo" {
		t.Fatalf("unexpected handle: %+v", handle)
	}
}

func TestWorkspaceMountsGuestDestination(t *testing.T) {
	tests := []struct {
		name                  string
		workspace             runtime.Workspace
		wantDest              string
		wantReadOnly          bool
		wantRecursiveReadOnly bool
	}{
		{
			name:      "default keeps host path",
			workspace: runtime.Workspace{Path: "/workspace"},
			wantDest:  "/workspace",
		},
		{
			name:      "explicit guest destination",
			workspace: runtime.Workspace{Path: "/host/source", GuestPath: "/workspace/project"},
			wantDest:  "/workspace/project",
		},
		{
			name:                  "read only alternate destination",
			workspace:             runtime.Workspace{Path: "/host/source", GuestPath: "/workspace/project", ReadOnly: true},
			wantDest:              "/workspace/project",
			wantReadOnly:          true,
			wantRecursiveReadOnly: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mounts, err := workspaceMounts(&runtime.Config{Workspaces: []runtime.Workspace{tt.workspace}})
			if err != nil {
				t.Fatal(err)
			}
			if len(mounts) != 1 {
				t.Fatalf("mount count = %d, want 1", len(mounts))
			}
			if mounts[0].Source != tt.workspace.Path || mounts[0].Destination != tt.wantDest ||
				mounts[0].ReadOnly != tt.wantReadOnly || mounts[0].RecursiveReadOnly != tt.wantRecursiveReadOnly {
				t.Fatalf("mount = %+v", mounts[0])
			}
		})
	}
}

func TestWorkspaceMountsRejectInvalidGuestDestination(t *testing.T) {
	for _, destination := range []string{
		"relative/path",
		"/workspace/../escape",
		"/workspace/./project",
		"/workspace,src=/attacker",
		"/workspace=bad",
		"/workspace\x00bad",
		"/workspace\nbad",
		"/workspace\rbad",
	} {
		t.Run(fmt.Sprintf("%q", destination), func(t *testing.T) {
			_, err := workspaceMounts(&runtime.Config{Workspaces: []runtime.Workspace{{Path: "/host", GuestPath: destination}}})
			if err == nil {
				t.Fatalf("workspaceMounts accepted destination %q", destination)
			}
		})
	}
}

func TestWorkspaceMountsRejectUnsafeHostSource(t *testing.T) {
	for _, source := range []string{"", "/work,src=/etc", "/work=other", "/work\"bad", "/work\x00bad", "/work\nbad", "/work\rbad"} {
		t.Run(fmt.Sprintf("%q", source), func(t *testing.T) {
			_, err := workspaceMounts(&runtime.Config{Workspaces: []runtime.Workspace{{Path: source, GuestPath: "/workspace"}}})
			if err == nil {
				t.Fatalf("workspaceMounts accepted unsafe source %q", source)
			}
		})
	}
	mounts, err := workspaceMounts(&runtime.Config{Workspaces: []runtime.Workspace{{Path: "/work/valid path", GuestPath: "/workspace"}}})
	if err != nil || len(mounts) != 1 || mounts[0].Source != "/work/valid path" {
		t.Fatalf("valid source rejected: mounts=%v err=%v", mounts, err)
	}
}

func TestRunRejectsUnsafeMountSource(t *testing.T) {
	runner := &fakeRunner{}
	client := newTestClient(t, runner)
	err := client.Run(context.Background(), RunSpec{
		ContainerID: "test", Image: "alpine", Mounts: []Mount{{Type: "ext4", Source: "/volume,src=/etc", Destination: "/data"}},
	})
	if err == nil {
		t.Fatal("Run accepted an injected mount source")
	}
	if len(runner.calls) != 0 {
		t.Fatal("Run invoked ctr for an invalid mount")
	}
}

func TestRunRejectsUnsupportedReadOnlyMounts(t *testing.T) {
	for _, mount := range []Mount{
		{Type: "ext4", Source: "/volume", Destination: "/data", ReadOnly: true},
		{Type: "ext4", Source: "/volume", Destination: "/data", RecursiveReadOnly: true},
		{Type: "bind", Source: "/workspace", Destination: "/workspace", RecursiveReadOnly: true},
	} {
		runner := &fakeRunner{}
		client := newTestClient(t, runner)
		err := client.Run(context.Background(), RunSpec{ContainerID: "test", Image: "alpine", Mounts: []Mount{mount}})
		if err == nil || len(runner.calls) != 0 {
			t.Fatalf("Run accepted mount %+v or invoked ctr: err=%v calls=%v", mount, err, runner.calls)
		}
	}
	runner := &fakeRunner{}
	client := newTestClient(t, runner)
	err := client.Run(context.Background(), RunSpec{ContainerID: "test", Image: "alpine", Mounts: []Mount{{Type: "ext4", Source: "/volume", Destination: "/data"}}})
	if err != nil || len(runner.calls) != 1 {
		t.Fatalf("valid writable volume rejected: err=%v calls=%v", err, runner.calls)
	}
}

func TestWorkspaceMountsRejectDuplicateGuestDestination(t *testing.T) {
	_, err := workspaceMounts(&runtime.Config{Workspaces: []runtime.Workspace{
		{Path: "/host/one", GuestPath: "/workspace"},
		{Path: "/host/two", GuestPath: "/workspace"},
	}})
	if err == nil {
		t.Fatal("workspaceMounts accepted duplicate guest destinations")
	}
}

func TestBackendCreateUsesGuestWorkspaceDestination(t *testing.T) {
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		return nil, nil
	}}
	backend := &Backend{stateDir: t.TempDir(), client: newTestClient(t, runner), image: "alpine:3.22", verifier: testArtifactVerifier(t)}
	_, err := backend.Create(context.Background(), runtime.Config{
		Name: "dev",
		Workspaces: []runtime.Workspace{{
			Path:      "/host/source",
			GuestPath: "/workspace/project",
			ReadOnly:  true,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if want := "type=bind,src=/host/source,dst=/workspace/project,options=rbind:ro:rro"; !strings.Contains(args, want) {
		t.Fatalf("missing guest workspace mount %q in %q", want, args)
	}
}

func TestCapabilitiesFailClosed(t *testing.T) {
	backend := &Backend{}
	caps, err := backend.Capabilities(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if caps.Network || caps.IPv6 {
		t.Fatalf("network capabilities must stay off: %+v", caps)
	}
}

func TestBackendHandle(t *testing.T) {
	backend := &Backend{fifoDir: "/tmp/fifo"}
	handle := backend.Handle("dev")
	if handle.ID != "rheic-dev" || handle.FIFODir != "/tmp/fifo" {
		t.Fatalf("unexpected handle: %+v", handle)
	}
}

type fakeNetwork struct {
	started     int
	ownedStarts int
	owned       map[string]string // sandbox -> token bound via StartOwned
	lastToken   string
	ports       []runtime.Port
	allow       []runtime.Rule
	deny        []runtime.Rule
	stopped     int
	stopErr     error
	stopCtxErr  error
}

func (f *fakeNetwork) StartOwned(ctx context.Context, sandbox, token string, ports []runtime.Port, allow, deny []runtime.Rule) (runtime.NetworkAttachment, error) {
	f.ownedStarts++
	f.lastToken = token
	if f.owned == nil {
		f.owned = map[string]string{}
	}
	f.owned[sandbox] = token
	return f.Start(ctx, sandbox, ports, allow, deny)
}

func (f *fakeNetwork) Start(_ context.Context, _ string, ports []runtime.Port, allow, deny []runtime.Rule) (runtime.NetworkAttachment, error) {
	f.started++
	f.ports = append([]runtime.Port(nil), ports...)
	f.allow = append([]runtime.Rule(nil), allow...)
	f.deny = append([]runtime.Rule(nil), deny...)
	return runtime.NetworkAttachment{Annotations: []string{"io.containerd.nerdbox.network.0=test"}}, nil
}
func (f *fakeNetwork) UpdatePolicy(context.Context, string, []runtime.Port, []runtime.Rule, []runtime.Rule, int) error {
	return nil
}

func (f *fakeNetwork) UpdatePorts(context.Context, string, []runtime.Port) error { return nil }

func (f *fakeNetwork) Stop(ctx context.Context, sandbox string) error {
	f.stopped++
	f.stopCtxErr = ctx.Err()
	delete(f.owned, sandbox)
	return f.stopErr
}

func (f *fakeNetwork) AttachmentState(_ context.Context, sandbox, token string) (runtime.AttachmentState, error) {
	bound, ok := f.owned[sandbox]
	if !ok {
		return runtime.AttachmentAbsent, nil
	}
	if token != "" && bound == token {
		return runtime.AttachmentOwned, nil
	}
	return runtime.AttachmentForeign, nil
}

type gitForwarderNetwork struct {
	fakeNetwork
	sandbox string
	enabled bool
	port    uint16
	err     error
}

func (f *gitForwarderNetwork) SetGitDaemon(_ context.Context, sandbox string, enabled bool) (uint16, error) {
	f.sandbox = sandbox
	f.enabled = enabled
	if !enabled {
		return 0, f.err
	}
	return f.port, f.err
}

func TestBackendSetGitDaemonRequiresAndDelegatesCapability(t *testing.T) {
	backend := &Backend{}
	if _, err := backend.SetGitDaemon(context.Background(), "dev", true); err == nil {
		t.Fatal("SetGitDaemon succeeded without a network")
	}
	backend.network = &fakeNetwork{}
	if _, err := backend.SetGitDaemon(context.Background(), "dev", true); err == nil {
		t.Fatal("SetGitDaemon succeeded without the optional network capability")
	}

	forwarder := &gitForwarderNetwork{port: 49152}
	backend.network = forwarder
	port, err := backend.SetGitDaemon(context.Background(), "dev", true)
	if err != nil || port != 49152 || forwarder.sandbox != "dev" || !forwarder.enabled {
		t.Fatalf("enable Git daemon = %d, %v; forwarder=%+v", port, err, forwarder)
	}
	if port, err = backend.SetGitDaemon(context.Background(), "dev", false); err != nil || port != 0 || forwarder.enabled {
		t.Fatalf("disable Git daemon = %d, %v; forwarder=%+v", port, err, forwarder)
	}
}

func TestCreateReportsNetworkCleanupFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := errors.New("synthetic run failure")
	cleanupErr := errors.New("synthetic network cleanup failure")
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), " run --detach") {
			cancel()
			return nil, runErr
		}
		return nil, nil
	}}
	network := &fakeNetwork{stopErr: cleanupErr}
	backend := &Backend{stateDir: t.TempDir(), client: newTestClient(t, runner), image: "alpine:3.22", network: network, verifier: testArtifactVerifier(t)}
	_, err := backend.Create(ctx, runtime.Config{Name: "dev"})
	if !errors.Is(err, runErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("runtime and cleanup errors not preserved: %v", err)
	}
	if network.stopped != 1 || network.stopCtxErr != nil {
		t.Fatalf("network cleanup did not use a live context: %+v", network)
	}
}

func TestStopReportsBothTaskAndNetworkFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	taskErr := errors.New("synthetic task inspection failure")
	networkErr := errors.New("synthetic network stop failure")
	runner := &fakeRunner{fn: func([]string) ([]byte, error) { return nil, taskErr }}
	network := &fakeNetwork{stopErr: networkErr}
	backend := &Backend{client: newTestClient(t, runner), network: network}
	err := backend.Stop(ctx, runtime.Handle{ID: "rheic-dev"}, time.Second)
	if !errors.Is(err, taskErr) || !errors.Is(err, networkErr) {
		t.Fatalf("one of the stop failures was hidden: %v", err)
	}
	if network.stopped != 1 || network.stopCtxErr != nil {
		t.Fatalf("network cleanup did not use a live context: %+v", network)
	}
}

func TestBackendNetworkAnnotations(t *testing.T) {
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "tasks ls") {
			return []byte("TASK PID STATUS\n"), nil
		}
		return nil, nil
	}}
	client := newTestClient(t, runner)
	network := &fakeNetwork{}
	backend := &Backend{stateDir: t.TempDir(), client: client, image: "alpine:3.22", network: network, verifier: testArtifactVerifier(t)}
	handle, err := backend.Create(context.Background(), runtime.Config{
		Name: "dev", Ports: []runtime.Port{{Host: 8080, Guest: 3000, Protocol: "tcp"}},
		Allow: []runtime.Rule{{Protocol: "tcp", CIDR: "0.0.0.0/0", Port: 80}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if network.started != 1 || len(network.ports) != 1 || network.ports[0].Host != 8080 ||
		len(network.allow) != 1 || network.allow[0].Port != 80 {
		t.Fatalf("network starts=%d ports=%+v allow=%+v", network.started, network.ports, network.allow)
	}
	joined := strings.Join(runner.calls[len(runner.calls)-1], " ")
	if !strings.Contains(joined, "io.containerd.nerdbox.network.0=test") {
		t.Fatalf("missing network annotation: %s", joined)
	}
	caps, err := backend.Capabilities(context.Background())
	if err != nil || !caps.Network {
		t.Fatalf("network capability: %+v, %v", caps, err)
	}
	if err := backend.Stop(context.Background(), handle, 0); err != nil {
		t.Fatal(err)
	}
	if network.stopped != 1 {
		t.Fatalf("network stops = %d", network.stopped)
	}
}

func TestCreateInvalidProxyDoesNotStartNetwork(t *testing.T) {
	runner := &fakeRunner{fn: func([]string) ([]byte, error) { return nil, nil }}
	network := &fakeNetwork{}
	backend := &Backend{stateDir: t.TempDir(), client: newTestClient(t, runner), image: "alpine:3.22", network: network}
	_, err := backend.Create(context.Background(), runtime.Config{Name: "dev", ProxyPort: 1})
	if err == nil {
		t.Fatal("invalid proxy configuration accepted")
	}
	if network.started != 0 {
		t.Fatal("network started before configuration validation")
	}
}

func TestCreateRemovesContainerWhenRunFails(t *testing.T) {
	listings := 0
	generation := ""
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "run --detach"):
			generation = labelValue(args, generationLabel)
			return []byte("failed format"), errors.New("exit status 1")
		case strings.Contains(joined, "containers ls -q"):
			listings++
			if listings == 1 {
				return nil, nil // pre-create check: name is free
			}
			return []byte("rheic-dev\n"), nil // ctr left a partial container
		case strings.Contains(joined, "containers info"):
			return []byte(fmt.Sprintf(
				`{"ID":"rheic-dev","Labels":{"%s":"dev","%s":%q}}`,
				sandboxLabel, generationLabel, generation,
			)), nil
		}
		return nil, nil
	}}
	opts := testArtifactOptions(t)
	opts.StateDir = t.TempDir()
	opts.Image = "img"
	backend, err := NewBackend(Config{Socket: "/tmp/containerd.sock", CTR: "ctr"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	backend.client.runner = runner
	if _, err := backend.Create(context.Background(), runtime.Config{Name: "dev", Image: "img"}); err == nil {
		t.Fatal("failed run returned no error")
	}
	if generation == "" {
		t.Fatal("create did not record a generation label")
	}
	calls := fmt.Sprint(runner.calls)
	if !strings.Contains(calls, "containers delete rheic-dev") {
		t.Fatalf("partial container was not removed: %s", calls)
	}
}

func TestCreateCleanupLeavesContainerOwnedByAnotherCreate(t *testing.T) {
	runErr := errors.New("first create failed")
	listings := 0
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		joined := strings.Join(args, " ")
		switch {
		case strings.Contains(joined, "run --detach"):
			return []byte("failed format"), runErr
		case strings.Contains(joined, "containers ls -q"):
			listings++
			if listings == 1 {
				return nil, nil // pre-create check: name is free
			}
			return []byte("rheic-dev\n"), nil // a concurrent create now owns the name
		case strings.Contains(joined, "containers info"):
			return []byte(fmt.Sprintf(
				`{"ID":"rheic-dev","Labels":{"%s":"dev","%s":"concurrent-create"}}`,
				sandboxLabel, generationLabel,
			)), nil
		}
		return nil, nil
	}}
	backend, err := NewBackend(Config{Socket: "/tmp/containerd.sock", CTR: "ctr"}, BackendOptions{Image: "img", StateDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	backend.client.runner = runner
	if _, err := backend.Create(context.Background(), runtime.Config{Name: "dev", Image: "img"}); !errors.Is(err, runErr) {
		t.Fatalf("create error = %v, want %v", err, runErr)
	}
	calls := fmt.Sprint(runner.calls)
	if strings.Contains(calls, "containers delete") || strings.Contains(calls, "tasks delete") {
		t.Fatalf("cleanup deleted a container owned by another create: %s", calls)
	}
}

func TestCreateCleanupFailsClosedWithoutContainerIdentity(t *testing.T) {
	for _, tc := range []struct {
		name string
		info string
		want string
	}{
		{
			name: "missing generation label",
			info: fmt.Sprintf(`{"ID":"rheic-dev","Labels":{"%s":"dev"}}`, sandboxLabel),
			want: "no generation label",
		},
		{
			name: "unreadable container info",
			info: "not json",
			want: "verify container rheic-dev ownership",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runErr := errors.New("create failed")
			listings := 0
			runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
				joined := strings.Join(args, " ")
				switch {
				case strings.Contains(joined, "run --detach"):
					return nil, runErr
				case strings.Contains(joined, "containers ls -q"):
					listings++
					if listings == 1 {
						return nil, nil
					}
					return []byte("rheic-dev\n"), nil
				case strings.Contains(joined, "containers info"):
					return []byte(tc.info), nil
				}
				return nil, nil
			}}
			backend, err := NewBackend(Config{Socket: "/tmp/containerd.sock", CTR: "ctr"}, BackendOptions{Image: "img", StateDir: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			backend.client.runner = runner
			_, err = backend.Create(context.Background(), runtime.Config{Name: "dev", Image: "img"})
			if !errors.Is(err, runErr) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("create error = %v, want run error and %q", err, tc.want)
			}
			calls := fmt.Sprint(runner.calls)
			if strings.Contains(calls, "containers delete") || strings.Contains(calls, "tasks delete") {
				t.Fatalf("cleanup deleted without proving identity: %s", calls)
			}
		})
	}
}

func labelValue(args []string, key string) string {
	for i, arg := range args {
		if arg != "--label" || i+1 >= len(args) {
			continue
		}
		if name, value, ok := strings.Cut(args[i+1], "="); ok && name == key {
			return value
		}
	}
	return ""
}

func TestCreateRecursiveReadOnlyMountFailsClosed(t *testing.T) {
	runCalls := 0
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), " run --detach") {
			runCalls++
			return []byte("mount_setattr '/workspace': invalid argument"), errors.New("exit status 1")
		}
		return nil, nil
	}}
	backend := &Backend{stateDir: t.TempDir(), client: newTestClient(t, runner), image: "alpine:3.22", verifier: testArtifactVerifier(t)}
	_, err := backend.Create(context.Background(), runtime.Config{
		Name: "dev",
		Workspaces: []runtime.Workspace{{
			Path:      "/host/source",
			GuestPath: "/workspace",
			ReadOnly:  true,
		}},
	})
	if err == nil {
		t.Fatal("rejected rro mount returned no error")
	}
	if runCalls != 1 {
		t.Fatalf("runtime retried instead of failing closed: %d run attempts", runCalls)
	}
	for _, want := range []string{
		"recursive read-only workspace mount rejected",
		"mount_setattr",
		"options=rbind:ro:rro",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

func TestCreatePassesProxyChannelAnnotation(t *testing.T) {
	runner := &fakeRunner{}
	opts := testArtifactOptions(t)
	opts.StateDir = t.TempDir()
	opts.Image = "img"
	backend, err := NewBackend(Config{Socket: "/tmp/containerd.sock", CTR: "ctr"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	backend.client.runner = runner
	proxySocket := filepath.Join(os.TempDir(), "dev.proxy.sock")
	if _, err := backend.Create(context.Background(), runtime.Config{Name: "dev", Image: "img", ProxyPort: 1027, ProxySocket: proxySocket}); err != nil {
		t.Fatal(err)
	}
	calls := fmt.Sprint(runner.calls)
	wantAnnotation := fmt.Sprintf("io.rheic.proxy=port=1027,socket=%s", proxySocket)
	if !strings.Contains(calls, wantAnnotation) {
		t.Fatalf("proxy annotation missing: %s", calls)
	}
}

func TestCreateMountsAndStartsProxyHelper(t *testing.T) {
	runner := &fakeRunner{}
	opts := testArtifactOptions(t)
	opts.StateDir = t.TempDir()
	opts.Image = "img"
	backend, err := NewBackend(Config{Socket: "/tmp/containerd.sock", CTR: "ctr"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	backend.client.runner = runner
	helper := filepath.Join(t.TempDir(), "rheic-proxy-helper")
	if err := os.WriteFile(helper, []byte("synthetic helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := runtime.Config{Name: "dev", Image: "img", ProxyPort: 1027, ProxySocket: filepath.Join(os.TempDir(), "dev.proxy.sock")}
	if _, err := backend.CreateWithProxy(context.Background(), &cfg, helper, 3128, "api.openai.com"); err != nil {
		t.Fatal(err)
	}
	calls := fmt.Sprint(runner.calls)
	for _, want := range []string{
		"type=bind,src=" + helper + ",dst=/tmp/rheic-proxy-helper,options=rbind:ro",
		"/tmp/rheic-proxy-helper -listen 127.0.0.1:3128 -cid 2 -port 1027 -service-host api.openai.com",
	} {
		if !strings.Contains(calls, want) {
			t.Fatalf("missing %q in runtime call: %s", want, calls)
		}
	}
	if strings.Contains(calls, "/bin/sh") {
		t.Fatalf("proxy helper unexpectedly depends on a shell: %s", calls)
	}
}

func TestCreateWithProxyRoutesStartsMultipleListeners(t *testing.T) {
	runner := &fakeRunner{}
	opts := testArtifactOptions(t)
	opts.StateDir = t.TempDir()
	opts.Image = "img"
	backend, err := NewBackend(Config{Socket: "/tmp/containerd.sock", CTR: "ctr"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	backend.client.runner = runner
	helper := filepath.Join(t.TempDir(), "rheic-proxy-helper")
	if err := os.WriteFile(helper, []byte("synthetic helper"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := runtime.Config{Name: "dev", Image: "img", ProxyPort: 1027, ProxySocket: filepath.Join(os.TempDir(), "dev.proxy.sock")}
	routes := []string{"openai=api.openai.com:3128", "anthropic=api.anthropic.com:3129"}
	if _, err := backend.CreateWithProxyRouteArgs(context.Background(), &cfg, helper, routes); err != nil {
		t.Fatal(err)
	}
	calls := fmt.Sprint(runner.calls)
	for _, want := range []string{
		"-route openai=api.openai.com:3128",
		"-route anthropic=api.anthropic.com:3129",
	} {
		if !strings.Contains(calls, want) {
			t.Fatalf("missing %q in runtime call: %s", want, calls)
		}
	}
	if strings.Contains(calls, "/bin/sh") {
		t.Fatalf("proxy helper unexpectedly depends on a shell: %s", calls)
	}
}

func TestValidProxyRoutesRejectAmbiguousOrUnsafeRoutes(t *testing.T) {
	valid := []proxyRoute{
		{service: "openai", port: 3128, host: "api.openai.com"},
		{service: "anthropic", port: 3129, host: "api.anthropic.com"},
	}
	if !validProxyRoutes(valid) {
		t.Fatal("valid proxy routes were rejected")
	}
	for _, routes := range [][]proxyRoute{
		{valid[0]},
		{valid[0], {service: "openai", port: 3130, host: "api.other.com"}},
		{valid[0], {service: "anthropic", port: 3128, host: "api.anthropic.com"}},
		{valid[0], {service: "anthropic;touch", port: 3129, host: "api.anthropic.com"}},
		{valid[0], {service: "anthropic", port: 3129, host: "api.anthropic.com:443"}},
	} {
		if validProxyRoutes(routes) {
			t.Fatalf("unsafe or ambiguous routes were accepted: %+v", routes)
		}
	}
}

func TestProxyHelperRejectsShellMetacharactersInHost(t *testing.T) {
	for _, host := range []string{"api.openai.com; touch /tmp/owned", "api.openai.com:443", " api.openai.com"} {
		if validProxyServiceHost(host) {
			t.Fatalf("accepted unsafe service host %q", host)
		}
	}
}

func TestRunRunsTrustedHelperAsRoot(t *testing.T) {
	runner := &fakeRunner{}
	client := newTestClient(t, runner)
	err := client.Run(context.Background(), RunSpec{
		ContainerID: "rheic-dev", Name: "dev", Image: "alpine:3.22", RunAsRoot: true,
		Args: []string{"/tmp/rheic-proxy-helper"},
	})
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(runner.calls[0], " ")
	if !strings.Contains(args, "--user 0:0") {
		t.Fatalf("helper did not run as root: %s", args)
	}
	runner.calls = nil
	if err := client.Run(context.Background(), RunSpec{ContainerID: "rheic-agent", Name: "agent", Image: "alpine:3.22"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(runner.calls[0], " "), "--user") {
		t.Fatal("agent workload unexpectedly forced to root")
	}
}

func TestCreateMarksOnlyWorkspacesForOwnershipSemantics(t *testing.T) {
	runner := &fakeRunner{}
	opts := testArtifactOptions(t)
	opts.StateDir = t.TempDir()
	opts.Image = "img"
	backend, err := NewBackend(Config{Socket: "/tmp/containerd.sock", CTR: "ctr"}, opts)
	if err != nil {
		t.Fatal(err)
	}
	backend.client.runner = runner
	helper := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(helper, []byte("synthetic"), 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := runtime.Config{Name: "dev", Image: "img", ProxyPort: 1027, ProxySocket: filepath.Join(os.TempDir(), "dev.proxy.sock"), Workspaces: []runtime.Workspace{{Path: "/host/work", GuestPath: "/guest/work", ReadOnly: true}}}
	if _, err := backend.CreateWithProxy(context.Background(), &cfg, helper, 3128, "api.openai.com"); err != nil {
		t.Fatal(err)
	}
	calls := fmt.Sprint(runner.calls)
	workHash := sha256.Sum256([]byte("/guest/work"))
	helperHash := sha256.Sum256([]byte("/tmp/rheic-proxy-helper"))
	if !strings.Contains(calls, fmt.Sprintf("io.rheic.workspace.%x=true", workHash[:])) {
		t.Fatal("workspace annotation missing")
	}
	if strings.Contains(calls, fmt.Sprintf("io.rheic.workspace.%x", helperHash[:])) {
		t.Fatal("proxy helper must not be marked as workspace")
	}
}

//nolint:nestif // The two outcomes share the same fake and journal assertions.
func TestCreateJournalLifecycle(t *testing.T) {
	for _, failPull := range []bool{false, true} {
		t.Run(fmt.Sprint("pull_failure_", failPull), func(t *testing.T) {
			state := t.TempDir()
			journalPath := filepath.Join(state, "journal", "create-rheic-dev.json")
			runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
				cmd := strings.Join(args, " ")
				if strings.Contains(cmd, "images ls") {
					data, err := os.ReadFile(journalPath)
					if err != nil {
						t.Fatalf("pending journal before image access: %v", err)
					}
					record, err := journal.Parse(data)
					if err != nil || record.Phase != "pending" || len(record.Resources) != 0 {
						t.Fatalf("pending record = %+v, %v", record, err)
					}
					if failPull {
						return nil, errors.New("image failure")
					}
					return []byte("img\n"), nil
				}
				return nil, nil
			}}
			backend := &Backend{client: newTestClient(t, runner), image: "img", stateDir: state}
			handle, err := backend.Create(context.Background(), runtime.Config{Name: "dev"})
			if failPull {
				if err == nil {
					t.Fatal("expected image failure")
				}
				if _, err := os.Stat(journalPath); err != nil {
					t.Fatal(err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if handle.FIFODir != filepath.Join(state, "fifo") {
					t.Fatalf("fifo root = %q", handle.FIFODir)
				}
				if _, err := os.Stat(journalPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("journal remains: %v", err)
				}
			}
		})
	}
}

func TestCreateSuccessRemovesJournal(t *testing.T) {
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) { return nil, nil }}
	state := t.TempDir()
	backend := &Backend{stateDir: state, client: newTestClient(t, runner), image: "alpine:3.22", verifier: testArtifactVerifier(t)}
	if _, err := backend.Create(context.Background(), runtime.Config{Name: "dev"}); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(state, "journal"))
	if err != nil {
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		return
	}
	if len(entries) != 0 {
		t.Fatalf("journal entries survived success: %v", entries)
	}
}

func TestCreateRunFailureKeepsJournal(t *testing.T) {
	runErr := errors.New("synthetic run failure")
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), " run --detach") {
			return nil, runErr
		}
		return nil, nil
	}}
	state := t.TempDir()
	backend := &Backend{stateDir: state, client: newTestClient(t, runner), image: "alpine:3.22", verifier: testArtifactVerifier(t)}
	if _, err := backend.Create(context.Background(), runtime.Config{Name: "dev"}); !errors.Is(err, runErr) {
		t.Fatalf("err=%v", err)
	}
	data, err := os.ReadFile(filepath.Join(state, "journal", "create-rheic-dev.json"))
	if err != nil {
		t.Fatalf("journal not kept after run failure: %v", err)
	}
	rec, perr := journal.Parse(data)
	if perr != nil || rec.Phase != "run" || rec.ID != "rheic-dev" {
		t.Fatalf("journal record = %+v err=%v", rec, perr)
	}
}

func TestRecoverStopsOwnedNetworkAndRemovesJournal(t *testing.T) {
	state := t.TempDir()
	runErr := errors.New("synthetic run failure")
	runner := &fakeRunner{fn: func(args []string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), " run --detach") {
			return nil, runErr
		}
		return nil, nil
	}}
	network := &fakeNetwork{}
	backend := &Backend{stateDir: state, client: newTestClient(t, runner), image: "alpine:3.22", network: network, verifier: testArtifactVerifier(t)}
	if _, err := backend.Create(context.Background(), runtime.Config{Name: "dev"}); !errors.Is(err, runErr) {
		t.Fatalf("create err=%v", err)
	}
	if network.ownedStarts != 1 || network.lastToken == "" {
		t.Fatalf("network not started with journal token: %+v", network)
	}
	findings, err := backend.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("unexpected findings: %v", findings)
	}
	if network.stopped != 1 {
		t.Fatalf("owned network not stopped: %+v", network)
	}
	if _, err := os.Stat(filepath.Join(state, "journal", "create-rheic-dev.json")); !os.IsNotExist(err) {
		t.Fatalf("journal survived reconciliation: %v", err)
	}
}

func TestRecoverLeavesForeignNetwork(t *testing.T) {
	state := t.TempDir()
	if err := os.MkdirAll(filepath.Join(state, "journal"), 0700); err != nil {
		t.Fatal(err)
	}
	rec := journal.Record{Schema: 1, ID: "rheic-dev", Token: "0123456789abcdef0123456789abcdef", Phase: "run", Resources: []journal.Resource{{Kind: "network", NativeID: "dev", Marked: true}}, StartedAtUnix: 1}
	data, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(state, "journal", "create-rheic-dev.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	network := &fakeNetwork{owned: map[string]string{"dev": "other-token"}}
	backend := &Backend{stateDir: state, client: newTestClient(t, &fakeRunner{fn: func([]string) ([]byte, error) { return nil, nil }}), image: "alpine:3.22", network: network, verifier: testArtifactVerifier(t)}
	findings, err := backend.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Reason != journal.ForeignResource {
		t.Fatalf("findings=%v", findings)
	}
	if network.stopped != 0 {
		t.Fatal("foreign network was stopped")
	}
	if _, err := os.Stat(filepath.Join(state, "journal", "create-rheic-dev.json")); err != nil {
		t.Fatalf("journal removed despite foreign resource: %v", err)
	}
}

func TestRecoverWithoutAttesterLeavesNetworkUnsupported(t *testing.T) {
	state := t.TempDir()
	if err := os.MkdirAll(filepath.Join(state, "journal"), 0700); err != nil {
		t.Fatal(err)
	}
	rec := journal.Record{Schema: 1, ID: "rheic-dev", Token: "0123456789abcdef0123456789abcdef", Phase: "run", Resources: []journal.Resource{{Kind: "network", NativeID: "dev", Marked: true}}, StartedAtUnix: 1}
	data, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(state, "journal", "create-rheic-dev.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	backend := &Backend{stateDir: state, client: newTestClient(t, &fakeRunner{fn: func([]string) ([]byte, error) { return nil, nil }}), image: "alpine:3.22", verifier: testArtifactVerifier(t)}
	findings, err := backend.Recover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Reason != journal.UnsupportedOwnership {
		t.Fatalf("findings=%v", findings)
	}
}
