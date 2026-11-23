package ctr

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

const taskRunning = "RUNNING"
const taskStopped = "STOPPED"

const (
	sandboxLabel    = "io.rheic.sandbox"
	generationLabel = "io.rheic.sandbox.generation"
)

// Runner executes ctr commands. Tests can replace it with a fake.
type Runner interface {
	CombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error)
}

type execRunner struct{}

func (execRunner) CombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- ctr and its arguments are validated by this adapter
	return cmd.CombinedOutput()
}

// StreamRunner is an optional Runner capability: execute ctr and hand every
// output chunk (stdout and stderr merged into the callback) to onChunk while
// the process runs. Implementations must serialize onChunk calls.
type StreamRunner interface {
	Stream(ctx context.Context, name string, args []string, onChunk func(chunk []byte)) error
}

func (execRunner) Stream(ctx context.Context, name string, args []string, onChunk func(chunk []byte)) error {
	cmd := exec.CommandContext(ctx, name, args...) // #nosec G204 -- ctr and its arguments are validated by this adapter
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	var mu sync.Mutex
	drain := func(r io.Reader) {
		buf := make([]byte, 4096)
		for {
			n, rerr := r.Read(buf)
			if n > 0 {
				chunk := append([]byte(nil), buf[:n]...)
				mu.Lock()
				onChunk(chunk)
				mu.Unlock()
			}
			if rerr != nil {
				return
			}
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); drain(stdout) }()
	go func() { defer wg.Done(); drain(stderr) }()
	wg.Wait()
	return cmd.Wait()
}

// Client wraps a pinned containerd CLI.
type Client struct {
	cfg    Config
	runner Runner
}

// New creates a containerd CLI client.
func New(cfg Config) (*Client, error) {
	cfg, err := cfg.withDefaults()
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, runner: execRunner{}}, nil
}

// Config returns the effective client configuration.
func (c *Client) Config() Config { return c.cfg }

// Version checks that containerd is reachable.
func (c *Client) Version(ctx context.Context) error {
	_, err := c.run(ctx, "version")
	return err
}

const (
	flagPlatform    = "--platform"
	flagSnapshotter = "--snapshotter"
)

// EnsureImage pulls image when it is not already present.
func (c *Client) EnsureImage(ctx context.Context, image string) error {
	return c.EnsureImageProgress(ctx, image, nil)
}

// EnsureImageProgress pulls image when absent, reporting advisory pull
// progress while the fetch runs. When onProgress is nil or the Runner does not
// support streaming, it uses the plain combined-output path. The returned
// error keeps the same redacted contract as run().
func (c *Client) EnsureImageProgress(ctx context.Context, image string, onProgress func(Progress)) error {
	if image == "" {
		return fmt.Errorf("image is required")
	}
	out, err := c.run(ctx, "images", "ls", "-q")
	if err != nil {
		return err
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == image {
			return nil
		}
	}
	pull := []string{"images", "pull", flagPlatform, c.cfg.Platform, flagSnapshotter, c.cfg.Snapshotter, image}
	if err := c.runPull(ctx, pull, onProgress); err != nil {
		return fmt.Errorf("pull %s: %w", image, err)
	}
	return nil
}

// runPull executes an image pull. Streaming runners drive a pullTracker so
// callers observe layer counts; otherwise it falls back to combined output.
func (c *Client) runPull(ctx context.Context, args []string, onProgress func(Progress)) error {
	sr, ok := c.runner.(StreamRunner)
	if !ok || onProgress == nil {
		_, err := c.run(ctx, args...)
		return err
	}
	full := c.globalArgs(args...)
	tracker := newPullTracker(onProgress)
	var combined bytes.Buffer
	err := sr.Stream(ctx, c.cfg.CTR, full, func(chunk []byte) {
		tracker.observe(chunk)
		combined.Write(chunk)
	})
	tracker.finish()
	if err == nil {
		return nil
	}
	roots := c.redactionRoots()
	message := fmt.Sprintf("ctr %s: %s: %s",
		redactHostPaths(formatArgs(full), roots),
		redactHostPaths(err.Error(), roots),
		redactHostPaths(outputTail(combined.String()), roots))
	return &redactedError{message: message, cause: err}
}

// ContainerExists reports whether a container exists.
func (c *Client) ContainerExists(ctx context.Context, id string) bool {
	found, _ := c.containerExists(ctx, id)
	return found
}

func (c *Client) containerExists(ctx context.Context, id string) (bool, error) {
	out, err := c.run(ctx, "containers", "ls", "-q")
	if err != nil {
		return false, err
	}
	return containsLine(out, id), nil
}

func (c *Client) containerLabels(ctx context.Context, id string) (map[string]string, error) {
	out, err := c.run(ctx, "containers", "info", id)
	if err != nil {
		return nil, err
	}
	var info struct {
		Labels map[string]string `json:"Labels"`
	}
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		return nil, fmt.Errorf("decode container info: %w", err)
	}
	return info.Labels, nil
}

// TaskRunning reports whether a task is running.
func (c *Client) TaskRunning(ctx context.Context, id string) bool {
	status, _ := c.taskStatus(ctx, id)
	return status == taskRunning
}

func (c *Client) taskStatus(ctx context.Context, id string) (string, error) {
	out, err := c.run(ctx, "tasks", "ls")
	if err != nil {
		return "", err
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	header := strings.Fields(lines[0])
	if len(header) != 3 || header[0] != "TASK" || header[1] != "PID" || header[2] != "STATUS" {
		return "", fmt.Errorf("invalid task list response")
	}
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return "", fmt.Errorf("invalid task status response")
		}
		if fields[0] == id {
			return fields[2], nil
		}
	}
	return "", nil
}

// Mount describes a bind mount.
type Mount struct {
	Type        string
	Source      string
	Destination string
	ReadOnly    bool
	// RecursiveReadOnly applies ReadOnly to every mount in the bind's mount
	// tree. It is rendered as the rro mount option and is only meaningful when
	// ReadOnly is set.
	RecursiveReadOnly bool
}

// RunSpec describes a detached runtime task.
type RunSpec struct {
	ContainerID string
	Name        string
	Image       string
	// Generation identifies one create attempt. It is recorded as a container
	// label so failed-create cleanup can prove ownership before deleting.
	Generation  string
	CPUs        uint8
	MemoryMiB   uint32
	FIFODir     string
	Mounts      []Mount
	Env         []string
	Privileged  bool
	Annotations []string
	Labels      []string
	Args        []string
	// RunAsRoot runs the trusted proxy helper as root so it can create the
	// vsock device and install the per-sandbox proxy CA bundle. Agent execs
	// keep the image user.
	RunAsRoot bool
}

// Run creates and starts a detached container.
func (c *Client) Run(ctx context.Context, spec RunSpec) error {
	if spec.ContainerID == "" || spec.Image == "" {
		return fmt.Errorf("container id and image are required")
	}
	if spec.CPUs == 0 {
		spec.CPUs = 2
	}
	if spec.MemoryMiB == 0 {
		spec.MemoryMiB = 1024
	}
	args := []string{
		"run", "--detach",
		"--runtime", c.cfg.Runtime,
		flagSnapshotter, c.cfg.Snapshotter,
		"--label", sandboxLabel + "=" + spec.Name,
		"--cpus", strconv.Itoa(int(spec.CPUs)),
		"--memory-limit", strconv.FormatUint(uint64(spec.MemoryMiB)*1024*1024, 10),
	}
	if spec.Generation != "" {
		args = append(args, "--label", generationLabel+"="+spec.Generation)
	}
	if spec.FIFODir != "" {
		args = append(args, "--fifo-dir", spec.FIFODir)
	}
	if spec.Privileged {
		args = append(args, "--cap-add", "CAP_SYS_ADMIN", "--cap-add", "CAP_NET_ADMIN", "--cap-add", "CAP_NET_RAW")
	}
	if spec.RunAsRoot {
		args = append(args, "--user", "0:0")
	}
	args = appendRunMetadata(args, spec.Annotations, spec.Labels)
	for _, mount := range spec.Mounts {
		if err := validateMount(mount); err != nil {
			return err
		}
		args = append(args, "--mount", mountSpec(mount))
	}
	for _, env := range spec.Env {
		args = append(args, "--env", env)
	}
	args = append(args, spec.Image, spec.ContainerID)
	if len(spec.Args) == 0 {
		args = append(args, "/bin/sh", "-c", "trap 'exit 0' TERM INT; while :; do sleep 3600; done")
	} else {
		args = append(args, spec.Args...)
	}
	_, err := c.run(ctx, args...)
	if err != nil {
		return recursiveReadOnlyError(spec.Mounts, err)
	}
	return nil
}

func appendRunMetadata(args, annotations, labels []string) []string {
	for _, annotation := range annotations {
		args = append(args, "--annotation", annotation)
	}
	for _, label := range labels {
		args = append(args, "--label", label)
	}
	return args
}

func validMountSource(source string) bool {
	return source != "" && !strings.ContainsAny(source, ",=\"\x00\r\n")
}

func validateMount(mount Mount) error {
	if !validMountSource(mount.Source) {
		return errors.New("mount source must not be empty or contain mount delimiters or control characters")
	}
	if mount.Type != "" && mount.Type != "bind" && (mount.ReadOnly || mount.RecursiveReadOnly) {
		return errors.New("read-only non-bind mounts are not supported")
	}
	if mount.RecursiveReadOnly && !mount.ReadOnly {
		return errors.New("recursive read-only requires a read-only mount")
	}
	return nil
}

// recursiveReadOnlyError makes a rejected rro option actionable. The pinned
// guest crun understands rro and applies it with mount_setattr(AT_RECURSIVE).
// If the guest runtime or kernel rejects the option, creating the sandbox must
// fail; retrying with a shallow ro bind would leave nested submounts writable.
func recursiveReadOnlyError(mounts []Mount, err error) error {
	recursive := false
	for _, mount := range mounts {
		if mount.ReadOnly && mount.RecursiveReadOnly {
			recursive = true
			break
		}
	}
	if !recursive || !strings.Contains(err.Error(), "mount_setattr") {
		return err
	}
	return fmt.Errorf("recursive read-only workspace mount rejected; the guest runtime must support rro via mount_setattr(AT_RECURSIVE) and the guest kernel must be Linux >= 5.12: %w", err)
}

// StartTask starts a stopped task.
func (c *Client) StartTask(ctx context.Context, id, fifoDir string) error {
	status, err := c.taskStatus(ctx, id)
	if err != nil {
		return fmt.Errorf("inspect task before start: %w", err)
	}
	switch status {
	case taskRunning:
		return nil
	case taskStopped:
		if err := c.DeleteTask(ctx, id); err != nil {
			return fmt.Errorf("remove stopped task before start: %w", err)
		}
	case "":
	default:
		return fmt.Errorf("cannot start task in state %q", status)
	}
	args := []string{"tasks", "start", "-d"}
	if fifoDir != "" {
		args = append(args, "--fifo-dir", fifoDir)
	}
	args = append(args, id)
	_, err = c.run(ctx, args...)
	return err
}

// StopTask terminates a task and waits for the grace period.
func (c *Client) StopTask(ctx context.Context, id string, grace time.Duration) error {
	status, err := c.taskStatus(ctx, id)
	if err != nil {
		return fmt.Errorf("inspect task: %w", err)
	}
	if status == "" {
		return nil
	}
	if status == taskStopped {
		return c.DeleteTask(ctx, id)
	}
	if status != taskRunning {
		return fmt.Errorf("cannot stop task in state %q", status)
	}
	if _, err := c.run(ctx, "tasks", "kill", "-s", "SIGTERM", id); err != nil {
		return fmt.Errorf("signal task: %w", err)
	}
	status, err = c.waitTaskStop(ctx, id, grace)
	if err != nil {
		return err
	}
	if status == taskRunning {
		if _, err := c.run(ctx, "tasks", "kill", "-s", "SIGKILL", id); err != nil {
			return fmt.Errorf("kill task: %w", err)
		}
	}
	if status == "" {
		return nil
	}
	if _, err := c.run(ctx, "tasks", "delete", "-f", id); err != nil {
		return fmt.Errorf("delete task: %w", err)
	}
	return nil
}

func (c *Client) waitTaskStop(ctx context.Context, id string, grace time.Duration) (string, error) {
	status := taskRunning
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		var err error
		status, err = c.taskStatus(ctx, id)
		if err != nil {
			return "", fmt.Errorf("inspect task: %w", err)
		}
		if status == "" || status == taskStopped {
			break
		}
		if status != taskRunning {
			return "", fmt.Errorf("cannot stop task in state %q", status)
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return status, nil
}

// DeleteTask removes a task if present.
func (c *Client) DeleteTask(ctx context.Context, id string) error {
	_, err := c.run(ctx, "tasks", "delete", "-f", id)
	return err
}

// DeleteContainer removes a container.
func (c *Client) DeleteContainer(ctx context.Context, id string) error {
	_, err := c.run(ctx, "containers", "delete", id)
	return err
}

// run executes ctr. The returned error is safe for API/CLI surfaces: the
// command line is rendered with environment values masked and host
// filesystem roots replaced by redactHostPaths, and only the last lines of
// globalArgs prefixes args with the daemon socket and namespace shared by
// every ctr invocation.
func (c *Client) globalArgs(args ...string) []string {
	return append([]string{"--address", c.cfg.Socket, "--namespace", c.cfg.Namespace}, args...)
}

// ctr output are attached. The full raw output is still returned for local
// daemon-side diagnostics.
func (c *Client) run(ctx context.Context, args ...string) (string, error) {
	full := c.globalArgs(args...)
	out, err := c.runner.CombinedOutput(ctx, c.cfg.CTR, full...)
	if err != nil {
		roots := c.redactionRoots()
		message := fmt.Sprintf("ctr %s: %s",
			redactHostPaths(formatArgs(full), roots),
			redactHostPaths(err.Error(), roots))
		if tail := redactHostPaths(outputTail(string(out)), roots); tail != "" {
			message += ": " + tail
		}
		return string(out), &redactedError{message: message, cause: err}
	}
	return string(out), nil
}

func containsLine(out, want string) bool {
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func mountSpec(m Mount) string {
	if m.Type != "" && m.Type != "bind" {
		return fmt.Sprintf("type=%s,src=%s,dst=%s", m.Type, m.Source, m.Destination)
	}
	options := "rbind:rw"
	switch {
	case m.ReadOnly && m.RecursiveReadOnly:
		// A plain ro bind only protects the top mount. rro applies
		// MOUNT_ATTR_RDONLY to the whole mount tree with mount_setattr, so
		// nested submounts cannot stay writable in the guest.
		options = "rbind:ro:rro"
	case m.ReadOnly:
		options = "rbind:ro"
	}
	return fmt.Sprintf("type=bind,src=%s,dst=%s,options=%s", m.Source, m.Destination, options)
}

// ImportImage imports an OCI/docker-save tar archive into the local image
// store under the given names, mirroring how template load consumes the
// baseline artifact. ref is the docker.io-normalized image name the daemon
// will boot from with --pull never semantics. Errors keep the redacted
// run() contract.
func (c *Client) ImportImage(ctx context.Context, tarPath, ref string) error {
	if tarPath == "" || ref == "" {
		return fmt.Errorf("import requires an archive path and an image name")
	}
	// Import must mirror the pull path's explicit platform/snapshotter: the
	// managed containerd config registers the erofs snapshotter but defines
	// no default unpack platforms, so an unflagged import aborts in the
	// transfer unpacker ("no unpack platforms defined").
	imp := []string{"images", "import", flagPlatform, c.cfg.Platform, flagSnapshotter, c.cfg.Snapshotter, tarPath}
	if _, err := c.run(ctx, imp...); err != nil {
		return fmt.Errorf("import template image: %w", err)
	}
	out, err := c.run(ctx, "images", "ls", "-q")
	if err != nil {
		return fmt.Errorf("verify imported template image: %w", err)
	}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == ref {
			return nil
		}
	}
	return fmt.Errorf("import template image: archive did not provide %s", ref)
}

// ExportImage writes the named image (with all its referenced layers by
// digest) to a docker-save-compatible tar for template save --output.
// Content addressing stays inside containerd; the daemon validates the
// produced file separately.
func (c *Client) ExportImage(ctx context.Context, tarPath, ref string) error {
	if tarPath == "" || ref == "" {
		return fmt.Errorf("export requires an archive path and an image name")
	}
	if _, err := c.run(ctx, "images", "export", tarPath, ref); err != nil {
		return fmt.Errorf("export template image: %w", err)
	}
	return nil
}

// RemoveImage deletes a template image reference from the local store. The
// daemon is responsible for refusing images still referenced by sandboxes.
func (c *Client) RemoveImage(ctx context.Context, ref string) error {
	if ref == "" {
		return errors.New("image reference is required")
	}
	if _, err := c.run(ctx, "images", "rm", ref); err != nil {
		return fmt.Errorf("remove image %s: %w", sanitizeRef(ref), err)
	}
	return nil
}

// ExportImageTo streams an existing image into the docker-save archive at
// tarPath (template export without a sandbox context).
func (c *Client) ExportImageTo(ctx context.Context, ref, tarPath string) error {
	return c.ExportImage(ctx, tarPath, ref)
}
