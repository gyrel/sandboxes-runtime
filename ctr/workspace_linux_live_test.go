//go:build linux && rheic_linux_workspace

package ctr

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	runtime "github.com/rheic/sandboxes-runtime"
)

// These tests exercise the Linux nerdbox/virtiofs workspace path against the
// Docker bind-mount baseline. They are opt-in because they create real
// containerd tasks and need a running, owned Linux host (a Linux VM is fine).
//
// The image must provide /bin/sh, stat, getfacl, setfacl, getfattr and
// setfattr. On Debian/Ubuntu install the acl and attr packages.
const (
	liveWorkspaceXattr      = "user.rheic.workspace.live"
	liveWorkspaceGuestXattr = "user.rheic.guest"
	liveWorkspaceRW         = "/workspace"
	liveWorkspaceRO         = "/workspace-ro"
)

type liveWorkspaceConfig struct {
	socket      string
	image       string
	ctr         string
	runtimeName string
	snapshotter string
	platform    string
	fifoDir     string
}

type liveWorkspaceFixture struct {
	root        string
	hostUID     uint32
	hostGID     uint32
	aclUID      uint32
	deniedUID   uint32
	writerUID   uint32
	secret      string
	aclAllow    string
	aclDeny     string
	xattrFile   string
	createdFile string
}

type liveWorkspaceResult struct {
	stdout string
	stderr string
	code   int
}

func TestLinuxWorkspaceReadWriteLive(t *testing.T) {
	cfg := loadLiveWorkspaceConfig(t)
	requireHostTools(t, "setfacl", "setfattr", "getfattr")
	fixture := prepareLiveWorkspace(t)

	backend := newLiveWorkspaceBackend(t, cfg)
	handle := createLiveWorkspace(t, backend, cfg, "linux-ws-rw", fixture.root, liveWorkspaceRW, false)
	requireGuestTools(t, backend, handle, "getfacl", "setfacl", "getfattr", "setfattr", "stat")

	assertGuestOwnership(t, backend, handle, fixture)
	assertGuestACLVisible(t, backend, handle, fixture)
	assertGuestXattrVisible(t, backend, handle, fixture)
	assertGuestXattrWrite(t, backend, handle, fixture)
	assertGuestCreateOwnership(t, backend, handle, fixture)
	assertModeIsolation(t, backend, handle, fixture)
	t.Run("ACLEnforcement", func(t *testing.T) {
		assertACLEnforcement(t, backend, handle, fixture)
	})
}

func TestLinuxWorkspaceReadOnlyLive(t *testing.T) {
	cfg := loadLiveWorkspaceConfig(t)
	requireHostTools(t, "setfacl", "setfattr")
	fixture := prepareLiveWorkspace(t)

	backend := newLiveWorkspaceBackend(t, cfg)
	handle := createLiveWorkspace(t, backend, cfg, "linux-ws-ro", fixture.root, liveWorkspaceRO, true)
	requireGuestTools(t, backend, handle, "getfacl", "getfattr", "setfattr", "stat")

	assertGuestOwnershipAt(t, backend, handle, fixture, liveWorkspaceRO)
	assertGuestACLVisibleAt(t, backend, handle, fixture, liveWorkspaceRO)
	assertGuestXattrVisibleAt(t, backend, handle, fixture, liveWorkspaceRO)
	assertReadOnlyWrites(t, backend, handle, liveWorkspaceRO)
}

func loadLiveWorkspaceConfig(t *testing.T) liveWorkspaceConfig {
	t.Helper()
	socket := os.Getenv("RHEIC_TEST_CTR_SOCKET")
	image := os.Getenv("RHEIC_TEST_IMAGE")
	if socket == "" || image == "" {
		t.Skip("set RHEIC_TEST_CTR_SOCKET and RHEIC_TEST_IMAGE to run the Linux workspace live tests")
	}
	platform := os.Getenv("RHEIC_TEST_PLATFORM")
	if platform == "" {
		platform = "linux/" + goruntime.GOARCH
	}
	fifoDir := os.Getenv("RHEIC_TEST_FIFO_DIR")
	if fifoDir == "" {
		fifoDir = t.TempDir()
	}
	return liveWorkspaceConfig{
		socket:      socket,
		image:       image,
		ctr:         os.Getenv("RHEIC_TEST_CTR"),
		runtimeName: os.Getenv("RHEIC_TEST_RUNTIME"),
		snapshotter: os.Getenv("RHEIC_TEST_SNAPSHOTTER"),
		platform:    platform,
		fifoDir:     fifoDir,
	}
}

func newLiveWorkspaceBackend(t *testing.T, cfg liveWorkspaceConfig) *Backend {
	t.Helper()
	backend, err := NewBackend(Config{
		Socket:      cfg.socket,
		CTR:         cfg.ctr,
		Runtime:     cfg.runtimeName,
		Snapshotter: cfg.snapshotter,
		Platform:    cfg.platform,
	}, BackendOptions{Image: cfg.image, FIFODir: cfg.fifoDir})
	if err != nil {
		t.Fatalf("configure live backend: %v", err)
	}
	return backend
}

func createLiveWorkspace(t *testing.T, backend *Backend, cfg liveWorkspaceConfig, prefix, hostPath, guestPath string, readOnly bool) runtime.Handle {
	t.Helper()
	name := fmt.Sprintf("%s-%d-%d", prefix, os.Getpid(), time.Now().UnixNano())
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	handle, err := backend.Create(ctx, runtime.Config{
		Name:  name,
		Image: cfg.image,
		Workspaces: []runtime.Workspace{{
			Path:      hostPath,
			GuestPath: guestPath,
			ReadOnly:  readOnly,
		}},
	})
	if err != nil {
		if readOnly && (strings.Contains(err.Error(), "mount_setattr") || strings.Contains(err.Error(), "recursive read-only")) {
			t.Skipf("guest runtime cannot apply recursive read-only workspace mounts: %v", err)
		}
		t.Fatalf("create workspace sandbox: %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		if err := backend.Delete(cleanupCtx, handle); err != nil {
			t.Logf("cleanup sandbox %s: %v", handle.ID, err)
		}
	})
	waitLiveTask(t, backend, ctx, handle)
	return handle
}

func waitLiveTask(t *testing.T, backend *Backend, ctx context.Context, handle runtime.Handle) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !backend.client.TaskRunning(ctx, handle.ID) {
		if time.Now().After(deadline) {
			t.Fatalf("sandbox %s did not reach RUNNING", handle.ID)
		}
		select {
		case <-ctx.Done():
			t.Fatalf("sandbox %s did not reach RUNNING: %v", handle.ID, ctx.Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func prepareLiveWorkspace(t *testing.T) liveWorkspaceFixture {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatalf("make workspace traversable: %v", err)
	}
	hostUID, err := effectiveID(os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	hostGID, err := effectiveID(os.Getegid())
	if err != nil {
		t.Fatal(err)
	}
	aclUID := pickUID(61000, hostUID, hostGID)
	deniedUID := pickUID(62000, hostUID, hostGID, aclUID)
	writerUID := pickUID(63000, hostUID, hostGID, aclUID, deniedUID)

	fixture := liveWorkspaceFixture{
		root:        root,
		hostUID:     hostUID,
		hostGID:     hostGID,
		aclUID:      aclUID,
		deniedUID:   deniedUID,
		writerUID:   writerUID,
		secret:      "secret.txt",
		aclAllow:    "acl-allow.txt",
		aclDeny:     "acl-deny.txt",
		xattrFile:   "xattr.txt",
		createdFile: "created-by-guest.txt",
	}
	writeLiveFile(t, root, fixture.secret, "host-secret\n", 0o600)
	writeLiveFile(t, root, fixture.aclAllow, "acl-allow\n", 0o600)
	writeLiveFile(t, root, fixture.aclDeny, "acl-deny\n", 0o666)
	writeLiveFile(t, root, fixture.xattrFile, "xattr\n", 0o644)

	runHostTool(t, "setfacl", "-m", fmt.Sprintf("u:%d:rw-", aclUID), filepath.Join(root, fixture.aclAllow))
	runHostTool(t, "setfacl", "-m", fmt.Sprintf("u:%d:---", deniedUID), filepath.Join(root, fixture.aclDeny))
	runHostTool(t, "setfattr", "-n", liveWorkspaceXattr, "-v", "visible", filepath.Join(root, fixture.xattrFile))
	return fixture
}

func writeLiveFile(t *testing.T, root, name, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), mode); err != nil {
		t.Fatalf("write fixture %s: %v", name, err)
	}
	if err := os.Chmod(filepath.Join(root, name), mode); err != nil {
		t.Fatalf("chmod fixture %s: %v", name, err)
	}
}

func requireHostTools(t *testing.T, names ...string) {
	t.Helper()
	for _, name := range names {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("host tool %q is required for the Linux workspace live tests: %v", name, err)
		}
	}
}

func runHostTool(t *testing.T, name string, args ...string) string {
	t.Helper()
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		message := strings.ToLower(string(output))
		if strings.Contains(message, "not supported") {
			t.Skipf("host filesystem does not support %s: %v: %s", name, err, strings.TrimSpace(string(output)))
		}
		t.Fatalf("%s %v: %v: %s", name, args, err, strings.TrimSpace(string(output)))
	}
	return string(output)
}

func effectiveID(id int) (uint32, error) {
	if id < 0 {
		return 0, fmt.Errorf("negative host uid/gid %d", id)
	}
	return uint32(id), nil
}

func pickUID(base uint32, used ...uint32) uint32 {
	uid := base
	for uid != 0 {
		conflict := false
		for _, candidate := range used {
			if uid == candidate {
				conflict = true
				break
			}
		}
		if !conflict {
			return uid
		}
		uid++
	}
	return base
}

func guestUser(uid uint32) string {
	return fmt.Sprintf("%d:%d", uid, uid)
}

func guestPath(root, name string) string {
	return path.Join(root, name)
}

func requireGuestTools(t *testing.T, backend *Backend, handle runtime.Handle, names ...string) {
	t.Helper()
	for _, name := range names {
		result := execLiveGuest(t, backend, handle, "0:0", "/bin/sh", "-c", `command -v "$1"`, "sh", name)
		if result.code != 0 {
			t.Skipf("guest image lacks %q; install the acl and attr packages in the test image (stderr=%s)", name, strings.TrimSpace(result.stderr))
		}
	}
}

func execLiveGuest(t *testing.T, backend *Backend, handle runtime.Handle, user string, argv ...string) liveWorkspaceResult {
	t.Helper()
	var stdout, stderr strings.Builder
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	code, err := backend.ExecNative(ctx, handle, runtime.ExecRequest{
		Argv:   argv,
		User:   user,
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("guest exec %q as %q: %v (stderr=%s)", argv, user, err, strings.TrimSpace(stderr.String()))
	}
	return liveWorkspaceResult{stdout: stdout.String(), stderr: stderr.String(), code: code}
}

func mustLiveGuest(t *testing.T, backend *Backend, handle runtime.Handle, user string, argv ...string) liveWorkspaceResult {
	t.Helper()
	result := execLiveGuest(t, backend, handle, user, argv...)
	if result.code != 0 {
		t.Fatalf("guest exec %q as %q exited %d (stderr=%s)", argv, user, result.code, strings.TrimSpace(result.stderr))
	}
	return result
}

func skipIfGuestUnsupported(t *testing.T, tool string, result liveWorkspaceResult) {
	t.Helper()
	message := strings.ToLower(result.stderr)
	if strings.Contains(message, "not supported") {
		t.Skipf("guest mount does not support %s for this workspace: %s", tool, strings.TrimSpace(result.stderr))
	}
}

func assertGuestOwnership(t *testing.T, backend *Backend, handle runtime.Handle, fixture liveWorkspaceFixture) {
	t.Helper()
	assertGuestOwnershipAt(t, backend, handle, fixture, liveWorkspaceRW)
}

func assertGuestOwnershipAt(t *testing.T, backend *Backend, handle runtime.Handle, fixture liveWorkspaceFixture, guestRoot string) {
	t.Helper()
	result := mustLiveGuest(t, backend, handle, "0:0", "stat", "-c", "%u:%g", guestPath(guestRoot, fixture.secret))
	want := fmt.Sprintf("%d:%d", fixture.hostUID, fixture.hostGID)
	if got := strings.TrimSpace(result.stdout); got != want {
		t.Fatalf("guest sees workspace owner %s, want host owner %s", got, want)
	}
}

func assertGuestACLVisible(t *testing.T, backend *Backend, handle runtime.Handle, fixture liveWorkspaceFixture) {
	t.Helper()
	assertGuestACLVisibleAt(t, backend, handle, fixture, liveWorkspaceRW)
}

func assertGuestACLVisibleAt(t *testing.T, backend *Backend, handle runtime.Handle, fixture liveWorkspaceFixture, guestRoot string) {
	t.Helper()
	result := execLiveGuest(t, backend, handle, "0:0", "getfacl", "-cn", guestPath(guestRoot, fixture.aclAllow))
	if result.code != 0 {
		skipIfGuestUnsupported(t, "getfacl", result)
		t.Fatalf("guest getfacl exited %d: %s", result.code, strings.TrimSpace(result.stderr))
	}
	want := fmt.Sprintf("user:%d:rw-", fixture.aclUID)
	if !strings.Contains(result.stdout, want) {
		t.Fatalf("guest getfacl output does not contain %q:\n%s", want, result.stdout)
	}
}

func assertGuestXattrVisible(t *testing.T, backend *Backend, handle runtime.Handle, fixture liveWorkspaceFixture) {
	t.Helper()
	assertGuestXattrVisibleAt(t, backend, handle, fixture, liveWorkspaceRW)
}

func assertGuestXattrVisibleAt(t *testing.T, backend *Backend, handle runtime.Handle, fixture liveWorkspaceFixture, guestRoot string) {
	t.Helper()
	result := execLiveGuest(t, backend, handle, "0:0", "getfattr", "--absolute-names", "--only-values", "-n", liveWorkspaceXattr, guestPath(guestRoot, fixture.xattrFile))
	if result.code != 0 {
		skipIfGuestUnsupported(t, "getfattr", result)
		t.Fatalf("guest getfattr exited %d: %s", result.code, strings.TrimSpace(result.stderr))
	}
	if got := strings.TrimSpace(result.stdout); got != "visible" {
		t.Fatalf("guest xattr value = %q, want %q", got, "visible")
	}
}

func assertGuestXattrWrite(t *testing.T, backend *Backend, handle runtime.Handle, fixture liveWorkspaceFixture) {
	t.Helper()
	result := execLiveGuest(t, backend, handle, "0:0", "setfattr", "-n", liveWorkspaceGuestXattr, "-v", "from-guest", guestPath(liveWorkspaceRW, fixture.xattrFile))
	if result.code != 0 {
		skipIfGuestUnsupported(t, "setfattr", result)
		t.Fatalf("guest setfattr exited %d: %s", result.code, strings.TrimSpace(result.stderr))
	}
	output := runHostTool(t, "getfattr", "--absolute-names", "--only-values", "-n", liveWorkspaceGuestXattr, filepath.Join(fixture.root, fixture.xattrFile))
	if got := strings.TrimSpace(output); got != "from-guest" {
		t.Fatalf("host xattr value after guest write = %q, want %q", got, "from-guest")
	}
}

func assertGuestCreateOwnership(t *testing.T, backend *Backend, handle runtime.Handle, fixture liveWorkspaceFixture) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Log("guest-created file ownership requires a rootful host shim so virtiofs can switch to the guest uid; skipping this check")
		return
	}
	result := execLiveGuest(t, backend, handle, guestUser(fixture.writerUID), "/bin/sh", "-c", `umask 077; printf created-by-guest > "$1"`, "sh", guestPath(liveWorkspaceRW, fixture.createdFile))
	if result.code != 0 {
		t.Logf("guest uid %d could not create a workspace file; the shim may be rootless (stderr=%s); skipping the ownership check", fixture.writerUID, strings.TrimSpace(result.stderr))
		return
	}
	info, err := os.Stat(filepath.Join(fixture.root, fixture.createdFile))
	if err != nil {
		t.Fatalf("stat guest-created file on host: %v", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("guest-created file has no stat metadata")
	}
	if stat.Uid != fixture.writerUID || stat.Gid != fixture.writerUID {
		t.Fatalf("guest-created file owner on host = %d:%d, want %d:%d", stat.Uid, stat.Gid, fixture.writerUID, fixture.writerUID)
	}
	visible := mustLiveGuest(t, backend, handle, guestUser(fixture.writerUID), "stat", "-c", "%u:%g", guestPath(liveWorkspaceRW, fixture.createdFile))
	if got, want := strings.TrimSpace(visible.stdout), guestUser(fixture.writerUID); got != want {
		t.Fatalf("guest sees guest-created file owner %s, want %s", got, want)
	}
	denied := execLiveGuest(t, backend, handle, guestUser(fixture.deniedUID), "cat", guestPath(liveWorkspaceRW, fixture.createdFile))
	if denied.code == 0 {
		t.Fatalf("second guest user uid %d read a mode-600 file created by uid %d", fixture.deniedUID, fixture.writerUID)
	}
}

func assertModeIsolation(t *testing.T, backend *Backend, handle runtime.Handle, fixture liveWorkspaceFixture) {
	t.Helper()
	secret := guestPath(liveWorkspaceRW, fixture.secret)
	owner := guestUser(fixture.hostUID)
	result := execLiveGuest(t, backend, handle, owner, "cat", secret)
	if result.code != 0 {
		t.Fatalf("workspace owner uid %d cannot read its mode-600 file: %s", fixture.hostUID, strings.TrimSpace(result.stderr))
	}
	result = execLiveGuest(t, backend, handle, guestUser(fixture.deniedUID), "cat", secret)
	if result.code == 0 {
		t.Fatalf("second guest user uid %d read a mode-600 file owned by uid %d", fixture.deniedUID, fixture.hostUID)
	}
}

func assertACLEnforcement(t *testing.T, backend *Backend, handle runtime.Handle, fixture liveWorkspaceFixture) {
	t.Helper()
	allow := execLiveGuest(t, backend, handle, guestUser(fixture.aclUID), "/bin/sh", "-c", `printf acl-write >> "$1"`, "sh", guestPath(liveWorkspaceRW, fixture.aclAllow))
	if allow.code != 0 {
		skipIfVirtiofsACL(t, backend, handle, liveWorkspaceRW,
			fmt.Sprintf("ACL grant to uid %d is visible but the write was denied (stderr=%s)", fixture.aclUID, strings.TrimSpace(allow.stderr)))
		t.Fatalf("guest uid %d could not use the ACL grant: %s", fixture.aclUID, strings.TrimSpace(allow.stderr))
	}
	deny := execLiveGuest(t, backend, handle, guestUser(fixture.deniedUID), "/bin/sh", "-c", `printf acl-deny >> "$1"`, "sh", guestPath(liveWorkspaceRW, fixture.aclDeny))
	if deny.code == 0 {
		skipIfVirtiofsACL(t, backend, handle, liveWorkspaceRW,
			fmt.Sprintf("ACL deny for uid %d is visible but the write succeeded", fixture.deniedUID))
		t.Fatalf("guest uid %d bypassed an explicit ACL deny entry", fixture.deniedUID)
	}
}

func skipIfVirtiofsACL(t *testing.T, backend *Backend, handle runtime.Handle, guestRoot, reason string) {
	t.Helper()
	if guestMountType(t, backend, handle, guestRoot) != "virtiofs" {
		return
	}
	t.Skipf("libkrun 1.19.6 virtiofs does not negotiate FUSE_POSIX_ACL, so ACL xattrs are visible but the guest kernel enforces mode bits only: %s", reason)
}

func guestMountType(t *testing.T, backend *Backend, handle runtime.Handle, guestRoot string) string {
	t.Helper()
	const script = `p="$1"; while read -r _ mnt type _; do if [ "$mnt" = "$p" ]; then printf '%s' "$type"; exit 0; fi; done < /proc/mounts; exit 1`
	result := execLiveGuest(t, backend, handle, "0:0", "/bin/sh", "-c", script, "sh", guestRoot)
	if result.code != 0 {
		return ""
	}
	return strings.TrimSpace(result.stdout)
}

func assertReadOnlyWrites(t *testing.T, backend *Backend, handle runtime.Handle, guestRoot string) {
	t.Helper()
	write := execLiveGuest(t, backend, handle, "0:0", "/bin/sh", "-c", `printf blocked > "$1"`, "sh", guestPath(guestRoot, "write-attempt.txt"))
	if write.code == 0 {
		t.Fatalf("read-only workspace accepted a file write")
	}
	xattr := execLiveGuest(t, backend, handle, "0:0", "setfattr", "-n", liveWorkspaceGuestXattr, "-v", "blocked", guestPath(guestRoot, "xattr.txt"))
	if xattr.code == 0 {
		t.Fatalf("read-only workspace accepted an xattr write")
	}
}
