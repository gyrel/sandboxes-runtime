# Linux workspace parity — 2026-11-16

Scope: workspace mounts for the containerd/nerdbox backend on a Linux host
(Linux/arm64 in the pinned build). The reference is Docker's Linux bind-mount
behavior, not Docker Desktop's macOS ownership translation.

## Findings

| Check | Linux result | Status |
| --- | --- | --- |
| Host UID/GID visible in the guest | Host owner is returned unchanged by libkrun's Linux passthrough | Holds |
| `user.*` xattr round trip | Host xattr is readable in the guest; a guest `setfattr` is visible on the host | Holds |
| POSIX ACL xattr visibility | `getfacl` in the guest shows the host ACL entries | Holds |
| POSIX ACL enforcement | The guest kernel checks mode bits only; ACL grants and denies are not applied | Platform limit |
| Mode-600 isolation between guest users | A second non-root guest UID gets `EACCES`; the owner and guest root can read | Holds (rootful shim) |
| Guest-created file ownership | A rootful shim creates the host file with the calling guest UID/GID by switching the worker thread credentials | Holds (rootful shim) |
| Read-only workspace | Writes and xattr updates fail; reads, `getfacl` and `getfattr` still work | Holds |
| Distinct non-root guest users on a rootless shim | Linux passthrough cannot switch to a foreign UID/GID and returns `EPERM` | Rootless limit |

The table combines pinned-source analysis with the assertions in the gated live
tests below. The live assertions were not executed in the macOS-hosted
environment used for this note because that VM had no `/dev/kvm`; see
[Local VM harness](#local-vm-harness).

Guest root is not isolated by construction: it can read a mode-600 file owned
by another user, exactly as in a rootful Docker container.

## Why the backend behaves this way

`ctr/backend.go` turns each `runtime.Workspace` into a bind mount. `ctr/client.go`
renders it as:

```text
type=bind,src=<host path>,dst=<guest path>,options=rbind:rw
type=bind,src=<host path>,dst=<guest path>,options=rbind:ro:rro
```

The nerdbox shim rewrites every bind into a virtiofs share and mounts it in the
guest under `/run/mnt/bind-<hash>`. The pinned shim patch marks workspace mounts
with an annotation, but selects libkrun's workspace semantics only on macOS:

```go
workspace := runtime.GOOS == "darwin" &&
    b.Spec.Annotations[fmt.Sprintf("io.gyrel.workspace.%x", hash[:])] == "true"
```

Guest user selection is separate from the mount. `Run` adds `--user 0:0` only
for `RunAsRoot` (the trusted proxy helper); otherwise the image's `USER`
applies, which is normally guest root for the test images. The older
`Backend.Exec` path rejects `ExecRequest.User`; `Backend.ExecNative` applies a
numeric `uid[:gid]` or a resolved guest user/group. The live tests use numeric
UIDs through `ExecNative` so they can exercise non-root guests.

The backend does not request an idmapped mount or a user namespace for a
workspace. Linux therefore presents the host ownership, which is also Docker's
default for a rootful Linux bind mount. Docker Desktop's macOS translation to
the agent UID is a different platform behavior and is not applied here.

On Linux the share therefore stays on libkrun's default
`KRUN_SEMANTICS_LINUX_COMPLETE` (value 0). That is the correct choice:
`LinuxSimplified` (value 1) would not map ownership in libkrun's Linux
passthrough, and it disables `ALLOW_IDMAP` in
`src/devices/src/virtio/fs/device.rs`; it only changes macOS behavior.

Relevant pinned inputs:

- libkrun 1.19.6, commit `227b2de6ed323fe180e02f871c5f325a90c13cc2`.
  The `server.rs`, `linux/passthrough.rs` and `device.rs` files used for this
  analysis compare byte-for-byte with that upstream commit.
- Linux kernel 6.12.109, virtio-fs client defaults in `fs/fuse/virtio_fs.c`
  (lines 1528-1529): `ctx->default_permissions = 1; ctx->allow_other = 1;`
  and `FS_ALLOW_IDMAP` (line 1756).
- libkrun `src/devices/src/virtio/fs/linux/passthrough.rs` returns the host
  `stat` UID/GID and has xattrs enabled by default (`xattr: true`).
- The same file's `set_creds` switches the serving thread to the guest UID/GID
  when the shim has `CAP_SETUID`/`CAP_SETGID`; an unprivileged shim returns
  `EPERM` for a different UID/GID.

## Platform limit: POSIX ACL enforcement

The ACL xattr survives both directions, so `getfacl` and `setfacl` see the host
ACL. The guest cannot use it for permission decisions because libkrun 1.19.6
does not negotiate the FUSE POSIX ACL capability. Its init reply advertises:

```text
ASYNC_READ | PARALLEL_DIROPS | BIG_WRITES | AUTO_INVAL_DATA | ASYNC_DIO |
HAS_IOCTL_DIR | ATOMIC_O_TRUNC | MAX_PAGES | SUBMOUNTS |
HANDLE_KILLPRIV_V2 | INIT_EXT
```

`FUSE_POSIX_ACL` is absent (`src/devices/src/virtio/fs/server.rs`, `init`).
The Linux kernel then treats ACLs as opaque xattrs:

- `fuse_get_inode_acl()` returns `NULL` when `!fc->posix_acl`
  (`fs/fuse/acl.c`, lines 79-90 in Linux 6.12.109).
- `generic_permission()` therefore falls back to mode bits
  (`fs/fuse/dir.c`, `fuse_permission`, line 1559 in Linux 6.12.109).
- `getfacl` still works because it reads the `system.posix_acl_access` xattr
  directly.

This is a libkrun/virtiofs limitation, not a Gyrel mount-rendering bug. The live
test asserts mode-based isolation unconditionally and skips the ACL allow/deny
assertions with this exact reason when the guest mount type is `virtiofs`.

Consequence: an ACL-only grant on a mode-600 file is denied in the guest, and
an ACL-only deny on a mode-666 file is not honored. Use group/mode bits for
guest isolation until libkrun negotiates `FUSE_POSIX_ACL`.

## Rootless limit

libkrun's Linux passthrough performs a guest operation with the guest UID/GID
by changing the worker thread credentials (`set_creds`). Without
`CAP_SETUID`/`CAP_SETGID`, a request for any UID/GID other than the shim user
returns `EPERM`. A rootless shim can therefore serve guest root and its own UID,
but cannot provide distinct non-root guest identities. Use a rootful
containerd/shim for the isolation and ownership checks.

## Live tests

`ctr/workspace_linux_live_test.go` is guarded by:

```go
//go:build linux && gyrel_linux_workspace
```

The tests create owned sandboxes, so they are opt-in. They do not run under a
plain `go test ./...`.

### Environment

| Variable | Required | Meaning |
| --- | --- | --- |
| `GYREL_TEST_CTR_SOCKET` | yes | containerd socket used by `ctr`/the native client |
| `GYREL_TEST_IMAGE` | yes | preloaded image with the guest tools below |
| `GYREL_TEST_CTR` | no | `ctr` binary; defaults to `ctr` on `PATH` |
| `GYREL_TEST_RUNTIME` | no | runtime name; defaults to `io.containerd.nerdbox.v1` |
| `GYREL_TEST_SNAPSHOTTER` | no | snapshotter; defaults to `erofs` |
| `GYREL_TEST_PLATFORM` | no | defaults to `linux/<GOARCH>` |
| `GYREL_TEST_FIFO_DIR` | no | FIFO directory; defaults to the test temp directory |

The test process must be able to use the containerd socket and the runtime
assets. Run it as root when you want the guest-created ownership check to run;
otherwise that check logs a skip reason and the remaining assertions still run.

### Guest image

The image needs `/bin/sh`, `stat`, `getfacl`, `setfacl`, `getfattr` and
`setfattr`. A minimal Alpine image:

```dockerfile
FROM alpine:3.22
RUN apk add --no-cache acl attr
```

Build it, then import it into the test containerd namespace, or use any image
that already contains those tools (for example a Debian/Ubuntu image with
`acl` and `attr` installed):

```sh
ctr --address "$GYREL_TEST_CTR_SOCKET" --namespace gyrel images import image.tar
export GYREL_TEST_IMAGE=localhost/gyrel-workspace-live:20261116
```

The image is only a userspace source; the workspace itself is the virtiofs
mount, not an image layer.

### Build and run

Cross-compile the gated test binary on the development host:

```sh
GOWORK=off GOOS=linux GOARCH=arm64 \
  go test -c -tags gyrel_linux_workspace ./ctr \
  -o /tmp/ctr-workspace-live.test
```

Copy it to the Linux host/VM, set the variables, and run:

```sh
export GYREL_TEST_CTR_SOCKET=/run/gyrel/containerd.sock
export GYREL_TEST_IMAGE=localhost/gyrel-workspace-live:20261116
export GYREL_TEST_CTR=/opt/gyrel/ctr
export GYREL_TEST_RUNTIME=io.containerd.nerdbox.v1
export GYREL_TEST_SNAPSHOTTER=erofs
export GYREL_TEST_PLATFORM=linux/arm64

sudo -E /tmp/ctr-workspace-live.test \
  -test.v -test.run '^TestLinuxWorkspace'
```

Each test creates one uniquely named sandbox and removes it in `t.Cleanup`.
`TestLinuxWorkspaceReadWriteLive` covers ownership, ACL/xattr visibility,
guest-side xattr write-through, guest-created ownership, mode-600 isolation and
ACL enforcement. `TestLinuxWorkspaceReadOnlyLive` covers the same visibility
checks plus read-only rejection of file and xattr writes.

### Local VM harness

The existing Linux runtime recipe is `build/README.md` plus the alpha bundle's
`README-ALPHA.md` (rootful containerd, nerdbox shim, `LIBKRUN_PATH`,
`LD_LIBRARY_PATH`). A Lima VM is sufficient if it exposes `/dev/kvm` to the
guest, because libkrun's Linux backend requires KVM:

```sh
limactl start --name gyrel-linux --vm-type=qemu --cpus=4 --memory=8 \
  --mount "$PWD:w" template://ubuntu-24.04
limactl shell gyrel-linux -- sudo apt-get update
limactl shell gyrel-linux -- sudo apt-get install -y acl attr
```

If the guest reports `kvm [1]: HYP mode not available` and has no `/dev/kvm`,
the nerdbox microVM cannot boot; use a native Linux host or a Linux VM with
nested KVM. That was the case in the macOS-hosted Lima environment used for
this note: Ubuntu 24.04.5, kernel `6.8.0-147-generic`, aarch64, no `/dev/kvm`.
The static checks in this change still ran on the host; the live tests were not
executed there.

## Status note

Pinned-source analysis says Linux workspace mounts preserve host UID/GID and
xattrs, and mode-based guest user isolation works with a rootful shim. The
gated live tests assert those properties; they were not executed in this
environment because the available Linux VM had no `/dev/kvm`. POSIX ACL
enforcement and distinct non-root identities on a rootless shim remain platform
limits. No released artifact or native-Linux acceptance is claimed by this
note.
