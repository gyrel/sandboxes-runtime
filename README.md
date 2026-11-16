# sandboxes-runtime

<img src="docs/assets/rheic-shark.png" alt="Rheic shark logo" width="180">


## Import path migration

The canonical Go module path is now `github.com/rheic/sandboxes-runtime` (previously `github.com/quoiner/sandboxes-runtime`). Update imports and `go.mod` requirements when moving to a release that includes this change. The old module path is not kept as a compatibility alias.

`runtime.Config` supports the additive per-VM service-proxy channel. A proxy
helper is mounted read-only at `/tmp/rheic-proxy-helper` and runs directly as
the container process, so proxy-enabled images do not need `/bin/sh`; the helper
accepts only the configured upstream host and talks to the host broker over the
shim's vsock bridge. The helper path must be
a static Linux ARM64 binary supplied by the daemon. Runtime users that leave
`ProxyHelperPath` empty retain the existing command path.

Status: pre-alpha.

Runtime adapters for containerd/nerdbox, VM lifecycle, workspace mounts, OCI
images, templates, and kits. Implements ports defined by sandboxes-core.

## Boundaries

- does not expose daemon or SDK types;
- does not make network policy decisions;
- host Docker socket is never mounted.

## Runtime pins

`build/manifest.yaml` pins containerd, nerdbox, libkrun, gvisor-tap-vsock,
patches, and the default image digest. Validate the checked-in inputs with:

```sh
make runtime-verify
```

`build/digests.yaml` records the SHA-256 of the manifest, its patches, and the
runtime-shipped shim, gvproxy, and QEMU binaries. The containerd adapter hashes
these inputs before every `Create` and `Start` and refuses to launch on a
missing entry, unreadable file, or digest mismatch. Host-provided `ctr` and
containerd are intentionally unmanaged and are not hashed by this runtime.
Regenerate the digest file after building or changing an artifact:

```sh
make artifact-digests ARTIFACTS="containerd-shim-nerdbox-v1=/path/to/shim gvproxy=/path/to/gvproxy"
```

See `build/README.md` for the full operator procedure.

## Host-services NAT exposure

The IPv4 gateway address is `192.168.127.1`. The gateway can also install a
host-services NAT alias that makes a guest-visible address reach host loopback:
`192.168.127.254` maps to `127.0.0.1`, and with the experimental IPv6 datapath
`fd72:6865:6963:1::2` maps to `::1`. Egress
policy is evaluated on the guest-visible address before NAT. A broad allow such
as `0.0.0.0/0`, `192.168.127.0/24`, or `::/0` therefore implies access to every
host loopback service on the matching address family, including host-local
daemons and development servers.

The pinned gvproxy datapath installs a loopback NAT entry only when host
services are explicitly enabled for the sandbox (`hostServicesEnabled: true`)
or the policy contains an exact-host allow for the alias, such as
`192.168.127.254/32`. A covering broad allow alone does not install it. Keep
egress rules narrow, avoid broad CIDRs, and do not enable host services for
sandboxes that do not need the proxy helper or registry endpoints.

## containerd adapter

`ctr` is the first lifecycle adapter. It uses a pinned containerd CLI and
implements the `runtime.Backend` contract: image pull, detached run, task
start/stop/delete, and workspace bind mounts. Read-only workspaces use the
recursive `rro` option (`options=rbind:ro:rro`) so nested submounts are
read-only too. This relies on the pinned guest crun and a guest kernel with
`mount_setattr(AT_RECURSIVE)` support; if the guest rejects the option, sandbox
creation fails closed rather than falling back to a shallow `ro` bind.

### Workspace filesystem semantics

On a Linux host, nerdbox exports each workspace through virtiofs with libkrun's
default `LinuxComplete` semantics. Host UID/GID, mode bits and xattrs, including
`system.posix_acl_*`, are passed through; a rootful shim can create host files
under the calling guest UID/GID and guest users with different non-root UIDs are
isolated by mode bits. Guest root is not isolated, as in a rootful Docker
container.

Two limits are platform limits, not mount-rendering choices:

- libkrun 1.19.6 does not negotiate `FUSE_POSIX_ACL`. `getfacl` and `setfacl`
  see the ACL xattrs, but the guest kernel enforces mode bits only, so ACL-only
  grants and denies do not affect access.
- A rootless shim cannot switch to a different guest UID/GID; Linux passthrough
  returns `EPERM` instead of providing distinct non-root identities.

Linux never applies the macOS-only workspace ownership mapping: libkrun's Linux
passthrough does not implement `LinuxSimplified` ownership, and selecting it
would only disable idmapped-mount support. See
[`docs/LINUX-WORKSPACE-PARITY-2026-11-16.md`](docs/LINUX-WORKSPACE-PARITY-2026-11-16.md)
for source evidence, live-test environment variables and the local Linux VM
recipe.

Current limits are explicit:

- `Capabilities.Network` is `false` unless a `runtime.Network` implementation is supplied;
- network annotations are wired through `runtime.Network`; the daemon supplies the gateway manager;
- non-interactive and interactive exec use separate adapter capabilities;
  native execution requires cancellation-aware output and interactive input
  requires an owned, closeable stream;
- local guest user/group name resolution depends on guest tools and is not
  a general NSS implementation; full signal and detach-key behavior is open;
- no snapshots or GPU;
- live VM validation is platform-specific and does not establish cross-platform
  parity; fault and independent security reviews remain open.

## Windows WHPX work in progress

`whpx.BuildArgs` builds a restricted QEMU argv for a Linux kernel/initrd/root
disk, forces `accel=whpx`, and permits the QEMU socket-network backend to
connect only to IPv4 loopback. `whpx.Runner` starts and tracks QEMU in
kill-on-close Windows Job Objects. It requires the QEMU executable's SHA-256 and
re-verifies it before every launch; a replaced or unreadable binary is refused.
These APIs are not wired into daemon composition and do not implement
`runtime.Backend`. Windows host support
remains unavailable until the project supplies and integrates owned disk/image
lifecycle, the guest control and workspace protocols, a private gateway API/
lease transport, and fail-closed cleanup. Do not use this low-level runtime
layer as evidence of a bootable or isolated sandbox.
