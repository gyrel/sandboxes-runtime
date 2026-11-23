# Changelog

## v0.0.56 — 2026-11-23

### Fixed

- `IndexCapture` skips the archive root marker. GNU tar run as
  `tar -cf - -C / .` stores a "./" member; the indexer normalized it
  to an empty path and recorded it as an entry, so the diff plan
  referenced a member the layer stream never emits and building failed
  with `plan references 1 entries absent from capture (first: [])` in
  the live roundtrip. The base listing already skipped the root;
  indexing now matches, with a regression test covering root plus a
  regular member through the full plan/stream path.

## v0.0.55 — 2026-11-23

### Fixed

- Hardlink targets are canonicalized across capture, base listing and
  layer streaming. GNU tar records the target of a hardlink as it stored
  the member itself (often with a "./" prefix), while registry layers use
  clean relative names; the mismatch made unchanged hardlinks look
  changed, and re-emitting them then failed path validation with
  "bad hardlink target on usr/bin/perl5.40.1" in the live roundtrip.
  Diff also guarantees layer self-containment: an emitted hardlink drags
  its target member into the layer, and dangling targets (not captured,
  under a virtual prefix, or inside an excluded directory) fail closed.

## v0.0.54 — 2026-11-23

### Fixed

- Diff planning now skips unchanged non-regular entries and never
  attaches payload readers to them. Previously only identical regular
  files were deduplicated against the base listing, so every unchanged
  symlink, directory and hardlink of the merged root (alpine's `bin ->
  usr/bin`, `lib -> usr/lib`, …) was re-emitted as an addition; the
  capture stream gave link entries a reader and layer building failed
  with `entry "bin" of type "symlink" must not carry a reader`.
  `BaseFile` gained the link target; `applyBaseEntry` stores the real
  header mode for hardlinks; `plannedFromHeader` attaches a reader only
  to regular entries.

## v0.0.53 — 2026-11-23

### Fixed

- `StreamBaseListing` decodes compressed base layers. Registry blobs are
  stored as `tar+gzip` (and `tar+zstd`), but the base listing opened them
  as raw tar, so `template save` failed with `archive/tar: invalid tar
  header` on every Docker Hub base (live repro: alpine layer
  `sha256:00dbf115…`). The leading magic bytes now win over the declared
  media type (gzip/zstd/plain), a media claim of compression with
  mismatched bytes fails closed, and `klauspost/compress` (already pinned
  at the fixed v1.20.2) becomes a direct dependency for zstd. Exported
  archives keep using the original compressed blobs (digest identity
  preserved); the capture stream remains uncompressed by design.

## v0.0.52 — 2026-11-23

### Fixed

- Template base resolution follows multi-platform OCI indexes. Registry
  images (e.g. the `shell` template at
  `docker.io/docker/sandbox-templates@sha256:b178ca62…`) ship as indexes
  with several children (per-arch manifests plus attestation entries);
  the previous single-child rule failed with `index with 4 manifests`,
  aborting `template save` at the `read base image` step. The resolver
  now selects the child matching the configured platform (same
  `os[/arch[/variant]]` grammar as `ctr --platform`), skips attestation
  entries, and fails closed on zero or ambiguous matches.

## v0.0.51 — 2026-11-23

### Fixed

- `ocilayer` path grammar no longer rejects ordinary guest paths that
  contain the letters `x`/`0`. `entryPathCharset` guarded with
  `strings.ContainsAny(p, "\\x00")`, which is the character set
  backslash/`x`/`0`, so capturing any real image failed with
  `unsafe path ... outside the guest FS grammar` at the index step
  (live repro: `etc/alternatives/babeljs-external-helpers`). The guard
  now checks NUL and backslash explicitly, matching the capture-side
  idiom, with a charset regression table for paths and symlink targets.

## v0.0.50 — 2026-11-22

### Fixed

- Template capture no longer walks guest virtual filesystems. `proc`,
  `sys`, `dev` and `run/bundles` are excluded at the tar capture argv and
  suppressed from the OCI diff plan (no additions, whiteouts or opaque
  markers under those prefixes). Previously GNU tar aborted with exit 2 on
  unreadable proc nodes and inflated the archive by re-walking the EROFS
  layer directories exposed at `/run/bundles`, so `template save` could
  never complete against a live guest. Guest tar stderr is now captured in
  a bounded tail and included in the failure message (guest paths only,
  never host routes).

## v0.0.49 — 2026-11-22

### Added

- `TemplateRuntime.ImageDigest` seam and backend implementation (native
  image target lookup); `LoadTemplate` records the imported manifest
  digest so daemon-side template registration stores a real digest
  instead of an empty field.

## v0.0.48 — 2026-11-22

### Added

- Public `runtime.TemplateBackend` seam (save/load/remove/export/boot
  document) with presence-only env names; the ctr adapter implements it
  over the ADR-0008 pipeline so the daemon depends only on the public
  runtime module.

## v0.0.47 — 2026-11-22

### Added

- `RemoveTemplateImage` and `ExportTemplateArchive` on the ctr backend
  (template rm/export primitives; reference safety is enforced by the
  daemon before calling).

## v0.0.46 — 2026-11-22

### Added

- Template save/load orchestration (ADR-0008 slice 3): `SaveTemplate`
  streams a root-owned guest `tar -cf -` capture into a private temp file,
  resolves the base image listing from verified content blobs (digests
  re-checked on read; mismatch aborts), plans and streams one OCI diff
  layer over the capture in a single pass, assembles the image reusing the
  base config and layer digests, writes the dual OCI + docker-save archive
  once (no layer duplication, no squash), imports it under the normalized
  docker.io/library reference and optionally exports an
  exclusive-create copy. Excludes (mounts, `/var/lib/docker`) become opaque
  markers and are also passed as tar excludes; the exclude grammar refuses
  escapes and flag-looking values. `LoadTemplate` reads the archived tag
  from manifest.json, normalizes references and imports.

## v0.0.45 — 2026-11-22

### Added

- Capture indexing and diff planning: `IndexCapture` builds a sorted,
  content-hashed index from a random-access guest capture tar (hostile
  records — escaping paths, FIFOs, oversize streams — abort indexing fail
  closed); `Diff` plans additions/changes/skips plus per-path whiteouts and
  opaque markers; `FindCapturePayload` re-streams exact payloads by scan.
  `ctr` gains `ImportImage` (with import verification against the image
  list) and `ExportImage` for the docker-save template artifact.

## v0.0.44 — 2026-11-22

### Added

- `internal/ocilayer`: deterministic OCI diff-layer builder for template
  capture (ADR-0008 slice 1). Encodes regular/dir/symlink/hardlink entries
  plus OCI whiteouts and opaque markers, validates guest paths fail closed
  (escaping, control characters, bad link targets), content-addresses the
  layer, and assembles manifest/index/config/docker-save documents that
  reuse base layers strictly by digest (never squash). Fuzz target for the
  entry grammar included.

## Unreleased

### Added

- `runtime.Rule` carries HTTP L7 conditions (`Methods`, `Path`,
  `Query []QueryCondition`) so daemon network configuration reaches the
  gateway policy engine without lossy conversion. Runtime treats them as
  opaque data; evaluation and fail-closed rejection live in the gateway.

## v0.0.41 — 2026-11-19

### Fixed

- Record the snapshot source path and identity on non-Linux platforms so a
  daemon restart can reattach and clean a shared-skills snapshot instead of
  failing closed.


## v0.0.40 — 2026-11-19

### Fixed

- Reattach a shared-skills pin after a daemon restart from container labels and
  the recorded store dev/inode identity, provided the private bind mount is
  still present.
- Clean up the recorded pin on delete even when the current daemon process did
  not create it, so a restarted daemon does not leak a mount.


## v0.0.39 — 2026-11-19

### Fixed

- Export a pinned shared-skills store through a private bind mount instead of
  passing a `/proc/<pid>/fd/<n>` path to nerdbox. The fd path could be stat'ed
  but failed with `EIO` when virtiofs opened it, so the guest helper could not
  read the store on a real Linux KVM host.
- Unmount and remove the private pin on sandbox delete; a successful create and
  delete leaves no `rheic-skills-pin-*` mount or directory behind.


## v0.0.38 — 2026-11-19

### Added

- Add the shared skills mount contract (`SkillsMount`, guest store and helper
  paths) and a read-only delivery path. Linux pins the host store with
  `openat2` and passes an opened descriptor to containerd; other platforms use
  a bounded private snapshot.
- Stage the guest skills helper in a private `0700` directory so the nerdbox
  shim never exports its installation directory.
- Add a shared skills label so a restarted daemon can fail closed when the
  pinned source is no longer available.

### Security and limitations

- Read-write shared skills remain unsupported.
- The macOS snapshot intentionally gives up Docker's live-edit semantics.
- The Linux fd path needs a daemon process that stays alive; after a daemon
  restart, starting a shared-skills sandbox fails closed until it is recreated.


## v0.0.37 — 2026-11-19

## v0.0.36 — 2026-11-17

### Added

- Publish complete Linux ARM64 and macOS ARM64 native runtime archives with
  containerd, ctr, the patched nerdbox shim and gvproxy, libkrun, libkrunfw,
  the patched ARM64 kernel, and the reproducible EROFS guest rootfs.
- Add a strict bundle inventory, platform check, SHA-256 verification, and
  deterministic archive packaging. Both platform bundles passed a live ARM64
  guest task and post-task inventory check.

### Security and limitations

- The bundle manifest is a content inventory, not a signature. Release archive
  SHA-256 checksums are published separately. macOS libraries include relocated
  Homebrew dependencies and ad hoc code signatures; they are not Apple
  notarized. The macOS libkrun and graphics dependencies were not rebuilt from
  source in this release.
- The live guest task checks VM boot and basic lifecycle. It does not establish
  full Docker baseline or network-policy parity.

## v0.0.35 — 2026-11-17

### Fixed

- Build the Linux ARM64 guest EROFS rootfs directly from the pinned nerdbox
  source and crun binary. The recipe no longer requires an unavailable upstream
  base image. Its file inventory, UUID, timestamp, block size and ownership are
  fixed; two clean builds with Go 1.27.4 and erofs-utils 1.7.1 produced identical
  images.

### Security and limitations

- The rootfs recipe verifies the pinned source, patch and crun digests and
  refuses to overwrite an existing output. Runtime assets still require an
  assembled and verified bundle before launch; this source tag does not publish
  a kernel, shim or rootfs binary.

## v0.0.34 — 2026-11-16

### Added

- Map workspace ownership in macOS guests and add the pinned ARM64 kernel netfilter configuration for Docker workloads.

- Add gated Linux live tests (`linux && rheic_linux_workspace`) for workspace
  ACL/xattr visibility, ownership and UID isolation over nerdbox/virtiofs.
- Document Linux workspace semantics, the libkrun POSIX ACL limit, rootless
  UID restriction, and the local VM recipe.
- Extend the pinned gvproxy patch with a dedicated Git upload-pack forward
  endpoint. It keeps the allocated listener bound to IPv4 loopback and reports
  its actual port; generic forward requests cannot request port zero.
- Render read-only workspace bind mounts with `options=rbind:ro:rro` so the
  guest applies read-only recursively to nested submounts. Rejection by the
  guest runtime or kernel fails sandbox creation instead of retrying with a
  shallow `ro` bind.

### Changed

- Remove the mandatory M7 external security review gate from the pre-tag
  release workflow. Release candidates still require the full reusable CI
  workflow and the candidate validation controls before an immutable,
  non-force tag is created from `main`.

### Security

- Re-authorize host-loopback NAT translations on every TCP and UDP connection
  against the current egress-policy revision. A host-services entry installed at
  startup from an exact-host allow no longer remains usable after the policy is
  widened to a broad CIDR allow; explicit host-services opt-in still bypasses
  the per-connection exact-host check. Adds a policy-revision regression test.

### Fixed

- Return command-not-found for missing absolute guest executables; bound gateway audit resource usage.
- Reject unsafe runtime mount specifications and harden runtime input manifest validation.

- Make failed-create cleanup verify the sandbox generation label recorded by
  that create attempt before deleting a container, so a concurrent create for
  the same name cannot lose the container it owns. Missing or unreadable
  ownership metadata fails closed and preserves the cleanup error.

### Security and limitations

- Linux workspaces pass through host UID/GID and xattrs, but libkrun 1.19.6
  does not negotiate `FUSE_POSIX_ACL`: ACL xattrs are visible while the guest
  kernel enforces mode bits only. Distinct non-root guest identities also need
  a rootful shim; Linux passthrough returns `EPERM` when an unprivileged shim
  cannot switch to the guest UID/GID. See
  `docs/LINUX-WORKSPACE-PARITY-2026-11-16.md`.
- Recursive read-only workspace mounts require the pinned guest crun with
  `rro` support and a guest kernel with `mount_setattr(AT_RECURSIVE)` (Linux
  5.12 or newer; the pinned guest kernel is 6.12.109).
- Patch application and upstream package tests passed against the pinned
  gvisor-tap-vsock commit. Live VM and host Git remote lifecycle remain open.

## v0.0.30 — 2026-11-10

### Added

- Add pinned Linux ARM64 libkrun and nerdbox shim build recipes, runtime
  manifest checks, and a deterministic EROFS guest-rootfs recipe.
- Restrict the experimental Linux guest network helper to `NETLINK_ROUTE` and
  clean host rootfs mounts after successful VM shutdown and after abrupt shim
  death through containerd's bundle-scoped delete action.
- Restrict VM runtime asset lookup to explicit `LIBKRUN_PATH` or fixed system
  directories; the shim builder publishes output atomically without following
  symlink destinations.
- Pin Go 1.27.4 for runtime builds and verify the signed crun 1.30.1 guest
  runtime release by checksum before embedding it in the EROFS image.

### Security and limitations

- Linux runtime support remains experimental. Acceptance is limited to a
  privileged rootful workflow in a macOS-hosted Ubuntu ARM64 VM; native Linux,
  ordinary-user and rootless acceptance remain open. Windows runtime is out of
  scope.
- Runtime build-image pinning, signed provenance, independent security review
  and full Docker Sandboxes parity remain open. Abrupt-shim cleanup has been
  verified for an owned EROFS bundle in a privileged rootful Linux ARM64 VM;
  native Linux and ordinary-user/rootless acceptance remain open.
- Runtime assets are not digest-verified at load time; configured and default
  host asset directories must remain protected from untrusted writes.
- The guest crun update addresses the upstream rootfs `/dev` symlink advisory
  affecting versions before 1.28. The latest upstream release is used because
  crun is security-sensitive guest runtime code; its release asset and
  checksum list signatures are verified against the pinned upstream key.

## v0.0.20 — 2026-11-03

### Added

- Add a read-only guest proxy-helper mount and supervised startup through the optional runtime capability.
- Publish a CycloneDX module SBOM as a CI artifact.

### Security

- Harden pinned native-source verification against ignored files, hidden index flags, redirected worktrees, local Git configuration, and submodules.
- Normalize native build metadata for repeatable same-host artifact digests.

### Changed

- Normalize the Go module path to the lowercase `github.com/quoiner/sandboxes-runtime` namespace.
- Update `golang.org/x/net` to v0.62.0.
