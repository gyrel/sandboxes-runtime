#!/bin/bash
# Darwin managed-alpha launcher. This file is the in-repo source of the
# published bundle artifact (staged as bin/gyreld-launch.sh). It bootstraps the
# pinned containerd for this bundle (alpha interim; daemon-managed containerd is
# the eventual design), then runs sandboxesd with per-launch artifact digest
# verification (refuses unverified bytes). Development escape hatch (NOT
# recommended): replace the digest flags with --allow-unmanaged-runtime.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
STATE="${GYREL_STATE_DIR:-${RHEIC_STATE_DIR:-$HOME/.sandboxes}}"
if [ -z "${GYREL_STATE_DIR:-}" ] && [ -n "${RHEIC_STATE_DIR:-}" ]; then
  echo "warning: RHEIC_STATE_DIR is deprecated; use GYREL_STATE_DIR" >&2
fi
# Prerequisite: Homebrew e2fsprogs provides mkfs.ext4 used by the nerdbox
# runtime to format sandbox rwlayer images (keg-only, not on minimal PATH).
e2fsprogs_sbin=""
for candidate in /opt/homebrew/opt/e2fsprogs/sbin /usr/local/opt/e2fsprogs/sbin; do
  if [ -x "$candidate/mkfs.ext4" ]; then PATH="$candidate:$PATH"; e2fsprogs_sbin="$candidate"; fi
done
export PATH
# The nerdbox shim resolves kernel/rootfs/libkrun assets strictly from
# LIBKRUN_PATH (never PATH; see nerdbox-runtime-asset-search.patch).
export LIBKRUN_PATH="$ROOT/runtime/assets:$ROOT/runtime/lib:$ROOT/runtime/bin"
if ! command -v mkfs.ext4 >/dev/null; then
  echo "missing prerequisite mkfs.ext4; install with: brew install e2fsprogs" >&2
  exit 1
fi
if [ "${1:-}" = --print-plan ]; then
  shift
  e2fsprogs_found="${e2fsprogs_sbin:-$(command -v mkfs.ext4)}"
  printf 'ROOT=%s\nSTATE=%s\nLIBKRUN_PATH=%s\ne2fsprogs candidate found: %s\n' "$ROOT" "$STATE" "$LIBKRUN_PATH" "$e2fsprogs_found"
  printf '%s\n' \
    "--state" "$STATE" \
    "--socket" "$STATE/sandboxesd.sock" \
    "--containerd" "$STATE/containerd.sock" \
    "--ctr" "$ROOT/runtime/bin/ctr" \
    "--gvproxy" "$ROOT/runtime/bin/gvproxy" \
    "--proxy-helper" "$ROOT/bin/gyrel-proxy-helper-linux-arm64" \
    "--artifact-digests=$ROOT/build/digests.yaml" \
    "--runtime-artifact" "containerd=$ROOT/runtime/bin/containerd" \
    "--runtime-artifact" "ctr=$ROOT/runtime/bin/ctr" \
    "--runtime-artifact" "containerd-shim-nerdbox-v1=$ROOT/runtime/bin/containerd-shim-nerdbox-v1" \
    "--runtime-artifact" "gvproxy=$ROOT/runtime/bin/gvproxy" \
    "--runtime-artifact" "kernel=$ROOT/runtime/assets/nerdbox-kernel-arm64" \
    "--runtime-artifact" "guest-rootfs=$ROOT/runtime/assets/nerdbox-rootfs-arm64.erofs" \
    "--run-dir" "$STATE/run" \
    "--image" "docker.io/library/alpine:3.22" \
    "$@"
  exit 0
fi
mkdir -p "$STATE"
umask 077
cat > "$STATE/containerd.toml" <<TOML
version = 3
[plugins.'io.containerd.server.v1.grpc']
  address = "$STATE/containerd.sock"
  uid = $(id -u)
  gid = $(id -g)
[plugins.'io.containerd.server.v1.ttrpc']
  address = "$STATE/containerd.sock.ttrpc"
  uid = $(id -u)
  gid = $(id -g)
[plugins.'io.containerd.snapshotter.v1.erofs']
  default_size = "64M"
[plugins.'io.containerd.differ.v1.erofs']
  mkfs_options = ['-b4096']
TOML
if [ ! -S "$STATE/containerd.sock" ]; then
  nohup "$ROOT/runtime/bin/containerd" --config "$STATE/containerd.toml" \
    --root "$STATE/containerd-root" --state "$STATE/containerd-state" \
    >> "$STATE/containerd.log" 2>&1 &
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -S "$STATE/containerd.sock" ] && break
    sleep 1
  done
  [ -S "$STATE/containerd.sock" ] || { echo "containerd failed to start; see $STATE/containerd.log" >&2; exit 1; }
fi
exec "$ROOT/bin/sandboxesd" \
  --state "$STATE" \
  --socket "$STATE/sandboxesd.sock" \
  --containerd "$STATE/containerd.sock" \
  --ctr "$ROOT/runtime/bin/ctr" \
  --gvproxy "$ROOT/runtime/bin/gvproxy" \
  --proxy-helper "$ROOT/bin/gyrel-proxy-helper-linux-arm64" \
  --artifact-digests="$ROOT/build/digests.yaml" \
  --runtime-artifact containerd="$ROOT/runtime/bin/containerd" \
  --runtime-artifact ctr="$ROOT/runtime/bin/ctr" \
  --runtime-artifact containerd-shim-nerdbox-v1="$ROOT/runtime/bin/containerd-shim-nerdbox-v1" \
  --runtime-artifact gvproxy="$ROOT/runtime/bin/gvproxy" \
  --runtime-artifact kernel="$ROOT/runtime/assets/nerdbox-kernel-arm64" \
  --runtime-artifact guest-rootfs="$ROOT/runtime/assets/nerdbox-rootfs-arm64.erofs" \
  --run-dir "$STATE/run" \
  --image docker.io/library/alpine:3.22 \
  "$@"
