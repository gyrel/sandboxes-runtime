#!/bin/bash
# Darwin managed-alpha launcher. This file is the in-repo source of the
# published bundle artifact (staged as bin/gyreld-launch.sh). It bootstraps the
# pinned containerd for this bundle (alpha interim; daemon-managed containerd is
# the eventual design), then runs sandboxesd with per-launch artifact digest
# verification (refuses unverified bytes).
# Development only: pass --allow-unmanaged-runtime first to skip pre-verification and daemon digest checks.
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
if ! command -v python3 >/dev/null 2>&1; then
  echo 'missing prerequisite python3 (required for managed artifact pre-verification and socket checks)' >&2
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
preverify_artifacts() {
  python3 - "$ROOT" <<'PYTHON'
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
name = 'artifacts'
try:
    paths = {key: 'runtime/bin/' + key for key in
             ('containerd', 'ctr', 'containerd-shim-nerdbox-v1', 'gvproxy')}
    paths.update(kernel='runtime/assets/nerdbox-kernel-arm64',
                 **{'guest-rootfs': 'runtime/assets/nerdbox-rootfs-arm64.erofs'})
    lines = (root / 'build/digests.yaml').read_text().splitlines()
    if 'artifacts:' not in lines:
        raise ValueError('missing or empty section')
    seen = set()
    for line in lines[lines.index('artifacts:') + 1:]:
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        if not line.startswith(' '):
            break
        name = line.strip().split(':', 1)[0]
        match = re.fullmatch(r' +([A-Za-z0-9_.-]+): sha256:([0-9a-f]{64}) *', line)
        if not match or name in seen:
            raise ValueError('invalid or duplicate digest entry')
        seen.add(name)
        digest = match[2]
        if name not in paths:
            raise ValueError('missing mapping')
        path = paths[name]
        if not (root / path).is_file():
            raise ValueError('missing or non-regular file')
        with (root / path).open('rb') as artifact:
            actual = subprocess.check_output(['shasum', '-a', '256'], stdin=artifact).split()[0].decode()
        if actual != digest:
            raise ValueError('digest mismatch')
        print(f'{name}={root / path}')
    missing = set(paths) - seen
    if missing:
        name = sorted(missing)[0]
        raise ValueError('missing digest')
except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
    sys.exit(f'artifact pre-verify failed: {name} [{error}]')
PYTHON
}
digest_args=()
if [ "${1:-}" = --allow-unmanaged-runtime ]; then
  shift
  digest_args+=(--allow-unmanaged-runtime)
else
  mappings=$(preverify_artifacts)
  digest_args+=("--artifact-digests=$ROOT/build/digests.yaml")
  while IFS= read -r artifact; do digest_args+=(--runtime-artifact "$artifact"); done <<< "$mappings"
fi
SOCKET="$STATE/containerd.sock"
UID_NOW=$(id -u)
check_socket() {
  python3 - "$1" "$UID_NOW" "$STATE/containerd.pid" "$2" <<'PYTHON'
import errno
import os
import pathlib
import socket
import stat
import subprocess
import sys

path, uid, pid_file, role = sys.argv[1:]

def inspect(endpoint, allow_reuse):
    original = os.lstat(endpoint)
    if not stat.S_ISSOCK(original.st_mode):
        sys.exit(f'inspect {endpoint}: expected a socket')
    if role == 'daemon':
        same_owner = original.st_uid == os.getuid()
    else:
        same_owner = subprocess.check_output(['stat', '-f%u', endpoint], text=True).strip() == uid
    if not same_owner:
        sys.exit(f'inspect {endpoint}: socket owner differs from current uid')
    if allow_reuse:
        try:
            pid = pathlib.Path(pid_file).read_text().strip()
            if pid.isascii() and pid.isdecimal() and int(pid) > 0:
                os.kill(int(pid), 0)
                fields = subprocess.check_output(
                    ['ps', '-p', pid, '-o', 'uid=', '-o', 'comm='], text=True).strip().split(None, 1)
                if len(fields) == 2 and fields[0] == uid and os.path.basename(fields[1]) == 'containerd':
                    return False
        except (OSError, ValueError, OverflowError, subprocess.CalledProcessError):
            pass
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
        probe.settimeout(1)
        try:
            probe.connect(endpoint)
        except OSError as error:
            if error.errno == errno.ECONNREFUSED:
                return original
            sys.exit(f'inspect {endpoint}: liveness uncertain ({error})')
    if role == 'daemon':
        sys.exit(f'inspect {endpoint}: daemon endpoint live with unverified provenance')
    sys.exit(f'inspect {endpoint}: live listener with unverified provenance')

dead = inspect(path, role == 'containerd')
if dead:
    stale = [(path, dead)]
    sibling = path + '.ttrpc'
    if role == 'containerd' and os.path.lexists(sibling):
        stale.append((sibling, inspect(sibling, False)))
    for endpoint, original in stale:
        if not os.path.samestat(original, os.lstat(endpoint)):
            sys.exit(f'inspect {endpoint}: socket changed during probe')
        os.unlink(endpoint)
    print("bootstrap")
else:
    print("reuse")
PYTHON
}
socket_action=bootstrap
if [ -e "$SOCKET" ] || [ -L "$SOCKET" ]; then socket_action=$(check_socket "$SOCKET" containerd); fi
mkdir -p "$STATE"
umask 077
if [ "$socket_action" = bootstrap ]; then
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
  nohup "$ROOT/runtime/bin/containerd" --config "$STATE/containerd.toml" \
    --root "$STATE/containerd-root" --state "$STATE/containerd-state" \
    >> "$STATE/containerd.log" 2>&1 &
  echo "$!" > "$STATE/containerd.pid"
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    [ -S "$STATE/containerd.sock" ] && break
    sleep 1
  done
  [ -S "$STATE/containerd.sock" ] || { echo "containerd failed to start; see $STATE/containerd.log" >&2; exit 1; }
fi
daemon_socket="$STATE/sandboxesd.sock"
if [ -e "$daemon_socket" ] || [ -L "$daemon_socket" ]; then
  check_socket "$daemon_socket" daemon > /dev/null
fi
exec "$ROOT/bin/sandboxesd" \
  --state "$STATE" \
  --socket "$STATE/sandboxesd.sock" \
  --containerd "$STATE/containerd.sock" \
  --ctr "$ROOT/runtime/bin/ctr" \
  --gvproxy "$ROOT/runtime/bin/gvproxy" \
  --proxy-helper "$ROOT/bin/gyrel-proxy-helper-linux-arm64" \
  "${digest_args[@]}" \
  --run-dir "$STATE/run" \
  --image docker.io/library/alpine:3.22 \
  "$@"
