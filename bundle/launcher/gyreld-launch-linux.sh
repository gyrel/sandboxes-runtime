#!/bin/bash
# Linux sibling of the published Darwin launcher. It is kept separate because
# that launcher is a published bundle artifact, not a source file in this tree;
# Linux adds rootless and socket-budget checks and discovers digest arguments.
# Development only: pass --allow-unmanaged-runtime first to skip pre-verification and daemon digest checks.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ -n "${GYREL_STATE_DIR:-}" ]; then
  STATE=$GYREL_STATE_DIR
elif [ -n "${RHEIC_STATE_DIR:-}" ]; then
  STATE=$RHEIC_STATE_DIR
  echo 'RHEIC_STATE_DIR is deprecated; set GYREL_STATE_DIR instead' >&2
else
  STATE=$HOME/.sandboxes
fi
UID_NOW=$(id -u)
GID_NOW=$(id -g)
SOCKET="$STATE/containerd.sock"
MANAGED="/tmp/.rsbx-$UID_NOW/h-0000000000000000.sock.ttrpc"
export LIBKRUN_PATH="$ROOT/runtime/assets:$ROOT/runtime/lib:$ROOT/runtime/bin"
# Byte count, including the longest actual state-local endpoint, not characters.
export LC_ALL=C
for endpoint in "$MANAGED" "$SOCKET.ttrpc" "$STATE/sandboxesd.sock"; do
  if [ "${#endpoint}" -ge 100 ]; then
    echo "AF_UNIX socket path exceeds the 99-byte budget; set GYREL_STATE_DIR to a shorter absolute path: $endpoint" >&2
    exit 1
  fi
done
case "$STATE" in /*) ;; *) echo 'GYREL_STATE_DIR must be an absolute path' >&2; exit 1;; esac
if ! command -v mkfs.ext4 >/dev/null 2>&1; then
  echo 'missing prerequisite mkfs.ext4; install e2fsprogs (Debian/Ubuntu: e2fsprogs; Fedora/RHEL: e2fsprogs; Arch: e2fsprogs) and include /usr/sbin in PATH' >&2
  exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
  echo 'missing prerequisite python3 (required for managed artifact pre-verification and socket checks)' >&2
  exit 1
fi
preverify_artifacts() {
  python3 - "$ROOT" "$1" <<'PYTHON'
import json
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1])
verify = sys.argv[2] == 'verify'
name = 'artifacts'
try:
    paths = {}
    for item in json.loads((root / 'RUNTIME-ARTIFACTS.json').read_text())['artifacts']:
        path = item['path']
        if item['kind'] not in ('bin', 'asset') or not path.startswith('runtime/'):
            continue
        if '..' in pathlib.PurePosixPath(path).parts or '\n' in path:
            raise ValueError('unsafe artifact path')
        paths.setdefault(item['sha256'], []).append(path)
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
        matches = paths.get(digest, [])
        if len(matches) != 1:
            raise ValueError('missing or ambiguous inventory mapping')
        path = matches[0]
        if name == 'containerd' and path != 'runtime/bin/containerd':
            raise ValueError('unexpected containerd path')
        if verify:
            if not (root / path).is_file():
                raise ValueError('missing or non-regular file')
            with (root / path).open('rb') as artifact:
                actual = subprocess.check_output(['sha256sum'], stdin=artifact).split()[0].decode()
            if actual != digest:
                raise ValueError('digest mismatch')
        print(f'{name}={root / path}')
    missing = {'containerd'} - seen
    if missing:
        name = sorted(missing)[0]
        raise ValueError('missing digest')
except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
    sys.exit(f'artifact pre-verify failed: {name} [{error}]')
PYTHON
}
if [ "${1:-}" = --print-plan ]; then
  mappings=$(preverify_artifacts plan)
  while IFS= read -r artifact; do set -- "$@" --runtime-artifact "$artifact"; done <<< "$mappings"
  shift
  printf 'ROOT=%s\nSTATE=%s\nLIBKRUN_PATH=%s\nmanaged socket budget: OK (%s bytes)\nstate socket budget: OK (%s bytes)\n' "$ROOT" "$STATE" "$LIBKRUN_PATH" "${#MANAGED}" "${#SOCKET}"
  printf '%s\n' "--state" "$STATE" "--socket" "$STATE/sandboxesd.sock" "--containerd" "$SOCKET" "--ctr" "$ROOT/runtime/bin/ctr" "--gvproxy" "$ROOT/runtime/bin/gvproxy" "--proxy-helper" "$ROOT/bin/gyrel-proxy-helper-linux-arm64" "--artifact-digests=$ROOT/build/digests.yaml" "--run-dir" "$STATE/run" "--image" 'docker.io/library/alpine:3.22' "$@"
  exit 0
fi
if [ "$UID_NOW" -ne 0 ]; then
  echo 'rootless is unsupported in this pinned alpha: loop-device access and containerd rootless support remain open (PLAN §5.7)' >&2
  exit 1
fi
digest_args=()
if [ "${1:-}" = --allow-unmanaged-runtime ]; then
  shift
  digest_args+=(--allow-unmanaged-runtime)
else
  mappings=$(preverify_artifacts verify)
  digest_args+=("--artifact-digests=$ROOT/build/digests.yaml")
  while IFS= read -r artifact; do digest_args+=(--runtime-artifact "$artifact"); done <<< "$mappings"
fi
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
        same_owner = subprocess.check_output(['stat', '-c%u', endpoint], text=True).strip() == uid
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
umask 077
mkdir -p "$STATE"
if [ "$socket_action" = bootstrap ]; then
  cat > "$STATE/containerd.toml" <<TOML
version = 3
[plugins.'io.containerd.server.v1.grpc']
  address = "$SOCKET"
  uid = $UID_NOW
  gid = $GID_NOW
[plugins.'io.containerd.server.v1.ttrpc']
  address = "$SOCKET.ttrpc"
  uid = $UID_NOW
  gid = $GID_NOW
[plugins.'io.containerd.snapshotter.v1.erofs']
  default_size = "64M"
[plugins.'io.containerd.differ.v1.erofs']
  mkfs_options = ['-b4096']
TOML
  nohup "$ROOT/runtime/bin/containerd" --config "$STATE/containerd.toml" --root "$STATE/containerd-root" --state "$STATE/containerd-state" >> "$STATE/containerd.log" 2>&1 &
  echo "$!" > "$STATE/containerd.pid"
  for _ in 1 2 3 4 5 6 7 8 9 10; do [ -S "$SOCKET" ] && break; sleep 1; done
  [ -S "$SOCKET" ] || { echo "containerd failed to start; see $STATE/containerd.log" >&2; exit 1; }
fi
daemon_socket="$STATE/sandboxesd.sock"
if [ -e "$daemon_socket" ] || [ -L "$daemon_socket" ]; then
  check_socket "$daemon_socket" daemon > /dev/null
fi
exec "$ROOT/bin/sandboxesd" --state "$STATE" --socket "$STATE/sandboxesd.sock" --containerd "$SOCKET" --ctr "$ROOT/runtime/bin/ctr" --gvproxy "$ROOT/runtime/bin/gvproxy" --proxy-helper "$ROOT/bin/gyrel-proxy-helper-linux-arm64" "${digest_args[@]}" --run-dir "$STATE/run" --image docker.io/library/alpine:3.22 "$@"
