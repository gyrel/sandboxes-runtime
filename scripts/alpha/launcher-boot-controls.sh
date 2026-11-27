# Shared by the two launcher suites. The caller supplies platform, tmp and root.
mkdir -p "$tmp/build" "$tmp/runtime/bin" "$tmp/runtime/assets"
export PATH="$tmp/tools:$PATH"
export GYREL_STATE_DIR="$tmp/state" MARKER="$tmp/containerd.started"
cat > "$tmp/listener.py" <<'PYTHON'
import os, pathlib, socket, sys
path = sys.argv[1]
with socket.socket(socket.AF_UNIX) as server:
    server.bind(path)
    server.listen()
    pathlib.Path(path + '.ready').write_text(str(os.getpid()))
    while True:
        server.accept()[0].close()
PYTHON
cat > "$tmp/runtime/bin/containerd" <<'MARKER'
#!/bin/bash
echo "$$" > "$MARKER"
[ -z "${STOP_BEFORE_BIND:-}" ] || exit 0
if [ -n "${MATRIX_LISTENER:-}" ]; then
  exec python3 "$MATRIX_LISTENER" "$GYREL_STATE_DIR/containerd.sock"
fi
python3 -c 'import os,socket; s=socket.socket(socket.AF_UNIX); s.bind(os.environ["GYREL_STATE_DIR"]+"/containerd.sock")'
MARKER
cat > "$tmp/bin/sandboxesd" <<'MARKER'
#!/bin/bash
printf '%s\n' "$@" > "$MARKER.daemon"
if [ -n "${MATRIX_LISTENER:-}" ]; then
  exec python3 "$MATRIX_LISTENER" "$GYREL_STATE_DIR/sandboxesd.sock"
fi
MARKER
chmod +x "$tmp/runtime/bin/containerd" "$tmp/bin/sandboxesd"
for name in ctr containerd-shim-nerdbox-v1 gvproxy; do echo "$name" > "$tmp/runtime/bin/$name"; done
for name in nerdbox-kernel-arm64 nerdbox-rootfs-arm64.erofs; do echo "$name" > "$tmp/runtime/assets/$name"; done
python3 - "$tmp" <<'PY'
import pathlib, hashlib, json, sys
root = pathlib.Path(sys.argv[1])
entries = []
lines = ['artifacts:']
for path in sorted((root / 'runtime').glob('*/*')):
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    name = {'nerdbox-kernel-arm64': 'kernel', 'nerdbox-rootfs-arm64.erofs': 'guest-rootfs'}.get(path.name, path.name)
    lines.append(f'    {name}: sha256:{digest}')
    entries.append(dict(path=str(path.relative_to(root)), kind='bin' if path.parent.name == 'bin' else 'asset', sha256=digest))
(root / 'build/digests.yaml').write_text('\n'.join(lines) + '\n')
(root / 'RUNTIME-ARTIFACTS.json').write_text(json.dumps(dict(artifacts=entries)))
PY
# The Linux launcher requires root. Keep simulated socket metadata consistent
# with the simulated current uid. The actual socket belongs to the test user.
if [ "$platform" = linux ]; then
  printf '#!/bin/sh\necho 0\n' > "$tmp/tools/id"
  printf '#!/bin/sh\n[ "$1" = -c%%u ] && echo 0\n' > "$tmp/tools/stat"
  chmod +x "$tmp/tools/id" "$tmp/tools/stat"
elif [ "$(uname -s)" != Darwin ]; then
  printf '#!/bin/sh\n[ "$1" = -f%%u ] && exec /usr/bin/stat -c%%u "$2"\n' > "$tmp/tools/stat"
  chmod +x "$tmp/tools/stat"
fi
launch() { bash "$tmp/bin/gyreld-launch.sh" "$@"; }
refuses() {
  local rc=0
  launch > "$tmp/out" 2>&1 || rc=$?
  [ "$rc" -eq 1 ]
}
cp "$tmp/runtime/bin/containerd" "$tmp/good"
echo '# tampered' >> "$tmp/runtime/bin/containerd"
refuses
grep -Fq 'artifact pre-verify failed: containerd [digest mismatch]' "$tmp/out"
[ ! -e "$MARKER" ] && [ ! -e "$GYREL_STATE_DIR" ] || exit 1
echo 'PASS tampered containerd refused before state or execution'
cp "$tmp/good" "$tmp/runtime/bin/containerd"
# Isolate acceptance of the restored bytes from host permission to bind.
mkdir "$tmp/fast"
printf '#!/bin/sh\nexec /bin/sleep 0.1\n' > "$tmp/fast/sleep"
chmod +x "$tmp/fast/sleep"
STOP_BEFORE_BIND=1 PATH="$tmp/fast:$PATH" refuses
grep -Fq 'containerd failed to start' "$tmp/out"
cmp "$GYREL_STATE_DIR/containerd.pid" "$MARKER"
echo 'PASS restored digest reaches containerd bootstrap and records its PID'
rm "$MARKER"
sock="$GYREL_STATE_DIR/containerd.sock"
python3 - "$sock" "$platform" <<'PY'
import socket, sys
for path in [sys.argv[1]] + ([sys.argv[1] + '.ttrpc'] if sys.argv[2] == 'darwin' else []):
    with socket.socket(socket.AF_UNIX) as s:
        s.bind(path)
PY
launch
[ -S "$sock" ]
[ ! -e "$sock.ttrpc" ]
cmp "$GYREL_STATE_DIR/containerd.pid" "$MARKER"
grep -Fxq -- "--artifact-digests=$tmp/build/digests.yaml" "$MARKER.daemon"
echo 'PASS matching digests, dead socket recovery, PID recording and daemon handoff'
rm "$sock" "$MARKER" "$MARKER.daemon"
python3 - "$sock" <<'PY' &
import socket, sys
with socket.socket(socket.AF_UNIX) as listener:
    listener.bind(sys.argv[1])
    listener.listen()
    while True:
        listener.accept()[0].close()
PY
listener=$!
trap 'kill "$listener" 2>/dev/null || true; wait "$listener" 2>/dev/null || true; rm -rf "$tmp"' EXIT
for _ in {1..50}; do [ -S "$sock" ] && break; sleep 0.1; done
[ -S "$sock" ]
echo "$listener" > "$GYREL_STATE_DIR/containerd.pid"
refuses
grep -Fq 'live listener with unverified provenance' "$tmp/out"
[ -S "$sock" ]
kill -0 "$listener"
[ ! -e "$MARKER" ] && [ ! -e "$MARKER.daemon" ] || exit 1
echo 'PASS live foreign listener preserved and launch refused'

kill "$listener"
wait "$listener" 2>/dev/null || true
rm "$sock"
daemon_sock="$GYREL_STATE_DIR/sandboxesd.sock"
daemon_pid=
containerd_pid=
foreign_pid=
cleanup_matrix() {
  for pid in "$daemon_pid" "$containerd_pid" "$foreign_pid"; do
    [ -z "$pid" ] || kill "$pid" 2>/dev/null || true
  done
  rm -rf "$tmp"
}
trap cleanup_matrix EXIT
start_pair() {
  MATRIX_LISTENER="$tmp/listener.py" bash "$tmp/bin/gyreld-launch.sh" &
  daemon_pid=$!
  for _ in {1..100}; do [ -s "$daemon_sock.ready" ] && break; sleep 0.1; done
  containerd_pid=$(cat "$MARKER")
  cmp "$MARKER" "$GYREL_STATE_DIR/containerd.pid"
  [ "$(cat "$sock.ready")" = "$containerd_pid" ]
  [ "$(cat "$daemon_sock.ready")" = "$daemon_pid" ]
}
kill_pair() {
  kill -KILL "$containerd_pid" "$daemon_pid"
  wait "$daemon_pid" 2>/dev/null || true
  containerd_pid=
  daemon_pid=
  rm "$sock.ready" "$daemon_sock.ready"
}
start_pair
old_pid=$containerd_pid
kill_pair
[ -S "$sock" ] && [ -S "$daemon_sock" ] || exit 1
start_pair
[ "$containerd_pid" != "$old_pid" ]
echo 'PASS dual SIGKILL: fresh markers bound both stale paths and containerd.pid updated'
kill_pair
rm "$daemon_sock" "$MARKER.daemon"
python3 "$tmp/listener.py" "$daemon_sock" &
foreign_pid=$!
for _ in {1..50}; do [ -s "$daemon_sock.ready" ] && break; sleep 0.1; done
[ "$(cat "$daemon_sock.ready")" = "$foreign_pid" ]
refuses
grep -Fq 'daemon endpoint live with unverified provenance' "$tmp/out"
[ ! -e "$MARKER.daemon" ]
python3 -c 'import socket, sys; s = socket.socket(socket.AF_UNIX); s.settimeout(1); s.connect(sys.argv[1])' "$daemon_sock"
kill -0 "$foreign_pid"
echo 'PASS foreign live daemon endpoint: rc=1 and listener still accepts connections'
