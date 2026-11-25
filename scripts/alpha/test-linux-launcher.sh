#!/bin/bash
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/build" "$tmp/runtime/bin" "$tmp/tools"
cp "$root/bundle/launcher/gyreld-launch-linux.sh" "$tmp/bin/gyreld-launch.sh"
printf '#!/bin/sh\nexit 0\n' > "$tmp/tools/mkfs.ext4"
chmod +x "$tmp/tools/mkfs.ext4"
printf 'artifacts:\n    containerd: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' > "$tmp/build/digests.yaml"
printf '%s\n' '{"artifacts":[{"path":"runtime/bin/containerd","kind":"bin","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}' > "$tmp/RUNTIME-ARTIFACTS.json"
PATH="$tmp/tools:$PATH" GYREL_STATE_DIR="$tmp/state" bash "$tmp/bin/gyreld-launch.sh" --print-plan > "$tmp/plan"
grep -q -- '--runtime-artifact' "$tmp/plan"
grep -q 'socket budget: OK' "$tmp/plan"
# GYREL_STATE_DIR takes precedence over the deprecated RHEIC_STATE_DIR.
PATH="$tmp/tools:$PATH" GYREL_STATE_DIR="$tmp/state" RHEIC_STATE_DIR="$tmp/legacy" bash "$tmp/bin/gyreld-launch.sh" --print-plan > "$tmp/precedence" 2> "$tmp/precedence.err"
grep -Fq "STATE=$tmp/state" "$tmp/precedence"
if grep -Fq "STATE=$tmp/legacy" "$tmp/precedence"; then exit 1; fi
if [ -s "$tmp/precedence.err" ]; then exit 1; fi
# Deprecated RHEIC_STATE_DIR still works as a fallback and emits a note.
PATH="$tmp/tools:$PATH" RHEIC_STATE_DIR="$tmp/legacy" bash "$tmp/bin/gyreld-launch.sh" --print-plan > "$tmp/fallback" 2> "$tmp/fallback.err"
grep -Fq "STATE=$tmp/legacy" "$tmp/fallback"
grep -Fq 'RHEIC_STATE_DIR is deprecated' "$tmp/fallback.err"
long=$(printf '%090d' 0)
if PATH="$tmp/tools:$PATH" GYREL_STATE_DIR="$tmp/$long" bash "$tmp/bin/gyreld-launch.sh" --print-plan >"$tmp/out" 2>&1; then exit 1; fi
grep -q 'shorter absolute path' "$tmp/out"
# Limit PATH to the commands needed before the mkfs probe.
mkdir "$tmp/missing"
for command in dirname id; do ln -s "$(command -v "$command")" "$tmp/missing/$command"; done
if PATH="$tmp/missing" GYREL_STATE_DIR="$tmp/state" /bin/bash "$tmp/bin/gyreld-launch.sh" --print-plan >"$tmp/out" 2>&1; then exit 1; fi
grep -q 'Debian/Ubuntu: e2fsprogs' "$tmp/out"
if [ "$(id -u)" -ne 0 ]; then
  if PATH="$tmp/tools:$PATH" GYREL_STATE_DIR="$tmp/state" bash "$tmp/bin/gyreld-launch.sh" >"$tmp/out" 2>&1; then exit 1; fi
  grep -Fxq 'rootless is unsupported in this pinned alpha: loop-device access and containerd rootless support remain open (PLAN §5.7)' "$tmp/out"
else
  echo 'SKIP rootless refusal: test runs as root'
fi
echo 'linux launcher synthetic checks passed'
