#!/bin/bash
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
tmp=$(mktemp -d /tmp/gyrel-launch.XXXXXXXX)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/tools"
cp "$root/bundle/launcher/gyreld-launch-darwin.sh" "$tmp/bin/gyreld-launch.sh"
printf '#!/bin/sh\nexit 0\n' > "$tmp/tools/mkfs.ext4"
chmod +x "$tmp/tools/mkfs.ext4"
# print-plan layout, proxy-helper name, and digest flags.
PATH="$tmp/tools:$PATH" GYREL_STATE_DIR="$tmp/state" bash "$tmp/bin/gyreld-launch.sh" --print-plan > "$tmp/plan"
grep -Fq 'ROOT=' "$tmp/plan"
grep -Fq "STATE=$tmp/state" "$tmp/plan"
grep -Fq 'LIBKRUN_PATH=' "$tmp/plan"
grep -Fq 'e2fsprogs candidate found:' "$tmp/plan"
grep -Fq 'gyrel-proxy-helper-linux-arm64' "$tmp/plan"
grep -Fq -- '--artifact-digests=' "$tmp/plan"
grep -Fq -- '--runtime-artifact' "$tmp/plan"
# GYREL_STATE_DIR takes precedence over the deprecated RHEIC_STATE_DIR.
PATH="$tmp/tools:$PATH" GYREL_STATE_DIR="$tmp/state" RHEIC_STATE_DIR="$tmp/legacy" bash "$tmp/bin/gyreld-launch.sh" --print-plan > "$tmp/precedence" 2> "$tmp/precedence.err"
grep -Fq "STATE=$tmp/state" "$tmp/precedence"
if grep -Fq "STATE=$tmp/legacy" "$tmp/precedence"; then exit 1; fi
if [ -s "$tmp/precedence.err" ]; then exit 1; fi
# Deprecated RHEIC_STATE_DIR still works as a fallback and emits a warning.
PATH="$tmp/tools:$PATH" RHEIC_STATE_DIR="$tmp/legacy" bash "$tmp/bin/gyreld-launch.sh" --print-plan > "$tmp/fallback" 2> "$tmp/fallback.err"
grep -Fq "STATE=$tmp/legacy" "$tmp/fallback"
grep -Fq 'warning: RHEIC_STATE_DIR is deprecated; use GYREL_STATE_DIR' "$tmp/fallback.err"
# Missing mkfs.ext4 prerequisite fails with the brew hint (PATH restricted).
# The launcher augments PATH from hardcoded Homebrew candidate dirs, so this
# branch is only reproducible on a host without e2fsprogs in those locations.
if [ -x /opt/homebrew/opt/e2fsprogs/sbin/mkfs.ext4 ] || [ -x /usr/local/opt/e2fsprogs/sbin/mkfs.ext4 ]; then
  echo 'SKIP missing-mkfs refusal: e2fsprogs present in a launcher candidate dir'
else
  mkdir "$tmp/missing"
  ln -s "$(command -v dirname)" "$tmp/missing/dirname"
  if PATH="$tmp/missing" GYREL_STATE_DIR="$tmp/state" /bin/bash "$tmp/bin/gyreld-launch.sh" --print-plan >"$tmp/out" 2>&1; then exit 1; fi
  grep -Fq 'brew install e2fsprogs' "$tmp/out"
fi
# Syntax check.
bash -n "$root/bundle/launcher/gyreld-launch-darwin.sh"
platform=darwin
. "$root/scripts/alpha/launcher-boot-controls.sh"
echo 'darwin launcher synthetic checks passed'
