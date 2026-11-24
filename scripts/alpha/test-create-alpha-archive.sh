#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
# Reuse the synthetic fixture generator without its cleanup or rejection cases.
sed '/^B="\$WORK\/rheic-sandboxes-alpha-linux-arm64"/,$d' "$ROOT/scripts/alpha/test-verify-alpha-package.sh" | sed '/^WORK=$(mktemp -d)/d; /^trap /d; /^ROOT=/d' > "$WORK/fixture.sh"
export ROOT WORK
. "$WORK/fixture.sh"
B="$WORK/rheic-sandboxes-alpha-linux-arm64"
python3 -I "$ROOT/scripts/alpha/verify-alpha-package.py" "$B"
python3 -I "$ROOT/scripts/alpha/create-alpha-archive.py" "$B" "$WORK/one.tar.gz"
python3 -I "$ROOT/scripts/alpha/create-alpha-archive.py" "$B" "$WORK/two.tar.gz"
cmp "$WORK/one.tar.gz" "$WORK/two.tar.gz"
# Published-alpha layout: single top-level directory inside the archive.
test "$(tar tzf "$WORK/one.tar.gz" | head -n 1)" = "rheic-sandboxes-alpha-linux-arm64/"
test "$(cut -d ' ' -f1 "$WORK/one.tar.gz.sha256")" = "$(cut -d ' ' -f1 "$WORK/two.tar.gz.sha256")"
printf 'PASS: deterministic archive and checksum\n'
