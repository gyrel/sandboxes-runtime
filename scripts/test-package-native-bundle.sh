#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
mkdir -p "$WORK/bundle/bin"
printf '{}\n' > "$WORK/bundle/bundle.json"
printf 'payload\n' > "$WORK/bundle/bin/shim"
chmod 0755 "$WORK/bundle/bin/shim"

python3 "$ROOT/scripts/package-native-bundle.py" --root "$WORK/bundle" --out "$WORK/one.tar.gz"
python3 "$ROOT/scripts/package-native-bundle.py" --root "$WORK/bundle" --out "$WORK/two.tar.gz"
cmp "$WORK/one.tar.gz" "$WORK/two.tar.gz"

if python3 "$ROOT/scripts/package-native-bundle.py" --root "$WORK/bundle" --out "$WORK/one.tar.gz" 2>/dev/null; then
  echo 'archive overwrite accepted' >&2
  exit 1
fi
ln -s /etc/passwd "$WORK/bundle/escape"
if python3 "$ROOT/scripts/package-native-bundle.py" --root "$WORK/bundle" --out "$WORK/three.tar.gz" 2>/dev/null; then
  echo 'bundle symlink accepted' >&2
  exit 1
fi
test ! -e "$WORK/three.tar.gz"
printf 'PASS: deterministic archive, overwrite and symlink controls\n'
