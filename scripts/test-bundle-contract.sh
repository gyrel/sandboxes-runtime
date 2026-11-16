#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/rheic-runtime-bundle-contract.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT INT TERM

root="$tmp/linux-arm64"
mkdir -p "$root/bin"
printf 'synthetic shim fixture\n' > "$root/bin/shim"

cd "$repo"
go run ./cmd/runtime-bundle manifest \
  --root "$root" \
  --platform linux/arm64 \
  --completeness partial \
  --file nerdbox-shim=bin/shim
go run ./cmd/runtime-bundle verify --root "$root" --platform linux/arm64 --allow-partial

if go run ./cmd/runtime-bundle verify --root "$root" --platform darwin/arm64 --allow-partial; then
  echo "wrong-platform bundle was accepted" >&2
  exit 1
fi
if go run ./cmd/runtime-bundle verify --root "$root" --platform linux/arm64; then
  echo "partial bundle was accepted without explicit opt-in" >&2
  exit 1
fi

printf 'tampered shim fixture\n' > "$root/bin/shim"
if go run ./cmd/runtime-bundle verify --root "$root" --platform linux/arm64 --allow-partial; then
  echo "modified artifact was accepted" >&2
  exit 1
fi

printf 'synthetic shim fixture\n' > "$root/bin/shim"
rm "$root/bin/shim"
if go run ./cmd/runtime-bundle verify --root "$root" --platform linux/arm64 --allow-partial; then
  echo "missing artifact was accepted" >&2
  exit 1
fi
