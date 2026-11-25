#!/bin/sh
# Regenerate build/digests.yaml from a verified runtime artifact set.
#
# Usage:
#   scripts/update-artifact-digests.sh NAME=/absolute/path [NAME=/absolute/path ...]
#
# Example:
#   scripts/update-artifact-digests.sh \
#     containerd-shim-nerdbox-v1=/opt/gyrel/bin/containerd-shim-nerdbox-v1 \
#     gvproxy=/opt/gyrel/bin/gvproxy \
#     qemu=/opt/gyrel/bin/qemu-system-x86_64
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ "$#" -eq 0 ]; then
  echo "usage: $0 NAME=/absolute/path [NAME=/absolute/path ...]" >&2
  exit 2
fi
exec env GOWORK=off go run "$ROOT/internal/artifact/cmd/artifact-digests" \
  -manifest "${MANIFEST:-$ROOT/build/manifest.yaml}" \
  -out "${OUT:-$ROOT/build/digests.yaml}" \
  "$@"
