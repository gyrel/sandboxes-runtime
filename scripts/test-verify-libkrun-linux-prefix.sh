#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
mkdir -p "$WORK/lib64" "$WORK/share/rheic-runtime"
printf 'libkrun fixture\n' > "$WORK/lib64/libkrun.so.1.19.6"
printf 'libkrunfw fixture\n' > "$WORK/lib64/libkrunfw.so.5.6.2"
printf 'kernel fixture\n' > "$WORK/nerdbox-kernel-arm64"
sha() { shasum -a 256 "$1" | awk '{print $1}'; }
cat > "$WORK/share/rheic-runtime/libkrun-linux-arm64-build-info" <<INFO
libkrun_version=1.19.6
libkrun_commit=227b2de6ed323fe180e02f871c5f325a90c13cc2
libkrunfw_version=5.6.2
libkrunfw_commit=f14ac64ca8a04c6c9d76cac1c61ee050809c88c9
kernel_version=linux-6.12.109
kernel_sha256=5484e552a334e15019f4aeba89e5b58f04651cf2f4e24e04de9f152f1c38e3fa
kernel_netfilter_patch_sha256=f777d97980fb467c2eb14ac1e2de99e7a663257a5252c92e5fb894bb2cfe8d7b
rustc_version=1.90.0
gcc_version=13.3.0
libkrun_sha256=$(sha "$WORK/lib64/libkrun.so.1.19.6")
libkrunfw_sha256=$(sha "$WORK/lib64/libkrunfw.so.5.6.2")
kernel_image_sha256=$(sha "$WORK/nerdbox-kernel-arm64")
INFO
verify() { "$ROOT/scripts/verify-libkrun-linux-prefix.sh" "$WORK"; }
verify
printf 'tamper\n' >> "$WORK/lib64/libkrun.so.1.19.6"
if verify 2>/dev/null; then echo 'tampered library accepted' >&2; exit 1; fi
printf 'libkrun fixture\n' > "$WORK/lib64/libkrun.so.1.19.6"
rm "$WORK/nerdbox-kernel-arm64"
if verify 2>/dev/null; then echo 'missing kernel accepted' >&2; exit 1; fi
printf 'kernel fixture\n' > "$WORK/nerdbox-kernel-arm64"
printf 'libkrun_version=foreign\n' >> "$WORK/share/rheic-runtime/libkrun-linux-arm64-build-info"
if verify 2>/dev/null; then echo 'foreign metadata accepted' >&2; exit 1; fi
printf 'PASS: Linux prefix verification and three rejection cases\n'
