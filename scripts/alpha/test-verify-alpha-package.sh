#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT HUP INT TERM
export WORK ROOT
python3 -I - <<'PY'
import os, pathlib, hashlib, json
w=pathlib.Path(os.environ['WORK'])
r=w/'gyrel-sandboxes-alpha-linux-arm64'
names=['README-ALPHA.md','bin/gyreld-launch.sh','bin/rsbx','bin/sandboxesd','build/manifest.yaml','build/patches/a.patch','runtime/assets/nerdbox-kernel-arm64','runtime/assets/nerdbox-rootfs-arm64.erofs']+['runtime/bin/'+x for x in ['containerd','ctr','containerd-shim-nerdbox-v1','gvproxy']]+['runtime/lib/libkrun.so.1.19.6','runtime/lib/libkrunfw.so.5.6.2']
for n in names:
 p=r/n;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(n+'\n')
h=lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
(r/'build/digests.yaml').write_text('version: 1\nmanifest_sha256: '+h(r/'build/manifest.yaml')+'\npatches:\n    a:\n        file: patches/a.patch\n        sha256: '+h(r/'build/patches/a.patch')+'\nartifacts:\n'+''.join('    '+n+': sha256:'+h(r/'runtime/bin'/n)+'\n' for n in ['gvproxy','containerd-shim-nerdbox-v1']))
entries=[{'path':str(p.relative_to(r/'runtime')),'sha256':h(p),'size':p.stat().st_size,'component':'fixture'} for p in sorted((r/'runtime').rglob('*')) if p.is_file()]
(r/'runtime/bundle.json').write_text(json.dumps({'platform':'linux/arm64','files':entries}))
(r/'SHA256SUMS').write_text(''.join(h(p)+'  '+str(p.relative_to(r))+'\n' for p in sorted(r.rglob('*')) if p.is_file()))
PY
B="$WORK/gyrel-sandboxes-alpha-linux-arm64"
python3 -I "$ROOT/scripts/alpha/verify-alpha-package.py" "$B"
python3 -I "$ROOT/scripts/alpha/verify-alpha-package.py" "$B"
# Positive control for check mode on the canonical (regenerated) inventories.
python3 -I "$ROOT/scripts/alpha/verify-alpha-package.py" "$B" --check
cp -R "$B" "$WORK/golden"
reject() {
 if python3 -I "$ROOT/scripts/alpha/verify-alpha-package.py" "$B" >"$WORK/out" 2>&1; then echo "FAIL: $1 accepted" >&2; exit 1; fi
 printf 'PASS: rejected %s\n' "$1"
 rm -rf "$B"; cp -R "$WORK/golden" "$B"
}
reject_check() {
 if python3 -I "$ROOT/scripts/alpha/verify-alpha-package.py" "$B" --check >"$WORK/out" 2>&1; then echo "FAIL: check mode accepted $1" >&2; exit 1; fi
 printf 'PASS: rejected in check mode %s\n' "$1"
 rm -rf "$B"; cp -R "$WORK/golden" "$B"
}
grep -v '  SYMLINKS.txt$' "$WORK/golden/SHA256SUMS" > "$B/SHA256SUMS"; reject_check 'SYMLINKS uncovered in sums'
printf 'x' >> "$B/SYMLINKS.txt"; reject 'non-empty SYMLINKS.txt'
printf tamper >> "$B/runtime/bin/ctr"; reject 'digest tamper'
rm "$B/runtime/bin/ctr"; reject 'missing artifact'
printf '%064d  /absolute\n' 0 >> "$B/SHA256SUMS"; reject 'absolute path'
printf x > "$B/._junk"; reject 'AppleDouble'
ln -s /etc/passwd "$B/link"; reject 'symlink'
python3 -I - "$B/runtime/bundle.json" <<'PY'
import json,sys
p=sys.argv[1]; x=json.load(open(p)); x['platform']='darwin/arm64'; open(p,'w').write(json.dumps(x))
PY
reject 'platform mismatch'
mv "$B" "$WORK/unsafe"
if python3 -I "$ROOT/scripts/alpha/verify-alpha-package.py" "$WORK/unsafe" > /dev/null 2>&1; then echo 'FAIL: unsafe name accepted' >&2; exit 1; fi
printf 'PASS: rejected unsafe name\n'
