#!/usr/bin/env python3
"""Validate an alpha staging tree and write its derived inventories."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

CONTROL = {'SHA256SUMS', 'SYMLINKS.txt', 'RUNTIME-ARTIFACTS.json'}
MATRIX = {'darwin/arm64': ('libkrun.dylib', 'libkrunfw.5.dylib'),
          'linux/arm64': ('libkrun.so.1.19.6', 'libkrunfw.so.5.6.2')}

def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def safe(name):
    p = PurePosixPath(name)
    if not name or p.is_absolute() or any(x in ('', '.', '..') for x in name.split('/')) or '\\' in name or '\n' in name:
        raise ValueError(f'path: unsafe {name!r}')
    if any(x.startswith('._') for x in p.parts):
        raise ValueError(f'path: AppleDouble {name!r}')
    return name

def verify(root, write=True):
    if root.is_symlink() or not root.is_dir():
        raise ValueError('root: expected real directory')
    match = re.fullmatch(r'rheic-sandboxes-alpha-([a-z0-9]+)-([a-z0-9]+)', root.name)
    if not match:
        raise ValueError('root: unsafe directory name')
    platform = '/'.join(match.groups())
    if platform not in MATRIX:
        raise ValueError(f'platform: unsupported {platform}')
    files = {}
    for base, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            path = Path(base) / name
            rel = safe(path.relative_to(root).as_posix())
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                raise ValueError(f'symlinks: {rel} mode={stat.S_IMODE(info.st_mode):04o} (alpha requires zero)')
            if stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise ValueError(f'hardlink: {rel}')
                if info.st_size == 0 and rel not in CONTROL:
                    raise ValueError(f'size: {rel} must be positive')
                files[rel] = path
            elif not stat.S_ISDIR(info.st_mode):
                raise ValueError(f'type: unsupported {rel}')
    required = ['README-ALPHA.md', 'bin/rheicd-launch.sh', 'bin/rsbx', 'bin/sandboxesd',
                'build/manifest.yaml', 'build/digests.yaml', 'runtime/bundle.json',
                'runtime/assets/nerdbox-kernel-arm64', 'runtime/assets/nerdbox-rootfs-arm64.erofs']
    required += ['runtime/bin/' + n for n in ('containerd', 'ctr', 'containerd-shim-nerdbox-v1', 'gvproxy')]
    required += ['runtime/lib/' + n for n in MATRIX[platform]]
    for name in required:
        if name not in files:
            raise ValueError(f'artifacts: missing {name}')
    patches = sorted(n for n in files if n.startswith('build/patches/') and n.endswith('.patch'))
    if not patches:
        raise ValueError('build_refs.patches: missing patches')
    bundle = json.loads(files['runtime/bundle.json'].read_text())
    if bundle.get('platform') != platform:
        raise ValueError(f'runtime/bundle.json.platform: expected {platform}')
    declared = set()
    for entry in bundle.get('files', []):
        name = 'runtime/' + safe(entry['path'])
        if name in declared or name not in files:
            raise ValueError(f'runtime/bundle.json.files: duplicate or missing {name}')
        declared.add(name)
        if digest(files[name]) != entry.get('sha256') or files[name].stat().st_size != entry.get('size'):
            raise ValueError(f'runtime/bundle.json.files: digest or size mismatch {name}')
    expected = {n for n in files if n.startswith('runtime/') and n != 'runtime/bundle.json'}
    if declared != expected or not set(required).intersection(expected).issubset(declared):
        raise ValueError(f'runtime/bundle.json.files: inventory mismatch {sorted(expected ^ declared)}')
    # digests.yaml is generated in a deliberately narrow, line-oriented format.
    lines = files['build/digests.yaml'].read_text().splitlines()
    manifest_hash = None
    section = None
    patch_file = None
    recorded_patches = set()
    artifact_hashes = {}
    for line in lines:
        if line.startswith('manifest_sha256: '): manifest_hash = line.split(': ', 1)[1]
        elif line in ('patches:', 'artifacts:'): section = line[:-1]
        elif section == 'patches' and re.fullmatch(r'        file: \S+', line): patch_file = line.strip().split(': ', 1)[1]
        elif section == 'patches' and re.fullmatch(r'        sha256: [0-9a-f]{64}', line):
            if not patch_file: raise ValueError('digests.yaml.patches: missing file')
            name = 'build/' + safe(patch_file)
            if name not in patches or digest(files[name]) != line.strip().split(': ', 1)[1]: raise ValueError(f'digests.yaml.patches: mismatch {name}')
            recorded_patches.add(name)
            patch_file = None
        elif section == 'artifacts':
            m = re.fullmatch(r'    ([A-Za-z0-9_.-]+): sha256:([0-9a-f]{64})', line)
            if m: artifact_hashes[m.group(1)] = m.group(2)
    if manifest_hash != digest(files['build/manifest.yaml']): raise ValueError('digests.yaml.manifest_sha256: mismatch')
    if recorded_patches != set(patches) or patch_file: raise ValueError('digests.yaml.patches: inventory mismatch')
    artifact_paths = {'containerd': 'runtime/bin/containerd', 'ctr': 'runtime/bin/ctr', 'containerd-shim-nerdbox-v1': 'runtime/bin/containerd-shim-nerdbox-v1', 'gvproxy': 'runtime/bin/gvproxy', 'kernel': 'runtime/assets/nerdbox-kernel-arm64', 'guest-rootfs': 'runtime/assets/nerdbox-rootfs-arm64.erofs'}
    for name in ('containerd-shim-nerdbox-v1', 'gvproxy'):
        if name not in artifact_hashes: raise ValueError(f'digests.yaml.artifacts.{name}: missing')
    for name, value in artifact_hashes.items():
        if name not in artifact_paths or value != digest(files[artifact_paths[name]]): raise ValueError(f'digests.yaml.artifacts.{name}: mismatch or unsupported')
    sums_path = root / 'SHA256SUMS'
    if not sums_path.is_file():
        raise ValueError('SHA256SUMS: missing input inventory')
    sums = {}
    for line in sums_path.read_text().splitlines():
        m = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not m:
            raise ValueError(f'SHA256SUMS: invalid line {line!r}')
        name = m.group(2)
        if name.startswith('./'):
            name = name[2:]
        safe(name)
        if name in sums or name in ('SHA256SUMS', 'RUNTIME-ARTIFACTS.json'):
            raise ValueError(f'SHA256SUMS: duplicate or forbidden {name}')
        sums[name] = m.group(1)
    payload = set(files) - CONTROL
    if write:
        if set(sums) - {'SYMLINKS.txt'} != payload:
            raise ValueError(f'SHA256SUMS: inventory mismatch {sorted((set(sums) - {"SYMLINKS.txt"}) ^ payload)}')
    elif set(sums) != payload | {'SYMLINKS.txt'}:
        raise ValueError(f'SHA256SUMS: coverage mismatch {sorted((set(sums) ^ payload) - {"SYMLINKS.txt"})}')
    for name, value in sums.items():
        if name == 'SYMLINKS.txt' and write and name not in files:
            continue  # regenerated below in write mode
        if name not in files or digest(files[name]) != value:
            raise ValueError(f'SHA256SUMS: digest mismatch {name}')
    def kind(n):
        if n.startswith(('bin/', 'runtime/bin/')): return 'bin'
        if n.startswith(('runtime/assets/', 'runtime/lib/')): return 'asset'
        if n.endswith('.md'): return 'doc'
        return 'config'
    artifacts = [{'path': n, 'sha256': digest(files[n]), 'size': files[n].stat().st_size, 'kind': kind(n)} for n in sorted(payload)]
    metadata = {'schema_version': 1, 'platform': platform, 'artifacts': artifacts,
                'build_refs': {'manifest.yaml': 'build/manifest.yaml', 'digests.yaml': 'build/digests.yaml', 'patches': patches},
                'limits': ['Alpha permits no symbolic links or hard links.', 'Checksums are not provenance; staging must be private and quiescent.', 'Platform labels do not prove binary compatibility or live execution.']}
    encoded = json.dumps(metadata, indent=2) + '\n'
    if 'RUNTIME-ARTIFACTS.json' in files and files['RUNTIME-ARTIFACTS.json'].read_text() != encoded:
        raise ValueError('RUNTIME-ARTIFACTS.json: metadata mismatch')
    if 'SYMLINKS.txt' in files and files['SYMLINKS.txt'].read_text() != '':
        raise ValueError('SYMLINKS.txt: alpha requires zero links')
    if write:
        (root / 'SYMLINKS.txt').write_text('')
        (root / 'RUNTIME-ARTIFACTS.json').write_text(encoded)
        sums_names = sorted(payload | {'SYMLINKS.txt'})
        canonical = ''.join((f'{digest(root / n)}  {n}\n' if n not in files else f'{digest(files[n])}  {n}\n') for n in sums_names)
        sums_path.write_text(canonical)
    elif sums_path.read_text() != ''.join(f'{digest(files[n])}  {n}\n' for n in sorted(payload | {'SYMLINKS.txt'})) or 'RUNTIME-ARTIFACTS.json' not in files or 'SYMLINKS.txt' not in files:
        raise ValueError('verification: generated inventories missing or noncanonical')
    return metadata

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('--check', action='store_true', help='verify existing inventories without writing (published-bundle layout)')
    args = p.parse_args()
    try:
        verify(args.root, write=not args.check)
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f'alpha verification failed: {exc}', file=sys.stderr)
        return 1
    print('alpha package verified')
    return 0

if __name__ == '__main__':
    sys.exit(main())
