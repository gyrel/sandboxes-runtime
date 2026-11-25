#!/usr/bin/env python3
"""Reverify and archive a private alpha staging tree reproducibly."""
import argparse
import gzip
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile

spec = importlib.util.spec_from_file_location('alpha_verifier', Path(__file__).with_name('verify-alpha-package.py'))
verifier = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verifier)

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('root', type=Path)
    p.add_argument('archive', type=Path)
    a = p.parse_args()
    try:
        verifier.verify(a.root, write=False)
        sidecar = Path(str(a.archive) + '.sha256')
        if a.archive.exists() or a.archive.is_symlink() or sidecar.exists() or sidecar.is_symlink():
            raise ValueError('output: refusing overwrite')
        if a.archive.resolve().is_relative_to(a.root.resolve()) or sidecar.resolve().is_relative_to(a.root.resolve()):
            raise ValueError('output: must be outside staging')
        paths = sorted((a.root,) + tuple(a.root.rglob('*')), key=lambda x: x.relative_to(a.root.parent).as_posix())
        fd, temp = tempfile.mkstemp(dir=a.archive.parent, prefix='.alpha-')
        try:
            with os.fdopen(fd, 'wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as gz, tarfile.open(fileobj=gz, mode='w', format=tarfile.PAX_FORMAT) as tar:
                for path in paths:
                    info = path.lstat()
                    item = tarfile.TarInfo(path.relative_to(a.root.parent).as_posix() + ('/' if stat.S_ISDIR(info.st_mode) else ''))
                    item.uid = item.gid = item.mtime = 0
                    item.uname = item.gname = ''
                    item.mode = 0o755 if stat.S_ISDIR(info.st_mode) or info.st_mode & 0o111 else 0o644
                    if stat.S_ISREG(info.st_mode):
                        item.size = info.st_size
                        with path.open('rb') as f: tar.addfile(item, f)
                    else: tar.addfile(item)
            h = hashlib.sha256()
            with open(temp, 'rb') as f:
                for block in iter(lambda: f.read(1024 * 1024), b''): h.update(block)
            os.link(temp, a.archive)
            try:
                with sidecar.open('x') as f: f.write(f'{h.hexdigest()}  {a.archive.name}\n')
            except Exception:
                a.archive.unlink()
                raise
        finally:
            os.unlink(temp)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f'alpha archive failed: {exc}', file=sys.stderr)
        return 1
    return 0

if __name__ == '__main__': sys.exit(main())
