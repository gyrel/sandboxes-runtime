#!/usr/bin/env python3
"""Create a deterministic archive from a verified, private runtime bundle."""

import argparse
import gzip
import os
from pathlib import Path
import stat
import tarfile
import tempfile


def entries(root: Path):
    result = []
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(base) / name
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not (
                stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)
            ):
                raise ValueError(f"unsupported bundle entry: {path}")
            if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
                raise ValueError(f"hard-linked bundle entry: {path}")
            result.append((path.relative_to(root).as_posix(), path, info))
    return sorted(result)


def write_archive(root: Path, output: Path):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("bundle root must be a real directory")
    if not (root / "bundle.json").is_file():
        raise ValueError("verified bundle manifest is missing")
    if output.exists() or output.is_symlink():
        raise ValueError("refusing to overwrite archive")
    if output.resolve().is_relative_to(root.resolve()):
        raise ValueError("archive output must be outside the bundle root")
    items = entries(root)
    if not items:
        raise ValueError("bundle is empty")
    fd, temporary = tempfile.mkstemp(prefix=output.name + ".", dir=output.parent)
    try:
        with os.fdopen(fd, "wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as zipped:
                with tarfile.open(mode="w", fileobj=zipped, format=tarfile.PAX_FORMAT) as archive:
                    for name, path, info in items:
                        member = tarfile.TarInfo(name + "/" if stat.S_ISDIR(info.st_mode) else name)
                        member.uid = member.gid = member.mtime = 0
                        member.uname = member.gname = ""
                        member.mode = 0o755 if stat.S_ISDIR(info.st_mode) or info.st_mode & 0o111 else 0o644
                        if stat.S_ISREG(info.st_mode):
                            member.size = info.st_size
                            with path.open("rb") as source:
                                archive.addfile(member, source)
                        else:
                            archive.addfile(member)
        os.link(temporary, output)
    finally:
        os.unlink(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    write_archive(args.root, args.out)


if __name__ == "__main__":
    main()
