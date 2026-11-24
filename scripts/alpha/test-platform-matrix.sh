#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
python3 -I - "$ROOT" <<'PY'
import importlib.util, pathlib, sys
p=pathlib.Path(sys.argv[1])/'scripts/alpha/verify-alpha-package.py'
s=importlib.util.spec_from_file_location('verify',p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m)
assert set(m.MATRIX)=={'linux/arm64','darwin/arm64'}
assert m.MATRIX['linux/arm64']==('libkrun.so.1.19.6','libkrunfw.so.5.6.2')
assert m.MATRIX['darwin/arm64']==('libkrun.dylib','libkrunfw.5.dylib')
for platform in ('windows/arm64','linux/amd64'):
 import tempfile
 with tempfile.TemporaryDirectory() as d:
  root=pathlib.Path(d)/('rheic-sandboxes-alpha-'+platform.replace('/','-')); root.mkdir()
  try: m.verify(root)
  except ValueError as e: assert 'unsupported' in str(e), str(e)
  else: raise AssertionError(platform+' accepted')
print('PASS: platform matrix and unsupported platforms')
PY
