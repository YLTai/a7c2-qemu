#!/usr/bin/env python3
"""Exact build identity and integrity receipts; never cache firmware or run state."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
os.chdir(ROOT)
FILES = [
    'runtime/sources/qemu-11.1.2/build-sony-ui/qemu-system-aarch64',
    'runtime/sources/qemu-11.1.2/build-user/qemu-aarch64',
    'runtime/sources/qemu-tools/usr/lib/libfdt.so.1',
    'runtime/sources/qemu-tools/usr/bin/dtc',
    'runtime/analysis/qemu-virt-board/virt-packed.dtb',
    'source/pci-hardware-build.json',
    'source/build-programs.sha256',
]
RECEIPT = Path('source/ci-build-receipt.json')

def sha(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Not a regular file: {path}')
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()

def identity():
    # Conservative: every tracked input, including board/model staging and scripts.
    paths = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
    paths += [str(p) for p in Path('tools/ci').glob('*') if p.is_file()]
    paths += [str(p) for p in Path('.github/workflows').glob('*') if p.is_file()]
    sources = {p: sha(p) for p in sorted(set(paths)) if p and Path(p).is_file()}
    toolchain = subprocess.check_output([
        'dpkg-query', '-W', '-f=${binary:Package}=${Version}\n'
    ]).decode()
    versions = {tool: subprocess.check_output([tool, '--version']).decode()
                for tool in ('cc', 'c++', 'python3', 'meson', 'ninja', 'bwrap')}
    return {'source': sources, 'packages': toolchain, 'versions': versions,
            'os': Path('/etc/os-release').read_text(), 'arch': platform.machine(),
            'runner_image': os.environ.get('ImageVersion', '')}

def key():
    return hashlib.sha256(json.dumps(identity(), sort_keys=True).encode()).hexdigest()

mode = sys.argv[1]
if mode == 'key':
    manifest = json.loads(Path('source/manifest.json').read_text())
    print('source_sha=' + manifest['base_sha256'])
    print('build_key=' + key())
elif mode == 'seal':
    RECEIPT.write_text(json.dumps({'key': key(), 'files': {p: sha(p) for p in FILES}}, indent=2)+'\n')
elif mode == 'verify':
    receipt = json.loads(RECEIPT.read_text())
    if receipt['key'] != key() or set(receipt['files']) != set(FILES):
        raise SystemExit('Cache build identity/inventory mismatch')
    for p, expected in receipt['files'].items():
        if sha(p) != expected:
            raise SystemExit('Cache digest mismatch: ' + p)
    subprocess.run(['sha256sum', '--check', 'source/build-programs.sha256'], check=True)
    print('BUILD_CACHE_VERIFIED')
else:
    raise SystemExit('Usage: qemu-cache.py key|seal|verify')
