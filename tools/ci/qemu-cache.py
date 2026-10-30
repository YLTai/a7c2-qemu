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

def package_closure():
    # Fingerprint installed toolchain/dependency closure, not unrelated runner apps.
    raw = subprocess.check_output(['dpkg-query', '-W',
        '-f=${binary:Package}\t${Status}\t${Version}\t${Depends}\t${Pre-Depends}\t${Provides}\n']).decode()
    import re
    records, names = {}, {}
    def terms(value):
        return [re.split(r'[ (]', x.strip(), 1)[0].split(':')[0]
                for x in re.split(r'[,|]', value) if x.strip()]
    for line in raw.splitlines():
        name, status, version, deps, predeps, provides = line.split('\t')
        if not status.endswith(' ok installed'):
            continue
        records[name] = (version, terms(deps + ',' + predeps))
        for alias in [name.split(':')[0]] + terms(provides):
            names.setdefault(alias, set()).add(name)
    roots = Path('tools/ci/dependencies.txt').read_text().split()
    selected, pending = set(), []
    for root in roots:
        if root not in names:
            raise ValueError('Required package missing: ' + root)
        pending.extend(names[root])
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        selected.add(name)
        for dependency in records[name][1]:
            pending.extend(names.get(dependency, ()))
    return {name: records[name][0] for name in sorted(selected)}


def identity():
    paths = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
    exact = {'build-qemu.sh', 'tools/ci/qemu-cache.py', 'tools/ci/dependencies.txt',
             'tools/ci/qemu-smoke.sh', 'runtime/analysis/test-qemu-native-input.py',
             'runtime/analysis/qemu-virt-board/virt-packed.dts'}
    prefixes = ('source/', 'report/virtual-pcidma/', 'report/virtual-dma330/',
                'report/virtual-atu/')
    paths = set(p for p in paths if p in exact or p.startswith(prefixes)) | exact
    sources = {p: sha(p) for p in sorted(paths)}
    versions = {tool: subprocess.check_output([tool, '--version']).decode()
                for tool in ('cc', 'c++', 'python3', 'meson', 'ninja', 'bwrap')}
    return {'source': sources, 'packages': package_closure(), 'versions': versions,
            'os': Path('/etc/os-release').read_text(), 'arch': platform.machine(),
            'runner_image': os.environ.get('ImageVersion', '')}

def key():
    return hashlib.sha256(json.dumps(identity(), sort_keys=True).encode()).hexdigest()

mode = sys.argv[1]
if mode == 'key':
    manifest = json.loads(Path('source/manifest.json').read_text())
    Path('ci-logs').mkdir(exist_ok=True)
    Path('ci-logs/build-identity.json').write_text(json.dumps(identity(), sort_keys=True, indent=2)+'\n')
    print('source_sha=' + manifest['base_sha256'])
    print('build_key=' + key())
elif mode == 'seal':
    RECEIPT.write_text(json.dumps({'key': key(), 'identity': identity(), 'files': {p: sha(p) for p in FILES}}, indent=2)+'\n')
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
