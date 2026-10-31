#!/usr/bin/env python3
"""Private firmware input -> bounded metadata. Never execute a target binary.

No firmware text, raw instructions, binary bytes or tool stderr is exported.
Cross references are candidates, not a proof of reachability or absent callers.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess

ROOT = Path('runtime/analysis')
NEEDLES = ('/tmp/jiritsu', 'libJit.so', 'SET_FILE2', '/proc/mounts',
           '/proc/self/mountinfo', '/proc/mountinfo', '/sys/power/image_mode',
           '/sys/power/image_drop', '/sys/power/image_dev')
INTEREST = re.compile(r'file|jit|init|dlopen|dlclose|mount|unshare|setns|chroot|readlink|realpath', re.I)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def command(args):
    p = subprocess.run(args, capture_output=True, text=True, timeout=120)
    if p.returncode:
        raise ValueError('analysis_tool_failed')
    return p.stdout


def script_facts(data):
    facts = []
    for number, line in enumerate(data.decode('utf-8', 'strict').splitlines(), 1):
        text = line.strip()
        if not text or text.startswith('#'):
            continue
        tags = [x for x in ('mount', 'tmpfs', '/tmp', 'jiritsu', 'initrc',
                           'image_', 'wbi', 'insmod', 'exec', 'chroot',
                           'unshare', 'setns', 'mkdir', 'ln ', 'init2') if x in text]
        if not tags and not re.match(r'^(if|then|else|elif|fi|case|esac)\b', text):
            continue
        row = {'line': number, 'line_sha256': digest(line.encode()), 'tags': tags}
        # Paths and shell operation types are facts, not the source line.
        row['paths'] = sorted(set(re.findall(r'(?<![\w:])/[A-Za-z0-9_./*-]+', text)))[:16]
        row['control'] = next((k for k in ('if', 'then', 'else', 'elif', 'fi', 'case', 'esac')
                               if re.match(r'^' + k + r'\b', text)), None)
        try:
            tokens = shlex.split(text, comments=True)
        except ValueError:
            tokens = []
        if tokens and Path(tokens[0]).name in ('mount', 'mkdir', 'ln', 'exec', 'source', '.'):
            row['operation'] = Path(tokens[0]).name
        if tokens and Path(tokens[0]).name == 'mount':
            row['filesystem'] = tokens[tokens.index('-t') + 1] if '-t' in tokens else None
            row['options'] = tokens[tokens.index('-o') + 1] if '-o' in tokens else None
            row['all_fstab'] = '-a' in tokens
        if len(tokens) >= 4 and tokens[1].startswith('/'):
            if tokens[2] in ('tmpfs', 'proc', 'sysfs', 'ext2', 'ext3', 'ext4', 'devpts', 'ramfs'):
                row['fstab'] = dict(zip(('source', 'target', 'type', 'options'), tokens[:4]))
        facts.append(row)
    return facts[:200]


def elf_facts(path, data):
    if data[:6] != b'\x7fELF\x02\x01':
        return {'supported_aarch64': False}
    if struct.unpack_from('<H', data, 18)[0] != 183:
        return {'supported_aarch64': False}
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, phnum = struct.unpack_from('<HH', data, 54)
    segments = []
    for index in range(phnum):
        kind, flags, off, va, _, length, _, _ = struct.unpack_from('<II6Q', data, phoff + index * phsize)
        if kind == 1:
            segments.append((off, va, length, flags))
    needles = []
    for word in NEEDLES:
        start = 0
        for _ in range(24):
            offset = data.find(word.encode(), start)
            if offset < 0:
                break
            mappings = [va + offset - off for off, va, length, _ in segments if off <= offset < off + length]
            needles.append({'id': word, 'file_offset': offset, 'virtual_addresses': mappings})
            start = offset + len(word)
    symbols = []
    for line in command(['aarch64-linux-gnu-readelf', '-Ws', str(path)]).splitlines():
        parts = line.split()
        if len(parts) >= 8 and parts[3] == 'FUNC' and INTEREST.search(parts[7]):
            entry = {'name': parts[7], 'va': int(parts[1], 16), 'size': int(parts[2]),
                     'undefined': parts[6] == 'UND'}
            if entry not in symbols:
                symbols.append(entry)
    listing = command(['aarch64-linux-gnu-objdump', '-d', str(path)])
    functions = []
    current = None
    registers = {}
    target_addresses = {va: n['id'] for n in needles for va in n['virtual_addresses']}
    for line in listing.splitlines():
        label = re.match(r'^([0-9a-f]+) <([^>]+)>:', line)
        if label:
            current = {'name': label[2], 'va': int(label[1], 16), 'calls': [], 'string_candidates': []}
            functions.append(current)
            registers = {}
            continue
        ins = re.match(r'^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+(\w+)\s*(.*)', line)
        if not ins or current is None:
            continue
        address, op, operands = int(ins[1], 16), ins[2], ins[3]
        if op in ('bl', 'b'):
            target = re.match(r'([0-9a-f]+) <([^>]+)>', operands)
            if target:
                current['calls'].append({'at': address, 'kind': op,
                                         'target_va': int(target[1], 16), 'target': target[2]})
        # Bounded ADRP/ADD candidate detection; not full data-flow analysis.
        page = re.match(r'(x\d+),\s*([0-9a-f]+)', operands) if op in ('adrp', 'adr') else None
        add = re.match(r'(x\d+),\s*(x\d+),\s*#(0x[0-9a-f]+|\d+)', operands) if op == 'add' else None
        if page:
            registers[page[1]] = (int(page[2], 16), address)
        elif add and add[2] in registers:
            value, previous = registers[add[2]]
            registers[add[1]] = (value + int(add[3], 0), previous)
        else:
            dest = re.match(r'(x\d+|w\d+)\b', operands)
            if dest and op not in ('str', 'stp', 'cmp', 'tst', 'cbz', 'cbnz'):
                registers.pop('x' + dest[1][1:], None)
        for register, (value, previous) in registers.items():
            if value in target_addresses and 0 <= address - previous <= 48:
                candidate = {'at': address, 'id': target_addresses[value], 'register': register}
                if candidate not in current['string_candidates']:
                    current['string_candidates'].append(candidate)
        if op in ('bl', 'blr', 'ret', 'b'):
            registers.clear()
    selected = []
    for f in functions:
        if f['string_candidates'] or any(re.search(r'dlopen|dlclose|setns|unshare|chroot', c['target']) for c in f['calls']):
            f['calls'] = f['calls'][:80]
            f['string_candidates'] = f['string_candidates'][:40]
            selected.append(f)
    return {'supported_aarch64': True, 'needles': needles, 'symbols': symbols[:180],
            'candidate_functions': selected[:60], 'candidate_only': True}


def main():
    manifest = json.loads((ROOT / 'sony-assets.json').read_text())
    report = {'schema': 'a7c2-lifecycle-static/1', 'model': 'ILCE-7CM2', 'version': '2.01',
              'executed_firmware': False, 'usb_access': False, 'complete_callgraph': False,
              'live_namespace_verified': False, 'camera_upload_enabled': False,
              'scripts': [], 'elf': [], 'symlinks': [], 'binary_needle_inventory': []}
    candidates = []
    for relative, expected in manifest.items():
        if expected.get('source_class') != 'sony_original' or not relative.startswith('menu-root/'):
            continue
        path = ROOT / relative
        if 'symlink' in expected:
            if not path.is_symlink() or os.readlink(path) != expected['symlink']:
                raise ValueError('symlink_identity_mismatch')
            if any(x in relative for x in ('tmp', 'init', 'jiritsu')):
                report['symlinks'].append({'path': relative, 'target': expected['symlink']})
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError('input_not_regular')
        data = path.read_bytes()
        if len(data) != expected['size'] or digest(data) != expected['sha256']:
            raise ValueError('original_file_identity_mismatch')
        item = {'path': relative, 'sha256': expected['sha256'], 'bytes': len(data)}
        hits = [word for word in NEEDLES if word.encode() in data]
        if hits:
            report['binary_needle_inventory'].append(item | {'needles': hits})
        if relative.startswith('menu-root/sbin/init') or (len(data) < 131072 and data.startswith(b'#!') and hits):
            report['scripts'].append(item | {'facts': script_facts(data)})
        if relative in ('menu-root/usr/lib/libJiritsu.so', 'menu-root/usr/lib/libusbcmd.so'):
            candidates.append((path, data, item))
    for path, data, item in candidates:
        report['elf'].append(item | elf_facts(path, data))
    encoded = json.dumps(report, indent=2)
    if len(encoded) > 240000:
        raise ValueError('report_bound_exceeded')
    Path('ci-logs/lifecycle-static.json').write_text(encoded + '\n')
    print('LIFECYCLE_STATIC_METADATA_WRITTEN; no live or startup-exhaustiveness proof')


if __name__ == '__main__':
    try:
        main()
    except Exception:
        # No firmware strings, host paths, tool output or traceback in public logs.
        print('LIFECYCLE_STATIC_FAILED; private inputs not exported')
        raise SystemExit(1)
