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
import stat
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


def script_facts(data, fstab=False):
    facts = []
    for number, line in enumerate(data.decode('utf-8', 'strict').splitlines(), 1):
        text = line.strip()
        if not text or text.startswith('#'):
            continue
        tags = [x for x in ('mount', 'tmpfs', '/tmp', 'jiritsu', 'initrc',
                           'image_', 'wbi', 'insmod', 'exec', 'chroot',
                           'unshare', 'setns', 'mkdir', 'ln ', 'init2') if x in text]
        if not fstab and not tags and not re.match(r'^(if|then|else|elif|fi|case|esac)\b', text):
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
        row['integer_tokens'] = [int(t) for t in tokens if re.fullmatch(r'[0-9]{1,6}', t)][:8]
        row['test_operators'] = [t for t in tokens if t in ('-e', '-d', '-f', '-eq', '-ne', '=', '!=')]
        if tokens and Path(tokens[0]).name in ('mount', 'mkdir', 'ln', 'exec', 'source', '.'):
            row['operation'] = Path(tokens[0]).name
        if tokens and Path(tokens[0]).name == 'mount':
            row['filesystem'] = tokens[tokens.index('-t') + 1] if '-t' in tokens else None
            row['options'] = tokens[tokens.index('-o') + 1] if '-o' in tokens else None
            row['all_fstab'] = '-a' in tokens
        if len(tokens) >= 4 and tokens[1].startswith('/'):
            if fstab or tokens[2] in ('tmpfs', 'proc', 'sysfs', 'ext2', 'ext3', 'ext4', 'devpts', 'ramfs'):
                row['fstab'] = dict(zip(('source', 'target', 'type', 'options'), tokens[:4]))
        facts.append(row)
    return facts[:200]


def image_path_facts(root, absolute):
    """Resolve an image path without following absolute links into the host.

    This describes extracted image entries, never the service's live namespace.
    """
    pending = absolute.strip('/').split('/')
    resolved = []
    trace = []
    links = 0
    while pending:
        part = pending.pop(0)
        if part in ('', '.'):
            continue
        if part == '..':
            if resolved:
                resolved.pop()
            continue
        path = root.joinpath(*resolved, part)
        guest = '/' + '/'.join([*resolved, part])
        try:
            mode = path.lstat().st_mode
        except FileNotFoundError:
            return {'requested': absolute, 'trace': trace, 'missing_at': guest,
                    'live_resolution_verified': False}
        kind = ('symlink' if stat.S_ISLNK(mode) else 'directory' if stat.S_ISDIR(mode)
                else 'regular' if stat.S_ISREG(mode) else 'other')
        row = {'path': guest, 'kind': kind}
        if kind == 'symlink':
            links += 1
            if links > 40:
                raise ValueError('image_symlink_loop')
            target = os.readlink(path)
            row['target'] = target
            if target.startswith('/'):
                resolved = []
            pending = target.split('/') + pending
        else:
            resolved.append(part)
        trace.append(row)
    return {'requested': absolute, 'trace': trace, 'image_resolution': '/' + '/'.join(resolved),
            'live_resolution_verified': False}


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

    def literal(va):
        for offset, base, length, _ in segments:
            if base <= va < base + length:
                pos = offset + va - base
                end = data.find(b'\0', pos, min(pos + 128, len(data)))
                if end < 0:
                    return None
                value = data[pos:end].decode('ascii', 'ignore')
                if re.fullmatch(r'/[A-Za-z0-9_.%/-]{1,110}', value) or value in (
                        'tmpfs', 'ramfs', 'ext2', 'ext3', 'ext4', 'vfat', 'exfat',
                        'auto', 'libJit.so', 'jit_init', 'jit_main', 'jit_exit'):
                    return value
        return None

    functions = []
    current = None
    registers = {}
    target_addresses = {va: n['id'] for n in needles for va in n['virtual_addresses']}
    for line in listing.splitlines():
        label = re.match(r'^([0-9a-f]+) <([^>]+)>:', line)
        if label:
            current = {'name': label[2], 'va': int(label[1], 16), 'calls': [],
                       'zero_tests': [], 'string_candidates': []}
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
                entry = {'at': address, 'kind': op,
                         'target_va': int(target[1], 16), 'target': target[2]}
                args = {}
                for n in range(5):
                    value = registers.get('x' + str(n))
                    if value is not None:
                        string = literal(value[0])
                        if string is not None:
                            args['x' + str(n)] = {'string_candidate': string}
                        elif 0 <= value[0] <= 65535:
                            args['x' + str(n)] = {'integer_candidate': value[0]}
                if args:
                    entry['arguments_candidate'] = args
                current['calls'].append(entry)
        if op in ('cbz', 'cbnz'):
            test = re.match(r'([wx]\d+),\s*([0-9a-f]+)', operands)
            if test:
                current['zero_tests'].append({'at': address, 'register': test[1],
                                              'test': op, 'target': int(test[2], 16)})
        # Bounded ADRP/ADD candidate detection; not full data-flow analysis.
        page = re.match(r'(x\d+),\s*([0-9a-f]+)', operands) if op in ('adrp', 'adr') else None
        add = re.match(r'(x\d+),\s*(x\d+),\s*#(0x[0-9a-f]+|\d+)', operands) if op == 'add' else None
        move = re.match(r'([wx]\d+),\s*#(0x[0-9a-f]+|\d+)', operands) if op == 'mov' else None
        copy = re.match(r'(x\d+),\s*(x\d+)\b', operands) if op == 'mov' else None
        if page:
            registers[page[1]] = (int(page[2], 16), address)
        elif add and add[2] in registers:
            value, previous = registers[add[2]]
            registers[add[1]] = (value + int(add[3], 0), previous)
        elif move:
            registers['x' + move[1][1:]] = (int(move[2], 0), address)
        elif copy and copy[2] in registers:
            registers[copy[1]] = registers[copy[2]]
        else:
            dest = re.match(r'(x\d+|w\d+)\b', operands)
            if dest and op not in ('str', 'stp', 'cmp', 'tst', 'cbz', 'cbnz'):
                registers.pop('x' + dest[1][1:], None)
        for register, (value, previous) in registers.items():
            if value in target_addresses and 0 <= address - previous <= 48:
                candidate = {'at': address, 'id': target_addresses[value], 'register': register}
                if candidate not in current['string_candidates']:
                    current['string_candidates'].append(candidate)
        if op in ('bl', 'blr'):
            registers = {r: v for r, v in registers.items() if 19 <= int(r[1:]) <= 29}
        elif op in ('ret', 'b'):
            registers.clear()
    selected = []
    for f in functions:
        if (f['string_candidates'] or
                re.search(r'ramdisk_|sys_mount|jiritsu_init|set_file_path|selection_mount|mountInfo|mkdir_POSIX|CFileAccess4(open|read)|CImJiritsu.*(init|run)', f['name']) or
                any(re.search(r'dlopen|dlclose|setns|unshare|chroot', c['target']) for c in f['calls'])):
            f['call_count'] = len(f['calls'])
            f['calls_truncated'] = len(f['calls']) > 180
            f['calls'] = f['calls'][:180]
            f['zero_tests'] = f['zero_tests'][:60]
            f['string_candidates'] = list({c['id']: c for c in f['string_candidates']}.values())
            selected.append(f)
    return {'supported_aarch64': True, 'needles': needles, 'symbols': symbols[:180],
            'candidate_functions': selected[:60], 'candidate_only': True,
            'function_count_before_limit': len(selected)}


def main():
    manifest = json.loads((ROOT / 'sony-assets.json').read_text())
    report = {'schema': 'a7c2-lifecycle-static/1', 'model': 'ILCE-7CM2', 'version': '2.01',
              'executed_firmware': False, 'usb_access': False, 'complete_callgraph': False,
              'live_namespace_verified': False, 'camera_upload_enabled': False,
              'scripts': [], 'elf': [], 'symlinks': [], 'binary_needle_inventory': []}
    report['image_paths'] = [image_path_facts(ROOT / 'menu-root', p)
                             for p in ('/tmp', '/tmp/jiritsu', '/etc/ld.so.preload')]
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
            report['scripts'].append(item | {'facts': script_facts(data, 'fstab' in relative)})
        if relative in ('menu-root/usr/lib/libJiritsu.so', 'menu-root/usr/lib/libusbcmd.so'):
            candidates.append((path, data, item))
    for path, data, item in candidates:
        report['elf'].append(item | elf_facts(path, data))
    encoded = json.dumps(report, indent=2)
    if len(encoded) > 400000:
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
