#!/usr/bin/env python3
"""Pinned original loader/service survey. Static data only; no target execution.

Publish bounded symbol/call/provenance metadata, never raw firmware instructions.
Imports and direct calls do not establish absence of indirect or other-DSO calls.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
from jiritsu_dispatch import follow

spec = importlib.util.spec_from_file_location('get_file2_static', Path(__file__).with_name('get-file2-static.py'))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)
PROCESS = re.compile(r'(^|_)(fork|vfork|clone|exec\w*|posix_spawn\w*|wait\w*|signal|sigaction|pthread_\w*|dlopen|dlclose|dlsym)(@|$)|osal_.*(thread|task|msg_queue)', re.I)
SELECT = re.compile(r'^(jiritsu_init|adj_cmd_set_file2|cmd_high_capacity_send_file|cmd_high_capacity_get_file|cmd_file_delete2|sys_file_remove2|ramdisk_mount)$|CImJiritsu.*(init|jit_thread|req|release)|CShellExecute|MakeOsalMessage|Serialize|ReadDeviceData')


def inspect(path, data):
    symbols = {}
    for line in base.run(['aarch64-linux-gnu-readelf', '-Ws', str(path)]).splitlines():
        parts = line.split()
        if len(parts) < 8 or parts[3] not in ('FUNC', 'NOTYPE'):
            continue
        name = parts[7]
        symbols[name] = {'name': name, 'va': int(parts[1], 16),
                         'size': int(parts[2], 0), 'undefined': parts[6] == 'UND'}
    instructions = []
    for line in base.run(['aarch64-linux-gnu-objdump', '-d', str(path)]).splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+([\w.]+)\s*(.*)', line)
        if m:
            instructions.append((int(m[1], 16), m[2], m[3]))
    relocations = {}
    for line in base.run(['aarch64-linux-gnu-readelf', '-rW', str(path)]).splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[2] in ('R_AARCH64_GLOB_DAT', 'R_AARCH64_JUMP_SLOT'):
            relocations[int(fields[0], 16)] = fields[4]
    dynamic = base.run(['aarch64-linux-gnu-readelf', '-dW', str(path)])
    needed = re.findall(r'\(NEEDED\).*\[([^\]]+)\]', dynamic)
    result = {'path': str(path.relative_to(base.ROOT)), 'sha256': hashlib.sha256(data).hexdigest(),
              'needed': needed, 'process_symbols': [s for n, s in symbols.items() if PROCESS.search(n)],
              'selected_functions': [], 'process_direct_calls': [],
              'complete_callgraph': False, 'sony_reaper_contract_verified': False}
    if path.name == 'libJiritsu.so':
        phoff = struct.unpack_from('<Q', data, 32)[0]
        phsize, phnum = struct.unpack_from('<HH', data, 54)
        segments = [struct.unpack_from('<II6Q', data, phoff + i * phsize) for i in range(phnum)]
        def read_integer(address, size, signed):
            for segment in segments:
                if segment[0] == 1 and segment[3] <= address and address + size <= segment[3] + segment[5]:
                    offset = segment[2] + address - segment[3]
                    return int.from_bytes(data[offset:offset + size], 'little', signed=signed)
            raise ValueError('table_outside_file')
        code = {a: (op, args) for a, op, args in instructions}
        result['callback_switch'] = []
        for selector in range(1, 21):
            try:
                edge = follow(code, 0xb61c, selector, read_integer)
                if edge['target'] not in code:
                    raise ValueError('invalid_switch_target')
                edge['direct_call_candidates'] = []
                for address in range(edge['target'], edge['target'] + 64, 4):
                    op, operands = code.get(address, ('missing', ''))
                    if op in ('bl', 'b'):
                        target = re.match(r'([0-9a-f]+) <([^>]+)>', operands)
                        if target:
                            edge['direct_call_candidates'].append({'at': address, 'symbol': target[2]})
                        break
                    if op in ('ret', 'br', 'missing') or op.startswith('b.'):
                        break
                result['callback_switch'].append(edge)
            except (KeyError, ValueError) as error:
                result['callback_switch'].append({'selector': selector, 'unresolved': type(error).__name__})
    for name, s in symbols.items():
        if s['undefined'] or not SELECT.search(name):
            continue
        if s['size'] > 12000:
            raise ValueError('function_size_limit')
        facts = base.trace(instructions, s['va'], s['va'] + s['size'])
        if len(facts) > 1600:
            raise ValueError('function_fact_limit')
        for fact in facts:
            if fact['kind'] != 'indirect_call':
                continue
            match = re.fullmatch(r'load64\(offset\(constant:(\d+),(-?\d+)\)\)', fact['target_candidate'])
            if match:
                slot = int(match[1]) + int(match[2])
                if slot in relocations:
                    fact['linker_symbol_candidate'] = relocations[slot]
        result['selected_functions'].append(s | {'cfg_candidates_only': True, 'facts': facts})
    for address, operation, operands in instructions:
        if operation not in ('bl', 'b'):
            continue
        target = re.match(r'([0-9a-f]+) <([^>]+)>', operands)
        if not target or not PROCESS.search(target[2]):
            continue
        owners = [s['name'] for s in symbols.values() if not s['undefined'] and s['va'] <= address < s['va'] + s['size']]
        result['process_direct_calls'].append({'at': address, 'target': target[2], 'owners': owners})
        if path.name == 'im.elf' and re.match(r'(waitpid|signal|fork)@', target[2]):
            # A bounded local window, explicitly not a recovered function/CFG.
            # Constants can narrow review; unknown origins remain unknown.
            window = base.trace(instructions, address - 80, address + 4)
            result.setdefault('im_process_windows', []).append({
                'call_at': address, 'function_boundary_known': False,
                'facts': window})
    if len(result['selected_functions']) > 24 or len(result['process_direct_calls']) > 300:
        raise ValueError('scope_limit')
    return result


def main():
    manifest = json.loads((base.ROOT / 'sony-assets.json').read_text())
    report = {'schema': 'jiritsu-entry-static/1', 'firmware_executed': False,
              'usb_access': False, 'camera_upload_enabled': False, 'files': []}
    for suffix in ('lib/libJiritsu.so', 'lib/libsencore.so', 'lib/libosal_uipc.so',
                   'lib/libosal_utm.so', 'bin/im.elf'):
        relative = 'menu-root/usr/' + suffix
        if relative not in manifest:
            report['files'].append({'path': relative, 'status': 'not_in_manifest'})
            continue
        path = base.ROOT / relative
        if path.is_symlink():
            raise ValueError('symlink_input')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != manifest[relative]['sha256']:
            raise ValueError('identity_mismatch')
        report['files'].append(inspect(path, data))
    encoded = json.dumps(report, separators=(',', ':')) + '\n'
    if len(encoded) > 300000:
        raise ValueError('report_limit')
    Path('ci-logs/jiritsu-entry-static.json').write_text(encoded)
    print('JIRITSU_ENTRY_STATIC_METADATA_WRITTEN; no execution')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        allowed = {'tool_failed', 'function_size_limit', 'function_fact_limit', 'scope_limit',
                   'symlink_input', 'identity_mismatch', 'report_limit', 'dataflow_bound'}
        print('JIRITSU_ENTRY_STATIC_FAILED category=' + (str(exc) if str(exc) in allowed else type(exc).__name__))
        raise SystemExit(1)
