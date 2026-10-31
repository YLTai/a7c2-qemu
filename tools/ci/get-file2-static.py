#!/usr/bin/env python3
"""Bounded private-data analysis for GET_FILE2. No firmware execution or USB.

Exports semantic load/compare/call facts, never bytes or disassembly listings.
Conservative CFG joins discard disagreeing origins. Unsupported operations lose
their output provenance; facts remain candidates, not a path-complete proof.
"""
from collections import deque
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess

ROOT = Path('runtime/analysis')
FUNCTIONS = ('adj_cmd_set_file_path', 'get_access_filename', 'adj_cmd_get_file2',
             '_ZN10libJiritsu11CFileAccess4statEPKcP13tag_FILE_INFO',
             '_ZN10libJiritsu11CFileAccess4readEPvm',
             '_Z17AdjustControlFuncPK12SenserPacket',
             '_ZN29SubsystemCommunicationCommand16TransactionStartEPK12SenserPacketPKvS4_',
             '_ZN24HostCommunicationCommand9DoExecuteEP12SenserPacket',
             '_ZN24HostCommunicationCommandC1EPK12SenserPacketRK15CommandCodeType')


def run(arguments):
    r = subprocess.run(arguments, capture_output=True, text=True, timeout=90)
    if r.returncode:
        raise ValueError('tool_failed')
    return r.stdout


def reg(name):
    return 'x' + name[1:] if name.startswith('w') else name


def short(value):
    return value if len(value) <= 120 else 'complex_unknown'


def trace(lines, start, end):
    initial = {f'x{i}': f'argument{i}' for i in range(8)} | {'sp': 'frame'}
    instructions = {a: (o, p) for a, o, p in lines if start <= a < end}
    incoming = {start: initial}
    pending = deque([start])
    records = {}
    iterations = 0
    while pending:
        address = pending.popleft()
        if address not in instructions:
            continue
        iterations += 1
        if iterations > 20000:
            raise ValueError('dataflow_bound')
        operation, operands = instructions[address]
        state = dict(incoming[address])
        comparison = state.pop('$comparison', None)
        memory = {}
        facts = []
        get = lambda name: state.get(reg(name), 'unknown')
        value = None
        destination = re.match(r'([wx]\d+|sp)\b', operands)
        pair = re.match(r'([wx]\d+|sp),\s*([wx]\d+|sp)$', operands)
        immediate = re.match(r'([wx]\d+|sp),\s*#(-?0x[0-9a-f]+|-?\d+)', operands)
        arithmetic = re.match(r'([wx]\d+|sp),\s*([wx]\d+|sp),\s*#(-?0x[0-9a-f]+|-?\d+)', operands)
        access = re.match(r'([wx]\d+),\s*\[(x\d+|sp)(?:,\s*#(-?0x[0-9a-f]+|-?\d+))?\]', operands)
        if operation == 'mov' and pair:
            value = get(pair[2])
        elif operation in ('uxtw', 'sxtw') and pair:
            value = short(f'{operation}({get(pair[2])})')
        elif operation in ('mov', 'movz') and immediate:
            value = 'constant:' + str(int(immediate[2], 0))
        elif operation in ('add', 'sub') and arithmetic:
            offset = int(arithmetic[3], 0) * (1 if operation == 'add' else -1)
            shift = re.search(r'lsl #?(\d+)', operands)
            if shift:
                offset <<= int(shift[1])
            value = short(f'offset({get(arithmetic[2])},{offset})')
        elif operation == 'and' and arithmetic:
            value = short(f'mask({get(arithmetic[2])},{int(arithmetic[3], 0)})')
        elif operation in ('lsl', 'lsr') and arithmetic:
            amount = int(arithmetic[3], 0)
            width = 32 if arithmetic[1].startswith('w') else 64
            if 0 <= amount < width:
                value = short(f'{operation}{width}({get(arithmetic[2])},{amount})')
        elif operation in ('ldrb', 'ldrh', 'ldr', 'ldrsw') and access:
            offset = int(access[3] or '0', 0)
            location = short(f'offset({get(access[2])},{offset})')
            width = 8 if operation == 'ldrb' else 16 if operation == 'ldrh' else 32 if access[1][0] == 'w' or operation == 'ldrsw' else 64
            value = memory.get(location, short(f'load{width}({location})'))
            facts.append({'at': address, 'kind': 'load', 'bits': width,
                          'base_candidate': get(access[2]), 'offset': offset,
                          'destination': reg(access[1])})
        elif operation in ('str', 'strb', 'strh') and access:
            location = short(f'offset({get(access[2])},{int(access[3] or "0", 0)})')
            memory[location] = get(access[1])
            facts.append({'at': address, 'kind': 'store', 'destination_candidate': location,
                          'value_candidate': get(access[1])})
        if value is not None and destination and operation not in ('ldrb', 'ldrh', 'ldr', 'ldrsw'):
            facts.append({'at': address, 'kind': 'assignment', 'destination': reg(destination[1]),
                          'value_candidate': value})
        if operation in ('cmp', 'tst'):
            if pair:
                comparison = {'at': address, 'lhs_candidate': get(pair[1]),
                              'rhs_candidate': get(pair[2]), 'test': operation}
            elif immediate:
                comparison = {'at': address, 'lhs_candidate': get(immediate[1]),
                              'constant': int(immediate[2], 0), 'test': operation}
            else:
                comparison = None
        if operation.startswith('b.'):
            target = re.match(r'([0-9a-f]+)', operands)
            if target:
                facts.append({'at': address, 'kind': 'conditional', 'condition': operation[2:],
                              'target': int(target[1], 16), 'comparison': comparison})
            comparison = None
        elif operation in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            check = re.match(r'([wx]\d+),\s*(?:#(\d+),\s*)?([0-9a-f]+)', operands)
            if check:
                facts.append({'at': address, 'kind': 'conditional', 'condition': operation,
                              'value_candidate': get(check[1]), 'bit': check[2],
                              'target': int(check[3], 16)})
        elif operation in ('bl', 'b'):
            target = re.match(r'([0-9a-f]+) <([^>]+)>', operands)
            if target:
                args = {f'x{i}': get(f'x{i}') for i in range(5)}
                facts.append({'at': address, 'kind': 'call' if operation == 'bl' else 'jump',
                              'target': int(target[1], 16), 'symbol': target[2],
                              'arguments_candidate': args if operation == 'bl' else {}})
        if value is not None and destination:
            state[reg(destination[1])] = value
        elif destination and operation not in ('str', 'strb', 'strh', 'stp', 'cmp', 'tst', 'cbz', 'cbnz', 'tbz', 'tbnz'):
            state.pop(reg(destination[1]), None)
        if operation in ('bl', 'blr'):
            state = {k: v for k, v in state.items() if k == 'sp' or k.startswith('x') and 19 <= int(k[1:]) <= 29}
            state['x0'] = 'call_result_at:' + hex(address)
            memory.clear()
            comparison = None
        if operation in ('stp', 'ldp'):
            pair_registers = re.match(r'([wx]\d+),\s*([wx]\d+)', operands)
            if operation == 'ldp' and pair_registers:
                state.pop(reg(pair_registers[1]), None)
                state.pop(reg(pair_registers[2]), None)
            indexed = re.search(r'\[sp,\s*#(-?0x[0-9a-f]+|-?\d+)\]!', operands)
            post = re.search(r'\[sp\],\s*#(-?0x[0-9a-f]+|-?\d+)', operands)
            update = indexed or post
            if update:
                state['sp'] = short(f'offset({get("sp")},{int(update[1], 0)})')
        if operation in ('adds', 'subs', 'ands', 'cmn'):
            comparison = None
        if comparison is not None:
            state['$comparison'] = comparison
        records[address] = facts
        successors = [address + 4]
        if operation in ('ret', 'br'):
            successors = []
        elif operation == 'b' or operation.startswith('b.'):
            target = re.match(r'([0-9a-f]+)', operands)
            successors = ([int(target[1], 16)] if target else []) + ([] if operation == 'b' else [address + 4])
        elif operation in ('cbz', 'cbnz', 'tbz', 'tbnz'):
            target = re.match(r'[wx]\d+,\s*(?:#\d+,\s*)?([0-9a-f]+)', operands)
            if target:
                successors.append(int(target[1], 16))
        for successor in successors:
            if successor not in instructions:
                continue
            previous = incoming.get(successor)
            merged = state if previous is None else {k: v for k, v in previous.items() if k in state and state[k] == v}
            if previous is None or merged != previous:
                incoming[successor] = dict(merged)
                pending.append(successor)
    return [fact for address in sorted(records) for fact in records[address]]


def inspect(path, data):
    symbols = []
    table = {}
    for line in run(['aarch64-linux-gnu-readelf', '-Ws', str(path)]).splitlines():
        p = line.split()
        if len(p) < 8:
            continue
        if p[3] == 'FUNC':
            entry = {'name': p[7], 'va': int(p[1], 16), 'size': int(p[2], 0), 'undefined': p[6] == 'UND'}
            if entry not in symbols:
                symbols.append(entry)
            if not entry['undefined']:
                table[p[7]] = entry
    listing = run(['aarch64-linux-gnu-objdump', '-d', str(path)])
    instructions = []
    for line in listing.splitlines():
        m = re.match(r'^\s*([0-9a-f]+):\s+[0-9a-f]{8}\s+([\w.]+)\s*(.*)', line)
        if m:
            instructions.append((int(m[1], 16), m[2], m[3]))
    output = {'path': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(data).hexdigest(),
              'function_facts': [], 'relevant_symbols': [], 'table_references': []}
    if path.name == 'libJiritsu.so':
        next_start = min(s['va'] for s in symbols if s['va'] > 0xb61c and not s['undefined'])
        table['registered_callback_0xb61c'] = {'name': 'registered_callback_0xb61c', 'va': 0xb61c, 'size': next_start - 0xb61c, 'undefined': False}
        table['stat_thunk_0x122f0'] = {'name': 'stat_thunk_0x122f0', 'va': 0x122f0, 'size': 16, 'undefined': False}
    for name in (*FUNCTIONS, 'registered_callback_0xb61c', 'stat_thunk_0x122f0'):
        if name not in table:
            continue
        s = table[name]
        facts = trace(instructions, s['va'], s['va'] + s['size'])
        if len(facts) > 420:
            raise ValueError('function_fact_limit')
        direct_edges = []
        if name == 'registered_callback_0xb61c':
            for address, operation, operands in instructions:
                if s['va'] <= address < s['va'] + s['size'] and operation in ('b', 'bl'):
                    target = re.match(r'([0-9a-f]+) <([^>]+)>', operands)
                    if target:
                        direct_edges.append({'at': address, 'target': int(target[1], 16),
                                             'symbol': target[2], 'selector_unresolved': True})
        output['function_facts'].append(s | {'facts': facts, 'cfg_candidates_only': True,
                                           'unresolved_switch_edges': direct_edges})
    if path.name != 'libJiritsu.so':
        output['relevant_symbols'] = [s for s in symbols if re.search(r'Jiritsu|jiritsu|[Ff]ile|[Aa]djust|[Ss]enser', s['name'])][:100]
    # Resolve only relocations referencing the two reviewed handlers. Values
    # around those records are typed metadata, not exported binary windows.
    phoff = struct.unpack_from('<Q', data, 32)[0]
    phsize, phnum = struct.unpack_from('<HH', data, 54)
    segments = [struct.unpack_from('<II6Q', data, phoff + i * phsize) for i in range(phnum)]
    def file_offset(va):
        return next((s[2] + va - s[3] for s in segments if s[0] == 1 and s[3] <= va < s[3] + s[5]), None)
    wanted = ('adj_cmd_get_file2', 'adj_cmd_set_file_path')
    for line in run(['aarch64-linux-gnu-readelf', '-rW', str(path)]).splitlines():
        if not any(name in line for name in wanted):
            continue
        p = line.split()
        va = int(p[0], 16)
        offset = file_offset(va)
        if offset is None or offset < 16 or offset + 24 > len(data):
            raise ValueError('relocation_mapping')
        fields = []
        for delta in (-16, -12, -8, -4, 8, 12, 16):
            value = struct.unpack_from('<I', data, offset + delta)[0]
            if value <= 65535:
                fields.append({'relative_offset': delta, 'integer': value})
        output['table_references'].append({'relocation_va': va,
            'handler': next(n for n in wanted if n in line), 'small_integer_candidates': fields})
    return output


def main():
    manifest = json.loads((ROOT / 'sony-assets.json').read_text())
    report = {'schema': 'get-file2-static/1', 'usb_access': False, 'firmware_executed': False,
              'complete_wire_mapping': False, 'files': []}
    for name in ('libJiritsu.so', 'libsencore.so', 'libusbcmd.so'):
        relative = 'menu-root/usr/lib/' + name
        path = ROOT / relative
        if path.is_symlink():
            raise ValueError('symlink_input')
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != manifest[relative]['sha256']:
            raise ValueError('identity_mismatch')
        report['files'].append(inspect(path, data))
    encoded = json.dumps(report, separators=(',', ':'))
    if len(encoded) > 180000:
        raise ValueError('report_limit')
    Path('ci-logs/get-file2-static.json').write_text(encoded + '\n')
    print('GET_FILE2_STATIC_METADATA_WRITTEN; no live requests')


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        allowed = {'tool_failed', 'function_fact_limit', 'relocation_mapping',
                   'symlink_input', 'identity_mismatch', 'report_limit', 'dataflow_bound'}
        code = str(exc) if str(exc) in allowed else type(exc).__name__
        print('GET_FILE2_STATIC_FAILED category=' + code)
        raise SystemExit(1)
