"""Bounded static interpretation of one pinned callback's integer switch.

No native execution. Only selector bytes and file-backed ELF table reads exist.
Unsupported operations stop the proof; no guessed successor is accepted.
"""
import re


def follow(instructions, start, selector, read_integer):
    regs = {'x0': 1 << 48, 'sp': 2 << 48}
    compare = None
    pc = start
    def get(name):
        if name in ('xzr', 'wzr'): return 0
        value = regs['x' + name[1:] if name.startswith('w') else name]
        return value & 0xffffffff if name.startswith('w') else value
    def put(name, value):
        regs['x' + name[1:] if name.startswith('w') else name] = value & (0xffffffff if name.startswith('w') else 0xffffffffffffffff)
    def operand(text):
        if text.startswith('#'): return int(text[1:], 0)
        return get(text)
    for _ in range(48):
        op, args = instructions[pc]
        args = args.split("//", 1)[0].strip()
        p = [part.strip() for part in args.split(',')]
        next_pc = pc + 4
        if op in ('stp', 'str'):
            base = re.search(r'\[(sp|x\d+)', args)
            if not base or get(base[1]) != 2 << 48:
                raise ValueError('nonstack_store')
            # Only stack saves/scratch writes are ignored in this prefix.
            pass
        elif op == 'mov':
            put(p[0], operand(p[1]))
        elif op in ('adr', 'adrp'):
            put(p[0], int(p[1].split()[0], 16))
        elif op in ('add', 'sub'):
            value = operand(p[2])
            if len(p) == 4:
                extend = re.fullmatch(r'(lsl|sxtw|uxtw)\s*(?:#(\d+))?', p[3])
                if not extend: raise ValueError('unsupported_extension')
                if extend[1] != 'lsl':
                    value &= 0xffffffff
                    if extend[1] == 'sxtw' and value & 0x80000000: value -= 1 << 32
                value <<= int(extend[2] or 0)
            put(p[0], get(p[1]) + value * (1 if op == 'add' else -1))
        elif op == 'cmp':
            compare = (get(p[0]), operand(p[1]))
        elif op == 'b.hi':
            if compare is None: raise ValueError('missing_comparison')
            if compare[0] > compare[1]: raise ValueError('outside_switch')
        elif op in ('ldrb', 'ldrh', 'ldrsw', 'ldr'):
            match = re.fullmatch(r'([wx]\d+),\s*\[(x\d+)(?:,\s*(#[0-9xa-f]+|[wx]\d+))?(?:,\s*(uxtw|sxtw|lsl)(?:\s*#(\d+))?)?\]', args)
            if not match: raise ValueError('unsupported_load')
            offset = operand(match[3]) if match[3] else 0
            if match[4] == 'sxtw' and offset & 0x80000000: offset -= 1 << 32
            offset <<= int(match[5] or 0)
            address = get(match[2]) + offset
            size = 1 if op == 'ldrb' else 2 if op == 'ldrh' else 4 if op == 'ldrsw' or match[1].startswith('w') else 8
            if address == (1 << 48) + 38 and size == 2:
                value = selector
            else:
                value = read_integer(address, size, op == 'ldrsw')
            put(match[1], value)
        elif op == 'br':
            return {'selector': selector, 'branch_at': pc, 'target': get(args)}
        else:
            raise ValueError('unsupported_operation:' + op)
        pc = next_pc
    raise ValueError('instruction_bound')
