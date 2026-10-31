"""Read-only FL23 menu preflight. Never patches an ELF or prints firmware data.

Research facts: QAQLeonard/a7c2-fl23-research@ef7db116e13e37be91e9af20360dc9bba8d64a9b,
src/fl23/assets/patches.json. Independent implementation; menu data only.
Run against the verified original appFw.so in private CI staging, not artifacts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct

SOURCE_SHA256 = '2ea02f7ecbc5bb917316fe8ef4ce5ffd87eb66efaae78ba2ce11420552df539b'
# Fixed semantic IDs; neither offsets nor replacement values are caller inputs.
FIELDS = (
    ('selection', 0x4b2ed19, bytes(2), b'\x01\x01'),
    ('fl2_fade', 0x4b3b544, bytes(4), b'\x01\x00\x00\x00'),
    ('fl3_fade', 0x4b3b54c, bytes(4), b'\x01\x00\x00\x00'),
    ('fl2_binding', 0x4b4a5e4, bytes(4), b'\x0a\x00\x00\x00'),
    ('fl3_binding', 0x4b4a5ec, bytes(4), b'\x0b\x00\x00\x00'),
    ('fl2_visible', 0x59892ca, bytes(2), b'\x01\x00'),
    ('fl3_visible', 0x5989382, bytes(2), b'\x01\x00'),
)


class Rejected(ValueError):
    """Fixed diagnostic code only; never include firmware contents or paths."""


def require_volatile_profile(env):
    # Reject malformed settings as well as enabled ones. Do not silently override
    # a user's persistent profile and accidentally claim it was tested.
    for name in ('MENU_BACKUP_SAVE', 'A7C2_SETTINGS_PERSIST'):
        if env.get(name, '0') != '0':
            raise Rejected('persistent_profile')
    if env.get('A7C2_SETTINGS_RESTORE'):
        raise Rejected('restore_profile')


def validate_launch_request(env):
    mode = env.get('A7C2_FL23_MENU', '0')
    audit = env.get('A7C2_FL23_AUDIT', '0')
    if audit not in ('0','1'):
        raise Rejected('invalid_menu_audit')
    if mode == '0':
        if audit=='1':require_volatile_profile(env)
        return
    if mode != '1':
        raise Rejected('invalid_menu_request')
    require_volatile_profile(env)
    # Enabling is only a request. The launcher must additionally verify the
    # original ELF and selected initramfs; the guest independently verifies live
    # mappings, Backup originals and the volatile module-load receipt.
    return True


def _load_segments(data):
    if len(data) < 64 or data[:7] != b'\x7fELF\x02\x01\x01':
        raise Rejected('elf_format')
    kind, machine, version = struct.unpack_from('<HHI', data, 16)
    phoff = struct.unpack_from('<Q', data, 32)[0]
    ehsize, phsize, phnum = struct.unpack_from('<HHH', data, 52)
    if (kind, machine, version, ehsize, phsize) != (3, 183, 1, 64, 56):
        raise Rejected('elf_target')
    if not 0 < phnum <= 128 or phoff < 64 or phoff + phnum * phsize > len(data):
        raise Rejected('elf_headers')
    segments = []
    for n in range(phnum):
        typ, flags, offset, va, _, filesz, memsz, align = struct.unpack_from(
            '<IIQQQQQQ', data, phoff + n * phsize)
        if typ != 1:
            continue
        if (filesz > memsz or offset + filesz > len(data) or
                va + memsz >= 1 << 64 or flags & ~7 or
                (align not in (0, 1) and (align & (align - 1) or
                                          va % align != offset % align))):
            raise Rejected('elf_segment')
        segments.append((offset, va, filesz, memsz, flags))
    if not segments:
        raise Rejected('elf_no_load')
    return segments


def _resolve(data, segments, fields, *, audit=False):
    result = []
    for name, offset, before, after in fields:
        size = len(before)
        matches = [s for s in segments if s[0] <= offset and offset + size <= s[0] + s[2]]
        if len(matches) != 1:
            raise Rejected('field_mapping')
        start, va, _, _, flags = matches[0]
        # Readable non-executable data only; do not make code writable.
        if not audit and (not flags & 4 or flags & 1):
            raise Rejected('field_permissions')
        live = va + offset - start
        if sum(s[1] <= live and live + size <= s[1] + s[3] for s in segments) != 1:
            raise Rejected('field_alias')
        if data[offset:offset + size] != before or len(after) != size:
            raise Rejected('field_original')
        result.append({'id': name, 'relative_va': live, 'size': size,
                       'elf_writable': bool(flags & 2),
                       'elf_readable': bool(flags & 4),
                       'elf_executable': bool(flags & 1)})
    return result


def _section_audit(data, mappings):
    """Metadata only; cannot authorize a guest write or relax strict preflight."""
    shoff = struct.unpack_from('<Q', data, 40)[0]
    shsize, shnum = struct.unpack_from('<HH', data, 58)
    if (shsize != 64 or not 0 < shnum < 65535 or shoff < 64 or
            shoff + shnum * shsize > len(data)):
        return {'section_table_valid': False}
    sections = []
    for i in range(shnum):
        _, typ, flags, va, offset, size, _, _, _, _ = struct.unpack_from(
            '<IIQQQQIIQQ', data, shoff + i * shsize)
        if va + size >= 1 << 64 or (typ != 8 and offset + size > len(data)):
            return {'section_table_valid': False}
        sections.append((typ, flags, va, offset, size))
    result = []
    for mapping, (_, offset, before, _) in zip(mappings, FIELDS):
        va = mapping['relative_va']
        matches = [s for s in sections if s[1] & 2 and s[0] != 8 and
                   s[3] <= offset and offset + len(before) <= s[3] + s[4] and
                   s[2] + offset - s[3] == va]
        page_start = va & ~4095
        page_end = (va + len(before) + 4095) & ~4095
        data_page = (len(matches) == 1 and matches[0][0] == 1 and
                     not matches[0][1] & 4 and matches[0][2] <= page_start and
                     page_end <= matches[0][2] + matches[0][4] and
                     not any(s[1] & 6 == 6 and s[2] < page_end and
                             page_start < s[2] + s[4] for s in sections))
        result.append({**mapping, 'unique_allocated_section': len(matches) == 1,
                       'nonexec_data_page_4096': bool(data_page)})
    return {'section_table_valid': True, 'fields': result}


def audit_original(data):
    # Fixed-field metadata only. In particular, this does not return instructions
    # or permit an unknown image merely because its program headers look valid.
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise Rejected('source_identity')
    mappings = _resolve(data, _load_segments(data), FIELDS, audit=True)
    return _section_audit(data, mappings)


def inspect_original(data):
    # Identity check precedes ELF inspection; no user-selectable digest bypass.
    audit = audit_original(data)
    return _require_data_pages(audit)


def _require_data_pages(audit):
    # RX PT_LOAD can contain non-executable rodata. This proves original ELF
    # layout only; the future guest adapter must verify actual maps and perform
    # bounded RX->RW->RX transitions, never W+X, before writing those pages.
    if not audit.get('section_table_valid'):
        raise Rejected('section_metadata')
    fields = audit['fields']
    if len(fields) != len(FIELDS) or any(
            not f['elf_readable'] or not f['unique_allocated_section'] or
            not f['nonexec_data_page_4096'] for f in fields):
        raise Rejected('field_permissions')
    return fields


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('original_appfw', type=Path)
    args = parser.parse_args()
    try:
        require_volatile_profile(os.environ)
        data = args.original_appfw.read_bytes()
        fields = inspect_original(data)
    except Rejected as error:
        result = {'passed': False, 'reason': str(error), 'guest_enabled': False}
        if str(error) == 'field_permissions':
            try:
                result['mapping_audit'] = audit_original(data)
            except Rejected as audit_error:
                result['audit_reason'] = str(audit_error)
        print(json.dumps(result))
        return 1
    except OSError:
        print(json.dumps({'passed': False, 'reason': 'source_unavailable'}))
        return 1
    # Only fixed-schema status is public; no memory contents, file path or maps.
    print(json.dumps({'passed': True, 'scope': 'original_elf_menu_data_only',
                      'fields_verified': len(fields), 'guest_enabled': False,
                      'fields_requiring_permission_transition': sum(
                          not f['elf_writable'] or f['elf_executable'] for f in fields)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
