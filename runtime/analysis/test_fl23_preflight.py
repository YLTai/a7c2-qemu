import struct
import hashlib
import unittest
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

from fl23_preflight import (Rejected, _load_segments, _resolve, inspect_original,
                            require_volatile_profile, validate_launch_request,
                            audit_original, model_mapping_audit, _section_audit, _require_data_pages, FIELDS)


def elf(segments):
    data = bytearray(4096)
    data[:7] = b'\x7fELF\x02\x01\x01'
    struct.pack_into('<HHI', data, 16, 3, 183, 1)
    struct.pack_into('<Q', data, 32, 64)
    struct.pack_into('<HHH', data, 52, 64, 56, len(segments))
    for i, (offset, va, filesz, memsz, flags) in enumerate(segments):
        struct.pack_into('<IIQQQQQQ', data, 64 + 56*i,
                         1, flags, offset, va, 0, filesz, memsz, 1)
    return data


class PreflightTests(unittest.TestCase):
    def test_readonly_model_audit_requires_identity_and_unique_data_mapping(self):
        data=elf([(512,0x1000,512,1024,6)])
        struct.pack_into('<Q',data,40,2048)
        struct.pack_into('<HH',data,58,64,1)
        struct.pack_into('<IIQQQQIIQQ',data,2048,0,1,3,0x1000,512,512,0,0,1,0)
        with self.assertRaisesRegex(Rejected,'^source_identity$'):
            model_mapping_audit(data)
        with patch('fl23_preflight.SOURCE_SHA256',hashlib.sha256(data).hexdigest()), \
             patch('fl23_preflight.MODEL_VA',0x1010):
            result=model_mapping_audit(data)
            self.assertEqual(result['file_offset'],528)
            self.assertTrue(result['nonexec_data'])
        struct.pack_into('<Q',data,2048+8,7)
        with patch('fl23_preflight.SOURCE_SHA256',hashlib.sha256(data).hexdigest()), \
             patch('fl23_preflight.MODEL_VA',0x1010):
            self.assertFalse(model_mapping_audit(data)['nonexec_data'])

    def test_identity_cannot_be_bypassed_with_plausible_elf(self):
        with self.assertRaisesRegex(Rejected, '^source_identity$'):
            inspect_original(elf([(512, 0x9000, 512, 1024, 6)]))
        with self.assertRaisesRegex(Rejected, '^source_identity$'):
            audit_original(elf([(512, 0x9000, 512, 1024, 5)]))

    def test_readonly_audit_does_not_relax_strict_permission_check(self):
        data = elf([(512, 0x9000, 512, 512, 5)])
        fields = [('a', 600, bytes(2), b'\1\1')]
        mappings = _resolve(data, _load_segments(data), fields, audit=True)
        self.assertTrue(mappings[0]['elf_executable'])
        with self.assertRaisesRegex(Rejected, '^field_permissions$'):
            _resolve(data, _load_segments(data), fields)
        self.assertEqual(_section_audit(data, mappings), {'section_table_valid': False})

    def test_section_audit_requires_entire_page_without_executable_alias(self):
        data = bytearray(16384)
        struct.pack_into('<Q', data, 40, 256)
        struct.pack_into('<HH', data, 58, 64, 2)
        struct.pack_into('<IIQQQQIIQQ', data, 320, 0, 1, 2, 0x10000, 4096,
                         4096, 0, 0, 1, 0)
        fields = [('selection', 4096, bytes(2), b'\1\1')]
        mappings = [{'id': 'selection', 'relative_va': 0x10000, 'size': 2}]
        with patch('fl23_preflight.FIELDS', fields):
            self.assertTrue(_section_audit(data, mappings)['fields'][0]['nonexec_data_page_4096'])
            struct.pack_into('<Q', data, 320 + 32, 200)
            self.assertFalse(_section_audit(data, mappings)['fields'][0]['nonexec_data_page_4096'])
            struct.pack_into('<Q', data, 320 + 32, 4096)
            struct.pack_into('<Q', data, 320 + 8, 6)
            self.assertFalse(_section_audit(data, mappings)['fields'][0]['nonexec_data_page_4096'])
            struct.pack_into('<Q', data, 320 + 8, 2)
            struct.pack_into('<IIQQQQIIQQ', data, 256, 0, 1, 6, 0x10000,
                             8192, 16, 0, 0, 1, 0)
            self.assertFalse(_section_audit(data, mappings)['fields'][0]['nonexec_data_page_4096'])

    def test_rx_segment_requires_positive_nonexec_data_page_proof(self):
        fields = [dict(id=name, elf_readable=True, elf_executable=True,
                       unique_allocated_section=True, nonexec_data_page_4096=True)
                  for name, _, _, _ in FIELDS]
        self.assertEqual(_require_data_pages({'section_table_valid': True, 'fields': fields}), fields)
        for property_name in ('elf_readable', 'unique_allocated_section', 'nonexec_data_page_4096'):
            invalid = [dict(field) for field in fields]
            invalid[-1][property_name] = False
            with self.assertRaisesRegex(Rejected, '^field_permissions$'):
                _require_data_pages({'section_table_valid': True, 'fields': invalid})
        with self.assertRaisesRegex(Rejected, '^section_metadata$'):
            _require_data_pages({'section_table_valid': False})

    def test_segment_mapping_is_not_a_global_delta(self):
        data = elf([(512, 0x9000, 512, 1024, 6), (2048, 0x18000, 512, 512, 4)])
        result = _resolve(data, _load_segments(data),
                          [('a', 600, bytes(2), b'\1\1'),
                           ('b', 2050, bytes(4), b'\1\0\0\0')])
        self.assertEqual([r['relative_va'] for r in result], [0x9058, 0x18002])
        self.assertEqual([r['elf_writable'] for r in result], [True, False])

    def test_mapping_rejections(self):
        field = [('a', 600, bytes(2), b'\1\1')]
        cases = [
            ([(512, 0x9000, 88, 512, 6)], 'field_mapping'),  # BSS is not file data
            ([(512, 0x9000, 89, 512, 6)], 'field_mapping'),  # crosses file extent
            ([(512, 0x9000, 512, 512, 5)], 'field_permissions'),
            ([(512, 0x9000, 512, 512, 2)], 'field_permissions'),
            ([(512, 0x9000, 512, 512, 6), (512, 0xa000, 512, 512, 6)], 'field_mapping'),
            ([(512, 0x9000, 512, 512, 6), (2048, 0x9000, 512, 512, 6)], 'field_alias'),
        ]
        for segments, error in cases:
            with self.subTest(error=error), self.assertRaisesRegex(Rejected, '^'+error+'$'):
                data = elf(segments)
                _resolve(data, _load_segments(data), field)
        data = elf([(512, 0x9000, 512, 512, 6)])
        data[600] = 5
        with self.assertRaisesRegex(Rejected, '^field_original$'):
            _resolve(data, _load_segments(data), field)

    def test_malformed_elf(self):
        for segments in ([(512, 0x9000, 512, 32, 6)],
                         [(4000, 0x9000, 512, 512, 6)],
                         [(512, (1 << 64)-128, 512, 512, 6)]):
            with self.assertRaisesRegex(Rejected, '^elf_segment$'):
                _load_segments(elf(segments))
        data = elf([(512, 0x9000, 512, 512, 6)])
        for truncated in (data[:1], data[:63], data[:100]):
            with self.assertRaises(Rejected):
                _load_segments(truncated)
        struct.pack_into('<H', data, 18, 62)
        with self.assertRaisesRegex(Rejected, '^elf_target$'):
            _load_segments(data)

    def test_persistence_and_restore_are_rejected(self):
        require_volatile_profile({})
        require_volatile_profile({'MENU_BACKUP_SAVE': '0', 'A7C2_SETTINGS_PERSIST': '0'})
        for key in ('MENU_BACKUP_SAVE', 'A7C2_SETTINGS_PERSIST'):
            for value in ('1', 'true', '', '2'):
                with self.subTest(key=key, value=value):
                    with self.assertRaisesRegex(Rejected, '^persistent_profile$'):
                        validate_launch_request({'A7C2_FL23_MENU': '1', key: value})
        with self.assertRaisesRegex(Rejected, '^restore_profile$'):
            require_volatile_profile({'A7C2_SETTINGS_RESTORE': '/unused'})

    def test_enable_is_a_request_not_a_firmware_verification(self):
        validate_launch_request({})
        validate_launch_request({'A7C2_FL23_MENU': '0', 'MENU_BACKUP_SAVE': '1'})
        self.assertTrue(validate_launch_request({'A7C2_FL23_MENU': '1'}))
        with self.assertRaisesRegex(Rejected, '^invalid_menu_request$'):
            validate_launch_request({'A7C2_FL23_MENU': 'yes'})
        with self.assertRaisesRegex(Rejected, '^persistent_profile$'):
            validate_launch_request({'A7C2_FL23_AUDIT':'1','A7C2_SETTINGS_PERSIST':'1'})
        with self.assertRaisesRegex(Rejected, '^invalid_menu_audit$'):
            validate_launch_request({'A7C2_FL23_AUDIT':'yes'})

    def test_launcher_rejects_before_loading_guest_dependencies(self):
        launcher = Path(__file__).with_name('qemu-menu-probe.py')
        for key, expected in (('MENU_BACKUP_SAVE', 'persistent_profile'),
                              ('A7C2_SETTINGS_PERSIST', 'persistent_profile')):
            env = dict(os.environ, A7C2_FL23_MENU='1', MENU_BACKUP_SAVE='0',
                       A7C2_SETTINGS_PERSIST='0', A7C2_SETTINGS_RESTORE='')
            if key:
                env[key] = '1'
            result = subprocess.run([sys.executable, str(launcher), '--help'],
                                    env=env, capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, '')
            self.assertIn('fl23_preflight.Rejected: '+expected, result.stderr)

    def test_controller_refuses_persistent_or_mock_fl23_instances(self):
        from menu_control import VM
        with patch.dict(os.environ, {'A7C2_FL23_MENU':'1', 'MENU_BACKUP_SAVE':'0',
                                     'A7C2_SETTINGS_PERSIST':'0', 'A7C2_SETTINGS_RESTORE':''}):
            for args in ({'instance':object(),'natural_boot':True},
                         {'natural_boot':False},
                         {'command':['not-executed'],'natural_boot':True}):
                with self.assertRaisesRegex(ValueError,'disposable'):
                    VM(**args)
            self.assertFalse(VM(natural_boot=True).status()['settings_persistent'])


if __name__ == '__main__':
    unittest.main()
