import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'ci'))
from jiritsu_dispatch import follow

class Dispatch(unittest.TestCase):
    def test_two_table_targets_and_bounds(self):
        code = {0: ('ldrh', 'w0, [x0, #38]'), 4: ('sub', 'w0, w0, #1'),
                8: ('cmp', 'w0, #1'), 12: ('b.hi', '100'),
                16: ('adrp', 'x1, 1000'), 20: ('ldrb', 'w0, [x1, w0, uxtw]'),
                24: ('adr', 'x1, 200'), 28: ('add', 'x0, x1, w0, sxtw #2'),
                32: ('br', 'x0')}
        def table(address, size, signed):
            self.assertEqual(size, 1); self.assertFalse(signed)
            return {4096: 3, 4097: 5}[address]
        self.assertEqual(follow(code, 0, 1, table)['target'], 0x20c)
        self.assertEqual(follow(code, 0, 2, table)['target'], 0x214)
        with self.assertRaises(ValueError): follow(code, 0, 3, table)
    def test_disassembler_immediate_comment_is_not_an_operand(self):
        edge = follow({0: ('mov', 'x0, #0x40 // #64'), 4: ('br', 'x0')},
                      0, 1, lambda *args: 0)
        self.assertEqual(edge['target'], 64)
    def test_unsupported_stops(self):
        with self.assertRaises(ValueError): follow({0: ('blr', 'x0')}, 0, 1, lambda *args: 0)
