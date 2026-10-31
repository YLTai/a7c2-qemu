import importlib.util
from pathlib import Path
import unittest
from get_file2_model import HEADER, COMMAND, decode_fixture, handler_hypothesis, stat_sized_read


def packet(command, parameters):
    body = COMMAND.pack(0x1001, command) + parameters
    return HEADER.pack(len(body), 0x40, 1, 0, 0, 0, 0) + body


class ReadFixtures(unittest.TestCase):
    def test_actual_regular_file_requests(self):
        for path in ("/usr/lib/appFw.so", "/cp/cpapp-b.bin"):
            selected = "/tmp/jiritsu/../../" + path.lstrip("/")
            request = decode_fixture(packet(15, b"\0" + selected.encode() + b"\0"))
            self.assertEqual(request["path"], selected)
            self.assertFalse(request["canonical_path_known"])
        request = decode_fixture(packet(17, bytes((0, 255, 0))))
        self.assertEqual((request["medium"], request["selector"], request["transfer"]), (0, 255, 0))
        self.assertEqual(request["first_word"], 0xff00)

    def test_distinguish_mode_and_filename_selector(self):
        ordinary = handler_hypothesis(bytes((0, 255, 0)))
        self.assertTrue(ordinary["mode_zero_mount_path"])
        self.assertFalse(ordinary["log_flush_gate"])
        self.assertTrue(handler_hypothesis(bytes((0, 3, 0)))["log_flush_gate"])
        self.assertFalse(handler_hypothesis(bytes((255, 0, 0)))["mode_zero_mount_path"])

    def test_proc_zero_size_is_not_empty_content_evidence(self):
        content = b"synthetic mountinfo data\n"
        self.assertEqual(stat_sized_read(content, 0), b"")
        self.assertEqual(stat_sized_read(content, len(content)), content)
        self.assertEqual(stat_sized_read(content, 4), b"synt")

    def test_content_does_not_supply_path_metadata(self):
        self.assertFalse(handler_hypothesis(bytes((0, 255, 0)))["path_metadata_available"])

    def test_reject_mutating_commands(self):
        for command in (16, 18):
            with self.assertRaises(ValueError):
                decode_fixture(packet(command, b"\0\xff\0"))

    def test_reject_malformed(self):
        for fixture in (b"", packet(17, b"\0"), packet(17, b"\0\xff\0")[:-1],
                        packet(15, b"\0/a\0b\0"), packet(15, b"\0/a")):
            with self.assertRaises(ValueError):
                decode_fixture(fixture)

    def test_size_bounds(self):
        for size in (-1, 256 * 1024 * 1024 + 1):
            with self.assertRaises(ValueError):
                stat_sized_read(b"", size)


class ProvenanceFixtures(unittest.TestCase):
    @staticmethod
    def trace(lines):
        path = Path(__file__).resolve().parents[1] / "ci/get-file2-static.py"
        spec = importlib.util.spec_from_file_location("get_file2_static", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.trace(lines, 0, max(row[0] for row in lines) + 4)

    def test_early_return_does_not_poison_other_branch(self):
        facts = self.trace([(0, "mov", "x19, x0"), (4, "cbz", "w1, 10"),
                            (8, "ldp", "x19, x20, [sp], #32"), (12, "ret", ""),
                            (16, "ldrh", "w2, [x19, #40]"),
                            (20, "cmp", "w2, #0x300"), (24, "b.ne", "20"),
                            (28, "ret", ""), (32, "ret", "")])
        condition = next(f for f in facts if f["at"] == 24)
        self.assertEqual(condition["comparison"]["lhs_candidate"], "load16(offset(argument0,40))")

    def test_disagreeing_branches_lose_origin(self):
        facts = self.trace([(0, "cbz", "w1, 10"), (4, "mov", "x19, x0"),
                            (8, "b", "14"), (12, "ret", ""),
                            (16, "mov", "x19, x2"), (20, "ldrb", "w3, [x19, #40]"),
                            (24, "ret", "")])
        load = next(f for f in facts if f["at"] == 20)
        self.assertEqual(load["base_candidate"], "unknown")


if __name__ == "__main__":
    unittest.main()
