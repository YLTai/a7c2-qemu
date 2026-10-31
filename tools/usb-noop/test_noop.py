import hashlib
import subprocess
import sys
import unittest
from pathlib import Path

import noop


class OfflineContract(unittest.TestCase):
    payload = b'non-executable fixture'
    digest = hashlib.sha256(payload).hexdigest()

    def run_case(self, fault='none', **kwargs):
        link = noop.Simulation(fault)
        report = noop.simulate_once(link, self.payload, self.digest, **kwargs)
        return link, report

    def test_success_and_no_residue(self):
        link, report = self.run_case()
        self.assertEqual(report['cleanup'], 'verified_absent')
        self.assertEqual(report['outcome'], 'passed')
        self.assertEqual(link.invocations, 1)
        self.assertEqual(link.files, {})

    def test_unknown_dispatch_never_retries_or_cleans(self):
        for fault in ('invoke_timeout', 'result_timeout', 'bad_result'):
            with self.subTest(fault=fault):
                link, report = self.run_case(fault)
                self.assertEqual(report['execution'], 'unknown')
                self.assertEqual(report['outcome'], 'needs_review')
                self.assertEqual(link.invocations, 1)
                self.assertFalse(any(op == 'remove' for op, _ in link.operations))
                before = list(link.operations)
                with self.assertRaises(ValueError):
                    noop.simulate_once(link, self.payload, self.digest)
                self.assertEqual(link.operations, before)

    def test_staging_timeout_is_not_execution(self):
        link, report = self.run_case('stage_timeout')
        self.assertEqual(link.invocations, 0)
        self.assertEqual(report['execution'], 'not_started')
        self.assertEqual(report['cleanup'], 'pending')
        self.assertIn(noop.STAGE, link.files)

    def test_cleanup_timeout_keeps_known_execution_separate(self):
        link, report = self.run_case('cleanup_timeout')
        self.assertEqual(report['execution'], 'returned_in_simulation')
        self.assertEqual(report['cleanup'], 'pending')
        self.assertEqual(report['failed_phase'], 'cleanup')
        self.assertEqual(link.operations[-1], ('remove', noop.RESULT))

    def test_wrong_identity_no_io(self):
        for args in ({'model': 'ILCE-7M4'}, {'version': '2.02'}):
            link, report = self.run_case(**args)
            self.assertEqual(report['outcome'], 'rejected')
            self.assertEqual(link.operations, [])

    def test_wrong_hash_no_io(self):
        link = noop.Simulation()
        report = noop.simulate_once(link, self.payload, '0' * 64)
        self.assertEqual(report['reason'], 'payload_identity_mismatch')
        self.assertEqual(link.operations, [])

    def test_stale_state_is_preserved(self):
        for name in noop.NAMES:
            link = noop.Simulation()
            link.files[name] = b'unknown owner'
            report = noop.simulate_once(link, self.payload, self.digest)
            self.assertEqual(report['reason'], 'existing_file_requires_review')
            self.assertEqual(link.files, {name: b'unknown owner'})
            self.assertFalse(any(op != 'read' for op, _ in link.operations))

    def test_elapsed_budget_stops_before_command(self):
        ticks = iter((0, 6))
        link, report = self.run_case(clock=lambda: next(ticks))
        self.assertEqual(report['outcome'], 'needs_review')
        self.assertEqual(link.operations, [])

    def test_reject_real_transport(self):
        with self.assertRaises(ValueError):
            noop.simulate_once(object(), self.payload, self.digest)

    def test_cli_default_and_even_confirmed_hardware_are_offline(self):
        path = Path(noop.__file__)
        for args, code in (([], 0), (['--simulate'], 0),
                           (['--execute-camera', '--confirm', 'I_ACCEPT'], 2)):
            completed = subprocess.run([sys.executable, '-I', str(path), *args],
                                       capture_output=True, text=True, timeout=5)
            self.assertEqual(completed.returncode, code, completed.stderr)
            self.assertNotIn('usb', sys.modules)


if __name__ == '__main__':
    unittest.main()
