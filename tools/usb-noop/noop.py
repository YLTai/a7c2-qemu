#!/usr/bin/env python3
"""Offline planning and fault simulation. Intentionally contains no USB backend."""
import argparse
import hashlib
import json
import secrets
import time

MODEL = 'ILCE-7CM2'
VERSION = '2.01'
STAGE = 'a7c2.noop.staged.so'
REQUEST = 'a7c2.noop.request'
TRIGGER = 'libJit.so'
RESULT = 'a7c2.noop.result'
NAMES = (STAGE, REQUEST, TRIGGER, RESULT)


def plan():
    return {
        'mode': 'offline', 'camera_access_enabled': False,
        'model': MODEL, 'firmware': VERSION,
        'directory': '/tmp/jiritsu', 'files': list(NAMES),
        'execution': 'DT_INIT in service process; return to loader, never exit',
        'trigger': 'uploading libJit.so may execute before upload reply',
        'blocked_on': ['live mount and canonical path evidence before upload',
                       'loader and startup residual-file consumption audit',
                       'fresh firmware/model proof and fixed reviewed payload hash'],
        'automatic_retry': False, 'reboot_cleanup_guaranteed': False,
    }


class Simulation:
    """In-memory fault model, not a camera transport or protocol emulator."""
    def __init__(self, fault='none'):
        self.files = {}
        self.fault = fault
        self.invocations = 0
        self.operations = []

    def read(self, name, deadline):
        self.operations.append(('read', name))
        if name == RESULT and self.invocations and self.fault == 'result_timeout':
            raise TimeoutError('simulated lost result response')
        return self.files.get(name)

    def put(self, name, value, deadline):
        self.operations.append(('put', name))
        self.files[name] = value
        if name != TRIGGER:
            if self.fault == 'stage_timeout' and name == STAGE:
                raise TimeoutError('simulated upload response loss')
            return
        self.invocations += 1
        if self.fault == 'invoke_timeout':
            raise TimeoutError('simulated trigger response loss; execution unknown')
        del self.files[TRIGGER]
        nonce = self.files[REQUEST][8:24]
        self.files[RESULT] = b'A7NOPR01' + nonce + bytes(8)
        if self.fault == 'bad_result':
            self.files[RESULT] = b'bad'

    def remove(self, name, deadline):
        self.operations.append(('remove', name))
        if self.fault == 'cleanup_timeout':
            raise TimeoutError('simulated delete response loss')
        self.files.pop(name, None)


def simulate_once(link, payload, digest, model=MODEL, version=VERSION,
                  budget=5, clock=time.monotonic):
    # This interface deliberately accepts only the built-in offline model.
    if type(link) is not Simulation:
        raise ValueError('Real transports are disabled pending lifecycle evidence')
    if getattr(link, '_used', False):
        raise ValueError('Session consumed; no automatic retry')
    link._used = True
    result = {'simulation': True, 'execution': 'not_started',
              'cleanup': 'not_needed', 'outcome': 'rejected'}
    if model != MODEL or version != VERSION:
        return result | {'reason': 'model_or_version_mismatch'}
    if not payload or len(payload) > 65536 or hashlib.sha256(payload).hexdigest() != digest:
        return result | {'reason': 'payload_identity_mismatch'}
    if not 0 < budget <= 30:
        return result | {'reason': 'invalid_budget'}
    deadline = clock() + budget

    def exchange(method, *args):
        if clock() >= deadline:
            raise TimeoutError('session deadline expired')
        value = method(*args, deadline)
        if clock() >= deadline:
            raise TimeoutError('reply arrived after session deadline')
        return value

    phase = 'preflight'
    try:
        for name in NAMES:
            if exchange(link.read, name) is not None:
                return result | {'reason': 'existing_file_requires_review'}
        nonce = secrets.token_bytes(16)
        request = b'A7NOPQ01' + nonce + bytes(8)
        owned = {STAGE: payload, REQUEST: request, TRIGGER: payload}
        phase = 'staging'
        result['cleanup'] = 'pending'
        for name in (STAGE, REQUEST):
            exchange(link.put, name, owned[name])
            if exchange(link.read, name) != owned[name]:
                raise ValueError('staging_readback_mismatch')
        phase = 'invoking'
        # Set uncertainty BEFORE dispatch: upload and execution are not separate.
        result['execution'] = 'unknown'
        exchange(link.put, TRIGGER, payload)
        raw = exchange(link.read, RESULT)
        if raw != b'A7NOPR01' + nonce + bytes(8):
            raise ValueError('result_not_verified')
        result['execution'] = 'returned_in_simulation'
        owned[RESULT] = raw
        phase = 'cleanup'
        for name in reversed(NAMES):
            actual = exchange(link.read, name)
            if actual is not None:
                if actual != owned[name]:
                    raise ValueError('preserve_unexpected_file')
                exchange(link.remove, name)
            if exchange(link.read, name) is not None:
                raise ValueError('cleanup_not_verified')
        result.update(outcome='passed', cleanup='verified_absent')
    except (TimeoutError, ValueError) as exc:
        # No further remote cleanup, rescue, or execution after uncertain I/O.
        result.update(outcome='needs_review', reason=str(exc), failed_phase=phase)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--simulate', action='store_true')
    parser.add_argument('--execute-camera', action='store_true')
    parser.add_argument('--confirm', default='')
    parser.add_argument('--model', default=MODEL)
    parser.add_argument('--firmware', default=VERSION)
    args = parser.parse_args()
    if args.execute_camera:
        print(json.dumps(plan() | {'outcome': 'blocked',
              'reason': 'Camera execution is not implemented or authorized in this stage'}))
        return 2
    if args.simulate:
        # Non-executable fixture, never an uploadable native payload.
        fixture = b'OFFLINE-NONEXECUTABLE-NOOP-FIXTURE'
        report = simulate_once(Simulation(), fixture, hashlib.sha256(fixture).hexdigest(),
                               args.model, args.firmware)
    else:
        report = plan()
    print(json.dumps(report, indent=2))
    return 0 if report.get('outcome', 'passed') == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
