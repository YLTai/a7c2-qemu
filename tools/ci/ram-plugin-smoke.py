#!/usr/bin/env python3
"""Actual guest tests. Artifacts contain only QEMU screenshots and fixed-schema results."""
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import time
from PIL import Image

ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / 'runtime/analysis'))
from menu_control import VM
from settings_instance import default_instance
from guest_test_support import close_vm, matches_yellow_mask

os.environ['A7C2_RAM_PLUGIN'] = '1'
OUT = ROOT / 'ci-firmware-evidence'
OUT.mkdir(exist_ok=True)
INSTANCE = default_instance(ROOT / 'runtime/analysis/camera-instances')
RESULT = {'scope': 'actual QEMU guest; interpreted bytecode, no native plugin execution',
          'passed': False, 'cases': []}
PHASE = 'start'

def healthy(vm):
    state = vm.status()
    if state['mock'] or state['state'] in ('error', 'faulted', 'exited', 'disconnected'):
        raise RuntimeError('Guest is not healthy')
    return state

def start():
    vm = VM(native_display='none', natural_boot=True, usb_net=True, instance=INSTANCE)
    vm.start()
    return vm

def ready(vm):
    deadline = time.monotonic() + 600
    next_progress = 0
    while time.monotonic() < deadline:
        state = healthy(vm)['state']
        if time.monotonic() >= next_progress:
            print(json.dumps({'phase': 'plugin_guest_start', 'state': state}), flush=True)
            next_progress = time.monotonic() + 30
        if state == 'running':
            return
        time.sleep(2)
    raise TimeoutError('Guest initialization')

def command(vm, case):
    with vm.lock:
        vm.plugin_result = None
    vm.enqueue({'action': 'ram_plugin', 'case': case})
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        reply = healthy(vm)['plugin_result']
        if reply:
            if reply.get('case') != case:
                raise RuntimeError('Unexpected guest response')
            text = reply['output']
            record = {'case': case}
            rejected = re.search(r'RAM_PLUGIN_REJECT case='+case+r' signal=(\d+) exit=(-?\d+) timed_out=(\d) bytes=(\d+)', text)
            if rejected:
                sig, code, timeout, size = map(int, rejected.groups())
                record.update(signal=sig, exit=code, timed_out=bool(timeout), output_bytes=size)
            rc = re.search(r'RAM_PLUGIN_RC=(\d+)', text)
            if rc:
                record['supervisor_exit'] = int(rc.group(1))
            if case == 'hello':
                record['ok'] = 'RAM_PLUGIN_OK uid=65534 no_new_privs=1 engine=bytecode-v1 instruction_budget=4096 wall_limit=3 output=bounded_mask' in text
            elif case == 'off':
                record['ok'] = 'RAM_PLUGIN_OFF' in text
            elif case == 'missing':
                record['ok'] = ('RAM_PLUGIN_REJECT missing/unsafe bytecode' in text
                                and record.get('supervisor_exit') == 1)
            else:
                match = re.search(r'RAM_PLUGIN_REJECT case='+case+r' signal=(\d+) exit=(-?\d+) timed_out=(\d) bytes=(\d+)', text)
                if match:
                    sig, code, timeout, size = map(int, match.groups())
                    record.update(signal=sig, exit=code, timed_out=bool(timeout), output_bytes=size)
                    record['ok'] = (sig == 0 and timeout == 0 and size == 0
                        and record.get('supervisor_exit') == 1 and ((case == 'forbidden' and code == 41) or
                        (case == 'timeout' and code == 43) or
                        (case == 'crash' and code == 42) or
                        (case == 'invalid_elf' and code == 41) or
                        (case == 'malformed' and code == 41)))
            RESULT['cases'].append(record)
            if not record.get('ok'):
                raise RuntimeError('Guest confinement/result check failed')
            return
        time.sleep(.1)
    raise TimeoutError('Guest plugin command')

GLYPHS = ((17,17,17,31,17,17,17),(31,16,16,30,16,16,31),(16,16,16,16,16,16,31),
          (14,17,17,17,17,17,14),(17,17,17,21,21,21,10),(30,17,17,30,20,18,17),
          (30,17,17,17,17,17,30),(0,0,0,0,0,0,0))
LETTERS = (0,1,2,2,3,7,4,3,5,2,6)
# Numeric comparison only: no host-generated image is saved as evidence.
YELLOW_PIXELS = [(16+8+k*12+x*2+dx,16+4+y*2+dy)
    for k, glyph in enumerate(LETTERS) for y in range(7) for x in range(5)
    if GLYPHS[glyph][y] & (16 >> x) for dy in range(2) for dx in range(2)]

def screenshot(vm, overlay, filename):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        before = (healthy(vm)['snapshot'] or {}).get('number', 0)
        vm.enqueue({'action': 'snapshot'})
        while time.monotonic() < deadline:
            state = healthy(vm)
            if state['snapshot'] and state['snapshot']['number'] > before:
                with vm.lock:
                    data = vm.png
                with Image.open(io.BytesIO(data)) as image:
                    pixels = image.convert('RGB')
                    mask_matches = matches_yellow_mask(pixels, YELLOW_PIXELS, overlay)
                    colors = pixels.crop((0,50,640,480)).getcolors(640*480)
                    camera_visible = len(colors) > 1 and sum(count for count,color in colors if max(color)>16) > 500
                if mask_matches and camera_visible:
                    (OUT / filename).write_bytes(data)
                    return hashlib.sha256(data).hexdigest()
                break
            time.sleep(.1)
        time.sleep(.3)
    raise TimeoutError('Actual display did not reach expected overlay state')

vm = None
try:
    vm = start()
    ready(vm)
    for case in ('off','hello','missing','hello','invalid_elf','hello','malformed','hello',
                 'crash','hello','timeout','hello','forbidden','hello'):
        PHASE = case
        print(json.dumps({'phase': 'plugin_case', 'case': case}), flush=True)
        command(vm, case)
        # Verify overlay removal and readdition, not full camera responsiveness.
        digest = screenshot(vm, case == 'hello', 'plugin-'+case+'.png')
        RESULT['cases'][-1]['screenshot_sha256'] = digest
    PHASE = 'restart'
    closed, RESULT['restart_close_attempts'] = close_vm(vm)
    if not closed:
        raise RuntimeError('Normal save/close failed before restart')
    vm = None
    vm = start()
    ready(vm)
    command(vm, 'hello')
    RESULT['restart_screenshot_sha256'] = screenshot(vm, True, 'plugin-restart.png')
    RESULT['restart_passed'] = True
    RESULT['passed'] = True
except Exception as error:
    RESULT.update(failed_phase=PHASE, error_type=type(error).__name__)
finally:
    try:
        RESULT['closed'] = True
        if vm:
            RESULT['closed'], RESULT['close_attempts'] = close_vm(vm)
            if not RESULT['closed']:
                RESULT['passed'] = False
    except Exception as error:
        RESULT.update(closed=False, close_error_type=type(error).__name__, passed=False)
    (OUT / 'plugin-result.json').write_text(json.dumps(RESULT, indent=2)+'\n')
    print(json.dumps(RESULT))
sys.exit(0 if RESULT['passed'] and RESULT['closed'] else 1)
