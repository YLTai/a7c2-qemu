#!/usr/bin/env python3
"""Draft: real existing VM controller; no mock, firmware caches or memory dumps."""
import hashlib
import json
from pathlib import Path
import sys
import time

root = Path.cwd()
sys.path.insert(0, str(root / 'runtime/analysis'))
from menu_control import VM
from settings_instance import default_instance

out = root / 'ci-firmware-evidence'
out.mkdir(exist_ok=True)
instance = default_instance(root / 'runtime/analysis/camera-instances')
vm = VM(native_display='none', natural_boot=True, usb_net=True, instance=instance)
result = {'scope': 'real Sony firmware headless boot; no plugin tested', 'passed': False}
try:
    vm.start()
    deadline = time.monotonic() + 600
    requested = False
    last_snapshot = 0
    next_progress = 0
    while time.monotonic() < deadline:
        state = vm.status()
        if time.monotonic() >= next_progress:
            print(json.dumps({'phase': 'boot', 'state': state['state'], 'elapsed_seconds': int(600 - deadline + time.monotonic())}), flush=True)
            next_progress = time.monotonic() + 30
        if state['mock']:
            raise RuntimeError('Mock VM is forbidden')
        if state['state'] in ('error', 'faulted', 'exited', 'disconnected'):
            raise RuntimeError('VM did not reach a healthy boot: ' + state['state'])
        if state['state'] == 'running' and not requested:
            vm.enqueue({'action': 'snapshot'})
            requested = True
        if state['snapshot'] and not state['stale'] and state['snapshot']['number'] > last_snapshot:
            with vm.lock:
                data = vm.png
            if not data:
                raise RuntimeError('No actual VM image returned')
            last_snapshot = state['snapshot']['number']
            requested = False
            import io
            from PIL import Image
            with Image.open(io.BytesIO(data)) as picture:
                colors = picture.convert('RGB').getcolors(640*480)
            if len(colors) < 2 or sum(count for count, color in colors if max(color) > 16) < 500:
                time.sleep(2)
                continue
            (out / 'firmware-screen.png').write_bytes(data)
            result.update(passed=True, snapshot=state['snapshot'],
                          screenshot_sha256=hashlib.sha256(data).hexdigest(),
                          run_directory=state['run'], state=state['state'])
            break
        if requested and not state['busy'] and not state['pending'] and not state['snapshot']:
            requested = False
        time.sleep(2)
    if not result['passed']:
        raise RuntimeError('Timed out waiting for a verified actual VM frame')
except Exception as exc:
    result['error_type'] = type(exc).__name__
    result['vm_state'] = vm.status()['state']
    # Only fixed diagnostic flags; never publish exception or guest log text.
    state = vm.status()
    private_error = state.get('error', '')
    result['diagnostics'] = {name: token in private_error for name, token in {
        'usb_anchor_changed': 'Native USB launcher anchor changed',
        'missing_file': 'No such file or directory',
        'permission_denied': 'Permission denied',
        'control_eof': 'EOF',
        'control_timeout': 'timed out',
        'profile_conflict': 'Natural imaging requires',
    }.items()}
    log_path = state.get('log')
    if log_path and Path(log_path).is_file():
        private_log = Path(log_path).read_text(errors='replace')
        result['log_bytes'] = Path(log_path).stat().st_size
        result['log_flags'] = {name: token in private_log for name, token in {
            'observer_build_failed': 'observer build failed',
            'initramfs_build_failed': 'initramfs build failed',
            'rebuild_completed': 'rebuilt observer + initramfs',
            'missing_file': 'No such file or directory',
            'permission_denied': 'Permission denied',
            'clang_error': 'clang: error:',
            'linker_error': 'ld.lld: error:',
            'python_traceback': 'Traceback (most recent call last)',
            'bwrap_error': 'bwrap:',
        }.items()}
finally:
    try:
        vm.close()
        result['closed'] = True
    except Exception as exc:
        result['closed'] = False
        result['close_error_type'] = type(exc).__name__
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
sys.exit(0 if result['passed'] and result.get('closed') else 1)
