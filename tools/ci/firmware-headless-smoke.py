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
from guest_test_support import close_vm

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
    latest = root / 'runtime/analysis/latest-menu-run.txt'
    if latest.is_file():
        run_path = Path(latest.read_text().strip()).resolve()
        runs = (root / 'runtime/analysis/menu-runs').resolve()
        if run_path.parent == runs and (run_path / 'console.log').is_file():
            private_console = (run_path / 'console.log').read_text(errors='replace')
            result['console_bytes'] = (run_path / 'console.log').stat().st_size
            result['console_flags'] = {name: token.lower() in private_console.lower() for name, token in {
                'missing_file': 'No such file or directory',
                'missing_command': 'command not found',
                'permission_denied': 'Permission denied',
                'operation_denied': 'Operation not permitted',
                'memory_allocation': 'Cannot allocate memory',
                'bwrap_failure': 'bwrap:',
                'qemu_failure': 'qemu-system-aarch64:',
                'invalid_parameter': 'Invalid parameter',
                'unsupported_option': 'unrecognized option',
                'missing_rom': 'Could not load ROM',
                'missing_kernel': 'could not load kernel',
                'missing_bus': 'No bus',
                'unknown_device': 'not a valid device model',
                'seccomp_failure': 'seccomp',
                'socket_failure': 'socket',
                'traceback': 'Traceback (most recent call last)',
                'kernel_started': 'Booting Linux',
            }.items()}
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
        import re
        import subprocess
        tracked = subprocess.check_output(['git', 'ls-files', '-z']).decode().split('\0')
        public_sources = {Path(p).name for p in tracked if p.endswith('.py')}
        result['traceback_frames'] = [
            {'file': Path(path).name, 'line': int(line)}
            for path, line in re.findall(r'File "([^"\n]+\.py)", line (\d+)', private_log)
            if Path(path).name in public_sources][-12:]
        # Strict list of public C/POSIX calls and compiler helpers used by this demo.
        allowed_symbols = set(('memcpy memset memmove memcmp strlen strcmp snprintf dprintf puts '
            'printf fflush _exit syscall __errno_location __stack_chk_fail __memcpy_chk '
            '__memset_chk __snprintf_chk __printf_chk __libc_start_main __libc_csu_init '
            '__libc_csu_fini open close read write fstat stat lstat fchmod fcntl '
            'mkdir unlink rename pipe2 fork waitpid kill clock_gettime poll '
            'getenv setrlimit prctl opendir readdir closedir dirfd dup2 '
            'chroot chdir setgroups setresgid setresuid getuid geteuid stdout').split())
        undefined = re.findall(r'undefined symbol: ([A-Za-z0-9_@.]+)', private_log)
        result['linker_public_symbols'] = sorted(set(undefined) & allowed_symbols)
        result['linker_unlisted_symbol_count'] = sum(name not in allowed_symbols for name in undefined)
        result['compiler_error_locations'] = [
            {'file': name, 'line': int(line), 'column': int(column)}
            for name, line, column in re.findall(r'([A-Za-z0-9_-]+\.c):([0-9]+):([0-9]+): (?:fatal )?error:', private_log)
            if name in ('ram-plugin-boot.c', 'ram-hello.c', 'ramfb-viewer.c')][:16]
        result['linker_error_kinds'] = {kind: kind in private_log for kind in
            ('duplicate symbol', 'undefined symbol', 'relocation', 'unable to find library')}
        result['exception_types'] = re.findall(
            r'^(AssertionError|ValueError|RuntimeError|KeyError|TypeError|NameError|AttributeError|FileNotFoundError|PermissionError|OSError|TimeoutError|ImportError|ModuleNotFoundError):',
            private_log, re.MULTILINE)[-4:]
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
        result['closed'], result['close_attempts'] = close_vm(vm)
    except Exception as exc:
        result['closed'] = False
        result['close_error_type'] = type(exc).__name__
    (out / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
sys.exit(0 if result['passed'] and result.get('closed') else 1)
