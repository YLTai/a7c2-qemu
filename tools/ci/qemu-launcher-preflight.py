#!/usr/bin/env python3
"""Exercise actual launcher isolation/USB/sandbox flags with no firmware input."""
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import sys
ROOT = Path.cwd()
sys.path.insert(0, str(ROOT / 'runtime/analysis'))
from menu_live import connect_in_run
binary_dir = ROOT / 'runtime/sources/qemu-11.1.2/build-sony-ui'
with tempfile.TemporaryDirectory(prefix='qemu-launcher-preflight-') as directory:
    out = Path(directory)
    command = ['bwrap','--unshare-all','--die-with-parent','--new-session','--clearenv',
        '--ro-bind','/usr','/usr','--symlink','usr/lib','/lib','--ro-bind','/lib64','/lib64',
        '--proc','/proc','--dev','/dev','--tmpfs','/tmp',
        '--ro-bind',str(binary_dir),'/tools','--bind',str(out),'/out',
        '--chdir','/','--setenv','LD_LIBRARY_PATH','/tools/usr/lib','--setenv','LC_ALL','C',
        '--setenv','QEMU_SONY_TIMERS','1','--setenv','QEMU_SONY_USB_NET','1',
        '/tools/qemu-system-aarch64','-machine','virt,secure=off,gic-version=2',
        '-cpu','cortex-a35','-smp','1','-m','24576','-nodefaults','-display','none',
        '-device','ramfb,id=a7c2-screen','-monitor','none','-serial','none','-nic','none',
        '-netdev','stream,id=sony_net,addr.type=unix,addr.path=/out/ethernet.sock,server=on',
        '-device','usb-net,id=sony-usb-network,netdev=sony_net',
        '-no-reboot','-sandbox','on','-qmp','unix:/out/qmp.sock,server=on,wait=off',
        '-device','loader,addr=0x40000000,data=0x14000000,data-len=4,cpu-num=0','-S']
    result = {'scope':'synthetic no-firmware launcher preflight','passed':False}
    with (out/'stderr.log').open('wb') as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        try:
            deadline = time.monotonic()+15
            while not (out/'qmp.sock').exists() and process.poll() is None and time.monotonic()<deadline:
                time.sleep(.1)
            result.update(exit_code=process.poll(),socket_exists=(out/'qmp.sock').exists(),
                          deadline_expired=time.monotonic()>=deadline)
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(5)
                connect_in_run(sock,out,'qmp.sock')
                with sock.makefile('rwb') as stream:
                    assert 'QMP' in json.loads(stream.readline())
                    for name in ('qmp_capabilities','quit'):
                        stream.write(json.dumps({'execute':name}).encode()+b'\n');stream.flush()
                        while True:
                            reply=json.loads(stream.readline())
                            if 'event' not in reply:break
                        assert 'return' in reply
            result['passed']=process.wait(timeout=5)==0
        finally:
            if process.poll() is None:
                process.terminate()
                try:process.wait(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.wait()
            result['final_exit_code']=process.returncode
            print(json.dumps(result),flush=True)
            # This process had no firmware, URL or credentials among its inputs.
            if not result['passed']:
                print((out/'stderr.log').read_text(errors='replace'),flush=True)
    if not result['passed']:raise SystemExit(1)
