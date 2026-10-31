"""Actual disposable guest only; public output is screenshots and fixed results."""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import sys
import time
from PIL import Image

ROOT=Path.cwd()
sys.path.insert(0,str(ROOT/'runtime/analysis'))
from menu_control import VM
from guest_test_support import close_vm

spec=importlib.util.spec_from_file_location('reviewed_firstboot',ROOT/'runtime/analysis/check-natural-gtk-input.py')
firstboot=importlib.util.module_from_spec(spec);spec.loader.exec_module(firstboot)
OUT=ROOT/'ci-firmware-evidence';OUT.mkdir(exist_ok=True)
os.environ.update(A7C2_RAM_PLUGIN='1',MENU_BACKUP_SAVE='0',A7C2_SETTINGS_PERSIST='0')
RESULT={'passed':False,'scope':'FL23 original menu only; CP/ISP color not verified',
        'menu_verified':False,'selection_verified':False,'color_verified':False,'cases':[]}
vm=None
PHASE='start'
last_image=None

def console():
    path=Path(vm.status()['run'])/'console.log'
    return path.read_text(errors='replace') if path.is_file() else ''

def wait(predicate,timeout=40):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        state=vm.status()
        if state['mock'] or state['state'] in ('error','faulted','exited','disconnected'):
            raise RuntimeError('guest_unhealthy')
        if 'FL23_MENU_FATAL' in console():raise RuntimeError('guest_broker_rejected')
        if predicate(state):return state
        time.sleep(.2)
    raise TimeoutError('guest_wait')

def idle():return wait(lambda s:s['state']=='running' and not s['busy'] and not s['pending'])

def command(case):
    idle()
    with vm.lock:vm.plugin_result=None
    vm.enqueue({'action':'ram_plugin','case':case})
    result=wait(lambda s:bool(s['plugin_result']))['plugin_result']
    if result['case']!=case or 'RAM_PLUGIN_RC=0' not in result['output']:
        raise RuntimeError('plugin_request_failed')
    return result['output']

def capture(label):
    global last_image
    before=(idle()['snapshot'] or {}).get('number',0)
    vm.enqueue({'action':'snapshot'})
    wait(lambda s:bool(s['snapshot']) and s['snapshot']['number']>before)
    with vm.lock:data=vm.png
    with Image.open(io.BytesIO(data)) as source:image=source.convert('RGB')
    path=OUT/'fl23-latest.png';path.write_bytes(data)
    last_image={'pixel_sha256':hashlib.sha256(image.tobytes()).hexdigest(),
                'firstboot_ui':firstboot.firstboot_frame(image,console()),'image':str(path)}
    return last_image

def key(name,mouse=False):
    idle();vm.enqueue({'action':'key','key':name});idle();time.sleep(.3)

def start(enabled):
    global vm
    os.environ['A7C2_FL23_MENU']='1' if enabled else '0'
    vm=VM(native_display='none',natural_boot=True,usb_net=True,instance=None)
    vm.start()
    next_progress=0
    def running(state):
        nonlocal next_progress
        if time.monotonic()>=next_progress:
            print(json.dumps({'phase':PHASE,'state':state['state']}),flush=True)
            next_progress=time.monotonic()+30
        return state['state']=='running'
    wait(running,600)
    if vm.status()['settings_persistent']:raise RuntimeError('persistent_instance')
    command('off')
    output=command('fl23_status')
    expected='FL23_BINDINGS fl2=10 fl3=11' if enabled else 'FL23_BINDINGS fl2=0 fl3=0'
    if expected not in output:raise RuntimeError('binding_readback_mismatch')
    ready='FL23_MENU_READY ap_fields=7 backup_bindings=2 permissions_restored=1' in console()
    if ready!=enabled:raise RuntimeError('broker_receipt_mismatch')
    RESULT['cases'].append({'enabled':enabled,'bindings_readback':True,'broker_ready':ready})

def close():
    global vm
    if vm is None:return
    ok,attempts=close_vm(vm)
    RESULT.setdefault('closes',[]).append(attempts)
    if not ok:raise RuntimeError('close_incomplete')
    vm=None

def negative_rollback():
    global vm
    os.environ.update(A7C2_FL23_MENU='1',A7C2_FL23_NEGATIVE='rollback')
    try:
        vm=VM(native_display='none',natural_boot=True,usb_net=True,instance=None)
        vm.start();deadline=time.monotonic()+600;next_progress=0
        while time.monotonic()<deadline:
            text=console()
            if 'FL23_MENU_FATAL' in text:
                if ('FL23_MENU_ROLLBACK complete=1' not in text or
                        'FL23_MENU_FATAL code=11 application_init_called=0' not in text or
                        'FL23_MENU_READY' in text):
                    raise RuntimeError('negative_rollback_unverified')
                RESULT['native_rollback_verified']=True
                close();return
            if vm.status()['state'] in ('error','faulted','exited','disconnected'):
                raise RuntimeError('negative_boot_failed_before_broker')
            if time.monotonic()>=next_progress:
                print(json.dumps({'phase':PHASE,'state':vm.status()['state']}),flush=True)
                next_progress=time.monotonic()+30
            time.sleep(.5)
        raise TimeoutError('negative_broker_wait')
    finally:
        os.environ.pop('A7C2_FL23_NEGATIVE',None)

try:
    PHASE='enabled_boot';start(True)
    initial=capture('language')
    PHASE='language_navigation'
    firstboot.select_simplified_chinese(initial,console,capture,lambda:key('DOWN'),wait)
    PHASE='firstboot_navigation'
    for n in range(30):
        step=firstboot.firstboot_step(last_image,console,capture,key,wait,
                                    lambda:OUT/'fl23-latest.png','fl23-firstboot-'+str(n))
        print(json.dumps({'phase':PHASE,'step':n,'page':step['page']['page']}),flush=True)
        if step['ready']:break
    else:raise RuntimeError('firstboot_incomplete')
    RESULT['firstboot_ready']=True
    PHASE='menu_navigation'
    key('MENU');capture('menu')
    (OUT/'fl23-menu-open.png').write_bytes((OUT/'fl23-latest.png').read_bytes())
    # A real current menu image is required before selecting any unreviewed row.
    # Subsequent iterations add the reviewed navigation and selection assertions.
    RESULT['menu_navigation_pending']=True
    PHASE='negative_rollback';close();negative_rollback()
    PHASE='disabled_restart';start(False);close()
    RESULT['fresh_vm_bindings_restored']=True
except Exception as error:
    RESULT.update(failed_phase=PHASE,error_type=type(error).__name__)
    if vm:
        text=console()
        fatal=re.findall(r'FL23_MENU_FATAL code=(\d+)',text)
        RESULT['broker_error_codes']=[int(code) for code in fatal]
        RESULT['rollback_complete']='FL23_MENU_ROLLBACK complete=1' in text
        RESULT['broker_started']='FL23_MENU_BEGIN' in text
finally:
    try:close()
    except Exception as error:RESULT['close_error_type']=type(error).__name__
    (OUT/'fl23-result.json').write_text(json.dumps(RESULT,indent=2)+'\n')
    print(json.dumps(RESULT),flush=True)
if not RESULT['passed']:raise SystemExit(1)
