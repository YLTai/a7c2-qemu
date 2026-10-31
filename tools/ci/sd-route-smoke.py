"""Synthetic multithreaded loader in real QEMU guest, alongside original UI.
No Sony USB loader claim, hardware access, native memory bridge or overlay.
"""
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
from menu_live import KEYS
from guest_test_support import close_vm
spec=importlib.util.spec_from_file_location('firstboot',ROOT/'runtime/analysis/check-natural-gtk-input.py')
firstboot=importlib.util.module_from_spec(spec);spec.loader.exec_module(firstboot)
os.environ.update(A7C2_RAM_PLUGIN='1',MENU_BACKUP_SAVE='0',A7C2_SETTINGS_PERSIST='0',A7C2_FL23_MENU='0',A7C2_FL23_AUDIT='1')
OUT=ROOT/'ci-firmware-evidence';OUT.mkdir(exist_ok=True)
result={'schema':'sd-route-guest/1','passed':False,'sony_usb_loader_verified':False,
        'hardware_access':False,'native_plugin':True,'malicious_native_sandbox':False}
vm=None
phase='start'
def wait(predicate,timeout=60):
    end=time.monotonic()+timeout;progress=0
    while time.monotonic()<end:
        s=vm.status()
        if s['mock'] or s['state'] in ('error','faulted','exited','disconnected'):raise RuntimeError('guest_unhealthy')
        if predicate(s):return s
        if time.monotonic()>progress:
            print(json.dumps({'phase':phase,'state':s['state']}),flush=True);progress=time.monotonic()+30
        time.sleep(.2)
    raise TimeoutError('guest_wait')
def idle():return wait(lambda s:s['state']=='running' and not s['busy'] and not s['pending'])
def console():
    p=Path(vm.status()['run']).resolve()
    if p.parent!=(ROOT/'runtime/analysis/menu-runs').resolve():raise RuntimeError('private_run_path')
    return (p/'console.log').read_text(errors='replace')
def command(case):
    idle()
    with vm.lock:vm.plugin_result=None
    vm.enqueue({'action':'ram_plugin','case':case})
    reply=wait(lambda s:bool(s['plugin_result']),90)['plugin_result']
    if reply['case']!=case:raise RuntimeError('wrong_reply')
    return reply['output']
def capture(label):
    before=(idle()['snapshot'] or {}).get('number',0)
    vm.enqueue({'action':'snapshot'})
    wait(lambda s:s['snapshot'] and s['snapshot']['number']>before)
    with vm.lock:data=vm.png
    image=Image.open(io.BytesIO(data)).convert('RGB')
    page=firstboot.firstboot_frame(image,console())
    (OUT/f'sd-route-{label}.png').write_bytes(data)
    return page,hashlib.sha256(image.crop((0,52,640,480)).tobytes()).hexdigest()
def key(name):
    before=len(console());idle();vm.enqueue({'action':'key','key':name});idle()
    def edges(_):
        records=re.findall(r'INPUT_EVENT32 n=(\d+) tid=\d+ words=\[([^]\r\n]+)\]',console()[before:])
        flags=[]
        for n,words in records:
            row=[int(w,0) for w in words.split(',')]
            if row in ([int(KEYS[name],0),0,1,0,0,0,0,0],[int(KEYS[name],0),0,0,0,0,0,0,0]):flags.append(row[2])
        return flags==[1,0]
    wait(edges);time.sleep(1)
def ui(label):
    page,a=capture(label+'-before')
    if page['screen_id']!=301:raise RuntimeError('expected_original_language_screen')
    key('DOWN');page,b=capture(label+'-down')
    if page['screen_id']!=301 or a==b:raise RuntimeError('original_ui_no_change')
    key('UP');page,c=capture(label+'-restored')
    if page['screen_id']!=301 or a!=c:raise RuntimeError('original_ui_not_restored')
    return {'screen_id':301,'native_press_release':True,'selection_changed':True,'selection_restored':True,'crop_sha256':a}
def start():
    global vm
    vm=VM(native_display='none',natural_boot=True,usb_net=True,instance=None);vm.start()
    wait(lambda s:s['state']=='running',600)
    if vm.status()['settings_persistent']:raise RuntimeError('persistent_settings')
    if 'RAM_PLUGIN_RC=0' not in command('off'):raise RuntimeError('overlay_off')
def close():
    global vm
    if vm:
        ok,attempts=close_vm(vm);result.setdefault('closes',[]).append(attempts)
        if not ok:raise RuntimeError('close_failed')
        vm=None
try:
    start();phase='baseline';result['ui_before']=ui('before')
    if 'SD_ROUTE_CLEAN=1' not in command('sd_clean'):raise RuntimeError('stale_request')
    phase='native_suite';text=command('sd_suite')
    result['mount_verified']=bool(re.search(r'SD_ROUTE_MOUNT fixture=tmpfs readonly=1 path=/tmp/sd-route/card',text))
    result['stale_session_rejected']='SD_ROUTE_STALE rejected=1' in text
    pattern=r'SD_ROUTE case=([a-z_]+) passed=(\d) entry_ms=(\d+) ticks=(\d+) exit=(-?\d+) signal=(\d+) timeout=(\d) spawn_error=(\d+) duplicates=(\d+) constrained=(\d) reaped=(\d) exec_ready=(\d) preload_ready=(\d) detached=(\d) ownership_lost=(\d) signals=(\d+) load_error=(\d+) input_mode=(\d+)'
    names=['case','passed','entry_ms','ticks','exit','signal','timeout','spawn_error','duplicates','constrained','reaped','exec_ready','preload_ready','detached','ownership_lost','signals','load_error','input_mode']
    result['cases']=[dict(zip(names,[r[0]]+list(map(int,r[1:])))) for r in re.findall(pattern,text)]
    result['native_failure_stages']=re.findall(r'SD_ROUTE_FAILURE stage=([a-z_]+) errno=(\d+) case=([a-z_]+)',text)
    result['suite_return_codes']=[int(v) for v in re.findall(r'SD_ROUTE_RC=(\d+)',text)]
    if not result['mount_verified'] or not result['stale_session_rejected'] or len(result['cases'])!=20 or not all(r['passed'] for r in result['cases']) or 'SD_ROUTE_SUITE passed=1' not in text or 'SD_ROUTE_RC=0' not in text:raise RuntimeError('native_suite_failed')
    phase='post_fault_ui';result['ui_after']=ui('after')
    if 'SD_ROUTE_CLEAN=1' not in command('sd_clean'):raise RuntimeError('residue')
    close();phase='new_vm';start()
    if 'SD_ROUTE_CLEAN=1' not in command('sd_clean'):raise RuntimeError('new_vm_residue')
    result['new_vm_no_autoexec']=True;result['new_vm_ui']=ui('restart')
    result['passed']=True
except Exception as exc:
    result.update(failed_phase=phase,error_type=type(exc).__name__)
    allowed={'guest_unhealthy','guest_wait','expected_original_language_screen','original_ui_no_change','original_ui_not_restored','native_suite_failed','stale_request','residue','new_vm_residue','persistent_settings','overlay_off'}
    result['reason']=str(exc) if str(exc) in allowed else 'other'
    if vm:
        state=vm.status()
        log=Path(state['log']) if state.get('log') else None
        private=log.read_text(errors='replace') if log and log.is_file() else ''
        result['diagnostics']={
            'undefined_symbols':re.findall(r'undefined symbol: ([A-Za-z_][A-Za-z_0-9]*)',private)[-12:],
            'own_source_errors':re.findall(r'(sd-route-[a-z.-]+:[0-9:]+: (?:fatal )?error: [^\r\n]{0,160})',private)[-8:],
            'missing_paths':[Path(p).name for p in re.findall(r"No such file or directory: '([^']+)'",private)[-8:]],
            'error_types':re.findall(r'(?m)^(\w+(?:Error|Exception)): ',private)[-8:],
            'log_sha256':hashlib.sha256(private.encode()).hexdigest()}

finally:
    try:close()
    except Exception as exc:result.update(passed=False,close_error=type(exc).__name__)
    (OUT/'sd-route-result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result),flush=True)
sys.exit(0 if result['passed'] else 1)
