#!/usr/bin/env bash
# Called only inside the existing original-ABI observer build in Actions.
set -euo pipefail
src=$1
out=$2
lib=$3
work=$4
common=(--target=aarch64-linux-gnu -fuse-ld=lld -nostdlib -O2 -mno-outline-atomics
        -isystem /usr/aarch64-linux-gnu/include -I"$src" -I"$work")
libraries=("$lib/libc-2.25.so" "$lib/libdl-2.25.so" "$lib/libpthread-2.25.so" "$lib/ld-2.25.so")
names=(normal constructor_crash run_crash constructor_hang run_hang)
for i in 0 1 2 3 4; do
  clang "${common[@]}" -shared -fPIC -Wl,--no-undefined,-init,_init -DFIXTURE="$i" \
    "$src/sd-route-plugin.c" "${libraries[@]}" -o "$out/sd-route-${names[$i]}.so"
done
python3 - "$out" "$work" <<'PY'
import hashlib,pathlib,sys
out,work=map(pathlib.Path,sys.argv[1:])
names=['normal','constructor_crash','run_crash','constructor_hang','run_hang']
hashes=[hashlib.sha256((out/f'sd-route-{n}.so').read_bytes()).hexdigest() for n in names]
(work/'sd-route-pins.h').write_text('/* Test fixture whitelist, not hardware distribution. */\n'+
 'static const char *sr_names[]={'+','.join('"'+n+'"' for n in names)+'};\n'+
 'static const char *sr_hashes[]={'+','.join('"'+h+'"' for h in hashes)+'};\n')
PY
clang "${common[@]}" -Wl,--no-undefined,-e,_start,--dynamic-linker=/lib/ld-linux-aarch64.so.1 \
  "$src/sd-route-runner.c" "${libraries[@]}" -o "$out/sd-route-runner"
python3 - "$out/sd-route-runner" "$work/sd-route-runner-pin.h" <<'PY'
import pathlib,hashlib,sys
pathlib.Path(sys.argv[2]).write_text('#define SR_RUNNER_HASH "'+hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()+'"\n')
PY
clang "${common[@]}" -shared -fPIC -Wl,-init,_init \
  "$src/sd-route-entry.c" "${libraries[@]}" -o "$out/sd-route-entry.so"
clang "${common[@]}" -Wl,--no-undefined,-e,_start,--export-dynamic,--dynamic-linker=/lib/ld-linux-aarch64.so.1 \
  "$src/sd-route-host.c" "${libraries[@]}" -o "$out/sd-route-host"
# Own-binary ABI metadata only; no original firmware ELF content is exported.
python3 - "$out" <<'PY'
import hashlib,json,pathlib,subprocess,sys,re
out=pathlib.Path(sys.argv[1]); records=[]
for p in sorted(out.glob('sd-route-*')):
 if not p.is_file():continue
 data=p.read_bytes()
 ph=subprocess.check_output(['aarch64-linux-gnu-readelf','-lW',str(p)],text=True)
 dynamic=subprocess.check_output(['aarch64-linux-gnu-readelf','-dW',str(p)],text=True)
 versions=subprocess.check_output(['aarch64-linux-gnu-readelf','-VW',str(p)],text=True)
 records.append({'name':p.name,'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data),
  'interpreter':re.findall(r'Requesting program interpreter: ([^\]]+)',ph),
  'needed':re.findall(r'\(NEEDED\).*?\[([^\]]+)\]',dynamic),
  'versions':sorted(set(re.findall(r'GLIBC_[0-9.]+',versions)))})
(out.resolve().parents[3]/'ci-logs/sd-route-build.json').write_text(json.dumps({'schema':'sd-route-build/1','sony_usb_abi_verified':False,'files':records},indent=2)+'\n')
PY
