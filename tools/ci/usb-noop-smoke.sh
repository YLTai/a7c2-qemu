#!/usr/bin/env bash
set -euo pipefail
root=$(pwd)
out=$(mktemp -d "${RUNNER_TEMP:?}/usb-noop.XXXXXX")
trap 'rm -rf "$out"' EXIT
python3 -m unittest discover -s tools/usb-noop -p test_noop.py -v
flags=(-shared -nostdlib -fPIC -fno-stack-protector -fno-builtin
       -fvisibility=hidden -O2 -Wall -Wextra -Werror
       -Wl,--build-id=none,-z,max-page-size=4096,-z,noexecstack,-z,relro,-z,now,-init,_init)
aarch64-linux-gnu-gcc "${flags[@]}" tools/usb-noop/noop.c -o "$out/noop.so"
aarch64-linux-gnu-gcc "${flags[@]}" tools/usb-noop/noop.c -o "$out/rebuilt.so"
cmp "$out/noop.so" "$out/rebuilt.so"
test "$(stat -c %s "$out/noop.so")" -le 65536
# No libc, constructors from CRT, undefined symbols or executable stack.
! aarch64-linux-gnu-readelf -d "$out/noop.so" | grep -q NEEDED
test -z "$(aarch64-linux-gnu-nm -u "$out/noop.so")"
aarch64-linux-gnu-readelf -d "$out/noop.so" | grep '(INIT)'
aarch64-linux-gnu-readelf -W -l "$out/noop.so" | grep GNU_STACK | grep -q 'RW '
aarch64-linux-gnu-gcc -O2 -Wall -Wextra -Werror tools/usb-noop/loader-test.c -ldl -o "$out/loader"
qemu="$root/runtime/sources/qemu-11.1.2/build-user/qemu-aarch64"
for scenario in success bad-request missing-request existing-result symlink-result; do
    timeout 20 bwrap --unshare-all --die-with-parent --ro-bind / / \
        --tmpfs /tmp --dev /dev --proc /proc \
        "$qemu" -L /usr/aarch64-linux-gnu "$out/loader" "$out/noop.so" "$scenario"
done
# Publish fixed metadata only; no uploadable payload is distributed in this stage.
python3 - "$out/noop.so" <<'PY'
import hashlib, json, pathlib, sys
payload = pathlib.Path(sys.argv[1]).read_bytes()
report = {'schema': 'a7c2-offline-noop/1', 'hardware_access': False,
          'synthetic_loader_only': True, 'real_loader_verified': False,
          'payload_sha256': hashlib.sha256(payload).hexdigest(),
          'payload_bytes': len(payload), 'reproducible_build': True,
          'camera_upload_enabled': False,
          'cases': ['success', 'bad-request', 'missing-request',
                    'existing-result', 'symlink-result']}
pathlib.Path('ci-logs/usb-noop-result.json').write_text(json.dumps(report, indent=2)+'\n')
print(json.dumps(report))
PY
