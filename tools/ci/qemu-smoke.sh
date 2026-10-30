#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
system=runtime/sources/qemu-11.1.2/build-sony-ui/qemu-system-aarch64
user=runtime/sources/qemu-11.1.2/build-user/qemu-aarch64
"$system" --version | tee /tmp/a7c2-system-version
"$user" --version | tee /tmp/a7c2-user-version
grep -F 'version 11.1.2' /tmp/a7c2-system-version
grep -F 'version 11.1.2' /tmp/a7c2-user-version
"$system" -machine help | tee /tmp/a7c2-machines
grep -E '^virt[[:space:]]' /tmp/a7c2-machines
"$system" -device help | grep -F 'sony-ui-input'
"$system" -display help | grep -x gtk
QEMU_TEST_BINARY="$(realpath "$system")" python3 -B runtime/analysis/test-qemu-native-input.py
printf '%s\n' 'QEMU_NO_FIRMWARE_SMOKE_PASS (not a Sony firmware boot test)'
