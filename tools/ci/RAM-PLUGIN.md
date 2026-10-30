# RAM overlay experiment

This experiment runs an independent AArch64 `HELLO WORLD` program inside the
emulated guest. It does not modify the original firmware input or flash hardware.
It has not yet passed the real guest tests; host parser/filter tests are not proof
of guest enforcement.

`runtime/analysis/ram-plugin-boot.c` is the trusted supervisor. It copies a bounded
executable into a sealed memfd, starts it with an empty environment and filesystem
root, drops groups, IDs and capabilities, sets resource limits and no-new-privileges,
and installs an AArch64 syscall allowlist before execution. The plugin can write
only to its output pipe and exit. The executable descriptor closes on execution.
The supervisor enforces a wall deadline and accepts only one fixed-size mask.
Missing kernel support or failed isolation setup rejects execution.

The plugin never enters the camera IM process or accesses the display bridge.
`ramfb-viewer.c` is the trusted bridge: after validating the original HOSDAP02
frame, it converts that frame, blends a validated 160x24 mask, and submits it.
Removing a mask recomposes the original frame. The mask file is root-owned and
not writable by the plugin identity.

`tools/ci/ram-plugin-smoke.py` exercises hello, missing input, invalid ELF,
malformed output, crash, timeout, forbidden syscall and a fresh VM restart.
It verifies actual guest responses and QEMU screenshots; host-rendered images
are never used as evidence. These tests cover the bounded demonstration, not
all arbitrary native plugins, guest kernel vulnerabilities or real-camera safety.

Firmware and extracted images remain temporary runner inputs. Public artifacts
are limited to expressly permitted emulator screenshots and fixed-schema results.
