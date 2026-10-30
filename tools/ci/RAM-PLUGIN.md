# RAM overlay experiment

This experiment runs an independent AArch64 `HELLO WORLD` program inside the
emulated guest. It does not modify the original firmware input or flash hardware.
The real firmware boots to its language-selection screen, but native plugin
execution is blocked by the original guest kernel's missing seccomp capability.
Run [41138388158](https://github.com/YLTai/a7c2-qemu/actions/runs/41138388158),
commit `2ba9af1249dfac526fb0ad4c7edc22eb828b12c9`, measured
`PR_GET_SECCOMP -> -1, errno=22 (EINVAL)`. The supervisor returned 2 before
executing plugin code. Linux documents this query failure for a kernel without
`CONFIG_SECCOMP`: [PR_GET_SECCOMP](https://man7.org/linux/man-pages/man2/pr_get_seccomp.2const.html).

Actual guest evidence: original firmware screenshot, overlay-off screenshot and
normal save/close passed. Hello was rejected before execution. Missing, invalid
ELF, malformed output, crash, timeout, forbidden syscall and fresh-instance
restart cases remain unexecuted because the prerequisite failed. Host filter,
FIFO rejection, display parser and exact-mask logic tests passed; these are not
proof of guest enforcement. The test job intentionally remains failing.

No unconfined fallback or guest-kernel modification is applied. Installing a
host library cannot enable this guest kernel feature. Continuing the native-code
design requires a compatible guest kernel with seccomp support and new boot/ABI
validation; alternatively, a separately reviewed restricted bytecode design
would change the plugin execution model.

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
It requires an exact yellow glyph mask, including negative pixels, and verifies
actual guest responses and QEMU screenshots; host-rendered images
are never used as evidence. These tests cover the bounded demonstration, not
all arbitrary native plugins, guest kernel vulnerabilities or real-camera safety.

Firmware and extracted images remain temporary runner inputs. Public artifacts
are limited to expressly permitted emulator screenshots and fixed-schema results.

To reproduce, configure the repository secret `SONY_FIRMWARE_URL` and manually
dispatch `qemu-build.yml` on `ci/qemu-actions` with `firmware=true`. The URL is never
provided as a public workflow input. The job restores the verified QEMU cache,
uses a process-local sparse RAM backend, and keeps host isolation enabled.
