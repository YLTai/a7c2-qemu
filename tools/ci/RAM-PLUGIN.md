# Experimental RAM display bytecode

This is an experimental QEMU startup hook, not a deployable camera bootloader.
The original guest kernel and original firmware input remain unchanged. The
native plugin attempt failed because the guest lacks seccomp; this version uses
a small trusted display-command interpreter instead. No bytecode is executed
as machine code, JIT-compiled, dynamically linked, or passed to a shell.

The 16-byte header is `A7BC0001`, a little-endian 16-bit instruction count, and
six zero reserved bytes. Every instruction is four bytes:

| Opcode | Operands | Effect |
| --- | --- | --- |
| 0 | all zero | Finish and return the complete mask |
| 1 | x, y, value | Set one pixel; x<160, y<24, value is 0 or 255 |
| 2 | target low byte, high byte, zero | Jump to an instruction index |
| 3 | all zero | Abort without publishing output |

Input is at most 8,208 bytes / 2,048 instructions. Every instruction, including
unreachable instructions, is validated before execution. Unknown opcodes,
reserved bits, invalid coordinates/targets, truncated operands, trailing bytes
and ELF inputs are rejected. There are no plugin pointers, loads/stores to
arbitrary addresses, syscalls, file/device/network operations, or native calls.
The jump operation makes a real 4,096-step execution budget test possible.
The input file is opened nonblocking without following symlinks, checked as a
bounded regular file, and copied once into RAM. Only that snapshot is interpreted.

`ram-plugin-boot.c` is the trusted supervisor. Its child closes inherited file
descriptors except the output pipe, enters an empty chroot, drops supplementary
groups, UID/GID and capabilities, applies no-new-privileges and resource limits,
and interprets the snapshot. A parent wall deadline remains as a fallback.
Only successful execution returning one valid 3,856-byte mask is atomically
published. Rejected/aborted/over-budget programs remove the previous mask.

`ramfb-viewer.c` is a separate trusted display bridge. It validates the original
HOSDAP02 frame and the root-owned fixed mask, converts the original frame, blends
the mask and submits it. It never interprets plugin commands. If the camera's
source snapshot disappears or becomes invalid, the bridge can retain its last
scanout; removal is visible only after a valid source frame can be recomposed.
This is not a guaranteed display-recovery mechanism for arbitrary firmware faults.

The trusted computing base includes the C interpreter/supervisor, libc, display
bridge, original guest kernel and QEMU. Without guest seccomp, a vulnerability in
the interpreter could expose native syscalls with its reduced process privileges;
chroot and resource limits do not replace a syscall filter or prevent kernel
exploits. These constraints apply to the bytecode language, not arbitrary native
plugins. This experiment does not establish real-camera compatibility or freedom
from bricking risk.

`build-ram-bytecode.py` creates the Hello World program and failure fixtures.
CI case labels `crash` and `timeout` mean an explicit bytecode abort (exit 42)
and instruction-budget exhaustion (exit 43), respectively; they are not native
crash or wall-timeout tests. Invalid programs exit 41. Host sanitizer tests check
fixtures, truncated/mutated inputs, valid prefixes with invalid tails, bounds,
budget exhaustion, FIFO and symlink rejection. Guest tests require exact glyph
and negative pixels from actual QMP screenshots, recovery after each bad input,
normal save/close, and a new VM instance. Real guest results are pending for this
revision; host tests are not evidence of guest display success.

Dispatch `qemu-build.yml` on `ci/qemu-actions` with `firmware=true`. The existing
`SONY_FIRMWARE_URL` repository secret supplies the temporary input. QEMU's exact
source/binary caches are reused. Public artifacts contain only approved actual
emulator screenshots and fixed-schema results, never firmware or extracted images.
