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
bounded regular file, and copied once into RAM with an additional one-byte EOF
check. Only that snapshot is interpreted. Concurrent writes after the snapshot
are not interpreted; this does not promise a filesystem transaction.

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
budget exhaustion, FIFO and symlink rejection, and an append after the maximum
input read. FIFO/symlink/append race tests are host-only. Guest tests require exact glyph
and negative pixels from actual QMP screenshots, recovery after each bad input,
normal save/close, and a new VM instance. Real guest results passed in
[run 41175323027](https://github.com/YLTai/a7c2-qemu/actions/runs/41175323027)
at commit `79646f6846b8c4bdeb0579fdebbb8faa591c8d2a`. The original camera UI,
Hello World, off, missing input, ELF rejection, valid prefix with malformed tail,
explicit abort, budget exhaustion, unknown opcode, repeated recovery, and new-VM
restart all passed. One normal controller cleanup attempt failed after SD export;
the second normal close attempt succeeded, then a fresh VM started successfully.
Final close succeeded on its first attempt. No forced-close bypass was added.
The underlying cleanup exception was not retained in the public fixed-schema
result, so its exact cause is unknown; this is a controller cleanup reliability
observation, not evidence of a bytecode interpreter failure.

The EOF and stricter zero-output assertions passed in the follow-up
[run 41176305947](https://github.com/YLTai/a7c2-qemu/actions/runs/41176305947)
at commit `383bb1e45f5fd9076414796929be67572edf2d42`. All same-instance
hello/reject/clear/hello sequences and new-VM restart passed again. Both normal
closes succeeded on their first attempt in that run, and all screenshot hashes
matched the earlier results. The exact QEMU binary cache was verified again.

The actual Hello World PNG has SHA-256
`7b7c5ad7ef3fec58f7cb2c36a43aa66bb36010d1a19065403a8c00b9bb3ad7a9`.
Only its 612 expected glyph pixels differ from the original camera image. Every
failure/off PNG is byte-identical to the original image; restart is byte-identical
to Hello World. These are QMP ramfb screenshots, not host-rendered images.
The 2,468-byte / 613-instruction Hello World program has SHA-256
`4f8eb5d1fe0241a94ad699117d67f022dd89ad9e803ae0081d55c7b22f75198d`.

QEMU's exact existing binary cache was restored and verified; QEMU was not
recompiled. Native interpreter crashes, wall-watchdog firing, arbitrary kernel
fault recovery and real hardware were not tested. The `crash`/`timeout` labels
must not be read as claims about those untested cases.
The display checks prove overlay removal and readdition, not full camera
responsiveness. Guest interpreted rejection tests also require zero signal,
no wall timeout, zero output bytes, and supervisor exit 1.

Dispatch `qemu-build.yml` on `ci/qemu-actions` with `firmware=true`. The existing
`SONY_FIRMWARE_URL` repository secret supplies the temporary input. QEMU's exact
source/binary caches are reused. Public artifacts contain only approved actual
emulator screenshots and fixed-schema results, never firmware or extracted images.

## Electronic shutter sound feasibility (blocked)

Read-only review pinned the upstream research to
[`QAQLeonard/a7c2-fl23-research` at `ef7db116e13e37be91e9af20360dc9bba8d64a9b`](https://github.com/QAQLeonard/a7c2-fl23-research/tree/ef7db116e13e37be91e9af20360dc9bba8d64a9b).
Its supported target is ILCE-7CM2 firmware 2.01. No upstream tool was executed.

[`candidate.py`](https://github.com/QAQLeonard/a7c2-fl23-research/blob/ef7db116e13e37be91e9af20360dc9bba8d64a9b/src/shutter_sound/candidate.py)
changes a five-byte CP selector table at file offset `0x393570` and an
18-byte gate at `0x3935bc`. The gate uses the per-capture electronic flag;
this is electronic shutter sound, not an ordinary beep switch. Its AP registry
preflight requires native sound kinds 1, 2 and 3. The normal mode-3 path uses
kind 3; the upstream counter-limited path also has mode-1 behavior.
The old single-site patch was shown to leak sound on mechanical captures and
must not be substituted. Audio Signals Off remains a separate native mute policy.
Upstream's disable operation is a muted electronic gate, not the stock inverse.
Its seven CP instruction guards and two AP getter guards are necessary context;
neither file offsets nor the synthetic `+0x108000` mapping prove a live CP address.
[`trial.py`](https://github.com/QAQLeonard/a7c2-fl23-research/blob/ef7db116e13e37be91e9af20360dc9bba8d64a9b/src/shutter_sound/trial.py)
writes the CP program file and requires a cold reload. Temporary custom-sound
audition does not remove the prerequisite of that already-enabled CP program.
Its synthetic Thumb selector tests are not a complete CP boot or audio-output
test; the playback-constructor trace explicitly excludes DSP decoding/output.

The current QEMU launcher (`runtime/analysis/qemu-kernel-probe.sh`) starts AP
Cortex-A35 CPUs on the virtual board. Our CP protocol models do not execute the
original Thumb shutter selector, and there is no verified live CP code mapping
for the above offsets. In `runtime/analysis/device-models/audio-device.c`,
`2004:0203` and `200d:032b` playback requests explicitly fail as unsupported.
Sound-table registration, source-buffer readback and volume/path configuration
are separate capabilities; none proves a capture-triggered playback or sound.

Consequently no shutter-enable bytecode opcode, RAM patch, persistent program
change, setting change or fabricated success result was added. Patching a copy
of the file in RAM would not establish that the executing CP consumed it.
This is a missing execution/audio implementation, not an approval denial.
No new Actions run was needed for this read-only feasibility finding; the last
executed Hello World regression remains run 41176305947.

To continue toward an actual enable capability, first establish either an
executing CP with verified code ownership/mapping/cache synchronization and
capture linkage, or an explicitly scoped virtual audio path whose claims remain
distinct from original CP execution. A RAM-only adapter must then validate the
firmware and original bytes, serialize updates, verify readback/rollback and
prove that fresh instances restore stock behavior, without saving settings or
changing source firmware. CP execution and audio playback are substantial missing
subsystems, not permissions that can be fixed by disabling isolation. Isolated
instruction tests could validate branch semantics only. Menu visibility, runtime
selection, capture-triggered audio requests and actual audio output remain
unverified for this plugin platform.

## Experimental FL2/FL3 menu capability

The trusted startup broker in `runtime/analysis/fl23-menu-guest.c` is a separate,
fixed-purpose capability. It does not add native execution, pointers, memory
instructions or shell access to display bytecode. Request it with
`A7C2_RAM_PLUGIN=1` and `A7C2_FL23_MENU=1` in a fresh natural-boot QEMU instance,
with `MENU_BACKUP_SAVE=0` and `A7C2_SETTINGS_PERSIST=0`. Persistent instances,
restored settings, mock backends, firmware overlays and other firmware identities
are rejected. Disabling requires a fresh VM with `A7C2_FL23_MENU=0`.
This is a startup request, not a hot enable/disable command. The broker runs
before Application_System_Init (after shared-library constructors). The existing
`ram_plugin` `off` request only disables the display overlay; it does not undo
FL23. `ram_plugin` `fl23_status` is a read-only fixed diagnostic request.
The original Intelligent Auto restriction is retained: use the existing MODE
dial control to choose P before opening Exposure/Color > Color/Tone > Creative
Look. The broker does not override native shooting-mode restrictions.

The launcher and broker pin original appFw identity, ELF layout, live private
file mappings, original bytes and native Backup originals. Only seven fixed AP
data fields and two fixed Backup bindings are writable. Three data pages lie
inside RX ELF segments, but their entire pages are non-executable data sections;
the broker temporarily uses RW without X, then verifies exact original mapping
permissions. Transaction failures roll back both AP data and Backup bindings;
uncertain recovery aborts the disposable application process before native init.

`Backup_save=0` is **not** a global native save gate. FL23 additionally uses a
read-only bind mount for the guest tmpfs Backup file, verifies actual tmpfs and
read-only flags, and checks its original SHA before and after the transaction.
Source firmware and persistent settings are not modified or exported. The
original camera may change native settings in RAM; they disappear with the VM.

The existing framework's fixed `fl23_status` request reads only native bindings
and hashes three fixed files. It cannot select arbitrary keys, paths or addresses.
The observer separately records the pinned camera product-model index once
following an original frame. It is not a Creative Look selection index.
Binding 10/11 alone is not proof of a selected Look.

[Run 41196866130](https://github.com/YLTai/a7c2-qemu/actions/runs/41196866130)
verified enabled bindings, seven AP fields after the first original frame, exact
file hashes, native forced rollback, fresh disabled originals and normal cleanup.
Original key input completed firstboot and opened MENU with the overlay off.
[Run 41197921239](https://github.com/YLTai/a7c2-qemu/actions/runs/41197921239)
also verified same-VM before/after Backup hashes and reached Exposure/Color.
[Run 41201197793](https://github.com/YLTai/a7c2-qemu/actions/runs/41201197793)
shows independent FL2/FL3 entries, each selected with OK, reflected in the parent
menu and retained after reopening. FL3 contrast was changed 0 -> +1, confirmed,
read back after reopening, then restored and read back as 0. Original file hashes
and native bindings remained unchanged after those UI operations. The acceptance
test now checks reviewed original screen IDs and exact control crops for these
results. Full [run 41201840284](https://github.com/YLTai/a7c2-qemu/actions/runs/41201840284)
passed at `2e8b7494926e56dba4672b2d08f30e90f3a208e3`: original firmware startup,
Hello World/negative/recovery tests, FL23 menu and parameter assertions, native
forced rollback and fresh disabled originals. All four FL23 VM closes succeeded
on their first attempt. The separate Hello World test needed one normal cleanup
retry (first close reported cleanup_failed; second close succeeded); its restart
closed on the first attempt. No forced-close bypass was used.
Exact QEMU source and binary caches were restored and
verified. Artifact `firmware-boot-evidence` (`13043257647`) contains the original
screenshots and fixed-schema results; `fl23-result.json` reports passed=true,
selection_verified=true, parameter_readback_verified=true, color_verified=false.

Selection readback here means the original menu value and reopened native
parameter page. A separate current-Look getter is not verified; product index 16
is never used as selection evidence. The six custom-Look slots' initial cached
bindings are not part of this acceptance; the tested choices are the independent
FL2/FL3 entries. Initial parameter order is contrast, highlights, shadows, fade,
saturation, sharpness, sharpness range and clarity (0/0/0/0/0/4/3/1 for both).
Use `fl23_only=true` only for navigation diagnostics; final validation must leave
it false to include Hello World and all baseline/recovery/restart tests.

No CP gamma/routing/converter code is modified. Menu and parameter verification
will not establish final-photo color processing or real-camera compatibility.
