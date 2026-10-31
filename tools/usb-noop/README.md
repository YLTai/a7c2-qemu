# Offline USB no-op candidate and lifecycle review

Status: source review and offline simulation only. **No USB backend is enabled.**
There is no camera upload, authentication, hardware passthrough or automatic retry
in this tool. Model ILCE-7CM2 / firmware 2.01 is the intended target, not a claim
that a device has been independently identified. User-reported successful service
connection and read-only stability tests do not prove native execution safety.

## Where the upstream program goes and who runs it

Reviewed upstream: QAQLeonard/a7c2-fl23-research at
`ef7db116e13e37be91e9af20360dc9bba8d64a9b`. Its source was read, not executed.
Facts below informed an independent implementation; no upstream implementation
or binary was copied. Upstream has its own PolyForm Noncommercial licensing.

* [transport.py lines 398–424](https://github.com/QAQLeonard/a7c2-fl23-research/blob/ef7db116e13e37be91e9af20360dc9bba8d64a9b/src/camera_runtime/transport.py#L398):
  selection uses Jiritsu command 15, file upload 16, read 17 and delete 18.
  Names are under `/tmp/jiritsu/`; 16 and 18 mark the session mutating.
  Native loading is triggered by writing **`/tmp/jiritsu/libJit.so`**. Treat the
  triggering upload as execution intent before transmitting any bytes, not as
  an inert file transfer followed by a separately safe execution command.
* [devicesession.py lines 158–197](https://github.com/QAQLeonard/a7c2-fl23-research/blob/ef7db116e13e37be91e9af20360dc9bba8d64a9b/src/looks/looktool/devicesession.py#L158):
  check for existing files/preload, stage and read back the library, optionally
  stage/read back a request, upload `libJit.so`, read/validate result, then clean
  in reverse order after comparing owned contents. Confirm absence after delete.
  An exception during invocation marks the outcome unknown, without retry.
* [probe.c lines 1–4 and 101–122](https://github.com/QAQLeonard/a7c2-fl23-research/blob/ef7db116e13e37be91e9af20360dc9bba8d64a9b/src/camera_runtime/native/probe.c#L101):
  upstream documents SET_FILE2's `dlopen`/`dlclose` loader. `_init` executes in
  the hosting service process. It unlinks `libJit.so`, writes
  `/tmp/jiritsu/a7c2.probe.result` and returns. **Return is not process exit.**
  Calling `exit`/`_exit`, crashing, blocking or corrupting memory can affect the
  privileged service process. Exact real process name, thread ID, loader flags,
  unload success and complete loader call graph remain unverified here.
* [app.py lines 81–89](https://github.com/QAQLeonard/a7c2-fl23-research/blob/ef7db116e13e37be91e9af20360dc9bba8d64a9b/src/camera_runtime/app.py#L81):
  unhealthy channels record cleanup pending rather than continuing. The
  transport's read-only rescue path is not available after a mutating operation.
* [usbcheck.py](https://github.com/QAQLeonard/a7c2-fl23-research/blob/ef7db116e13e37be91e9af20360dc9bba8d64a9b/src/desktopapp/usbcheck.py):
  the newer GUI stability check reads program files and does not stage workers.
  This differs from old backup/native-probe workflows; the word “backup” alone
  does not establish that a workflow never uploads or invokes native code.

## Does it delete itself? Does restarting run it again?

Normal self-unlink removes the filename, not an already loaded mapping. The
loader still owns that mapping until it actually unloads it. The request,
staged library and result need host cleanup. A disconnection, loader failure,
failed unlink, short result write or host crash can leave files behind. A valid
result does not alone prove `_init` returned or `dlclose` completed. A timeout
does not prove execution never happened. No automatic retry, cleanup over an
uncertain channel, service rescue, or automatic restart is permitted here.

**Real mount type and canonical path are unresolved.** `/tmp` is only a name.
The upstream probe collects mounts, but
[core.py lines 129–135](https://github.com/QAQLeonard/a7c2-fl23-research/blob/ef7db116e13e37be91e9af20360dc9bba8d64a9b/src/camera_runtime/core.py#L129)
validates `/usr` as read-only ext2; it does not prove this upload path is volatile.
Our QEMU launcher explicitly makes a tmpfs, which is evidence about QEMU only.

Before any future upload, an independently reviewed **non-native read path**
must obtain current mount/mountinfo and path-resolution evidence for the exact
service namespace. Resolve every parent/symlink, identify the deepest covering
mount and submounts, establish that it is volatile tmpfs, and inspect the real
loader/startup consumers of leftover `libJit.so`. Reading `/proc/mounts` alone
does not establish symlink resolution or the service process's namespace. The
upstream host API can select/read paths, but neither safe canonical-path proof
nor a complete startup-consumer audit is established by this review. **Do not
upload a probe to obtain the proof required before uploading that probe.**

Warm startup may restore a retained system image; an ordinary off/on cycle must
not be equated with a fresh kernel/tmpfs. Upstream
[wbi.c](https://github.com/QAQLeonard/a7c2-fl23-research/blob/ef7db116e13e37be91e9af20360dc9bba8d64a9b/src/camera_runtime/native/wbi.c)
has separate retained-image controls. This tool never uses them. Cold boot
normally reconstructs volatile memory, but actual device power/snapshot restore
behavior and cleanup have not been observed here. **No promise that restarting
deletes all files or prevents execution is justified.** File residue and automatic
execution are distinct questions. This candidate registers no startup action,
preload, service, boot install, WBI control or configuration change; that does not
prove firmware never consumes a leftover trigger file during startup.

These unresolved facts block the camera transport, rather than being silently
accepted risks. No actual persistent upload has been attempted or observed.

## Candidate and offline use

From the repository root:

```sh
python3 tools/usb-noop/noop.py
python3 tools/usb-noop/noop.py --simulate
python3 -m unittest discover -s tools/usb-noop -p test_noop.py -v
```

The first command only prints a plan; the second uses a non-executable byte
fixture and in-memory files, not USB or the native library. Explicit
`--execute-camera --confirm ...` remains rejected before device access. The
model/version inputs describe simulation fixtures, not camera identity evidence.
No live adapter can be injected into this interface. A future adapter requires
fresh reviewed evidence and separate authorization; adding a confirmation flag
alone will not satisfy those gates.

`noop.c` is the separate AArch64 library candidate. It has one `_init`, no libc
dependency, destructor, fork, thread, exit syscall or persistence operation. Its
only syscalls are openat, fstatfs, read, unlinkat, write and close. All paths and
operations are fixed. It checks the already-open directory is tmpfs, reads a
32-byte fixed request containing a fresh 16-byte nonce, unlinks the trigger,
creates a new 32-byte result exclusively, closes descriptors and returns.
Writes are bounded to four attempts. It never truncates an existing result or
follows its symlink. The post-load tmpfs check is only defense in depth: it cannot
make an earlier unverified upload safe. Model/firmware proof is a required host
gate, not something this tiny no-op independently validates.

Proposed owned names: `/tmp/jiritsu/a7c2.noop.staged.so`, `a7c2.noop.request`,
`libJit.so` and `a7c2.noop.result`. No user-selected payload/path/key/address is
part of a future camera interface. A reviewed build's exact SHA-256 must be pinned;
the simulation's fixture digest is not a production authorization mechanism.
The current build emits a payload identity receipt but deliberately publishes no
uploadable library or live execution command.

`tools/ci/usb-noop-smoke.sh` builds the candidate twice and compares its bytes,
checks the dependency/entry/stack properties, and tests a synthetic AArch64
`dlopen`/`dlclose` harness with the cached QEMU user emulator. Every run is in the
existing approved bwrap profile, with private tmpfs `/tmp`, no hardware USB and
no firmware. It checks same-process/thread return, result/nonce, unlink and
post-cleanup absence; negative cases cover malformed/missing requests and existing
or symlinked results. The harness's normal process exit occurs only after the
library returns; the library never exits its host.

Host fault tests distinguish pre-invoke staging residue, unknown invocation,
verified simulated execution with cleanup pending, and fully verified absence.
One session has one fixed deadline and at most one invocation. Once a timeout
occurs, no later command runs. Blocking inside a real kernel/service is not made
safe merely by a host deadline, and the synthetic harness timeout does not grant
permission to kill a real service.

Not verified: real Sony loader ABI/call graph, mount/path/boot behavior, camera
native execution, recovery after a crash, or real hardware safety. This work is
high-privilege native execution research, not an ordinary read-only operation or
a guarantee against bricking. No FL23/color/CP/AP modification is included.
