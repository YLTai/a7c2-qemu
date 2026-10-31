# Fixed native SD route — QEMU research only

This candidate is disabled on hardware. It is not a Sony USB payload and does
not provide a working camera installation procedure. The original USB no-op CLI
continues to reject camera execution.

## Architecture and ABI boundary

The small entry library runs `_init`, checks a fixed enable marker, submits a
parameterless `sd_route_request_v1()` request, and returns. It neither loads the
SD plugin nor creates a thread whose code could outlive `dlclose`. The resident
broker and its threads belong to our synthetic host executable. **That broker
ABI has not been found or integrated in the original Sony service.** Resolving
that integration without changing the service remains a separate blocker.

The resident worker validates the simulated card and exact runner hash, then
uses `posix_spawn` to exec the verified runner through its open file descriptor.
There is no project-written post-fork child path with allocator/dlopen calls.
The broker does not alter SIGCHLD and waits only for the PID it created. Its
owned process group is terminated on a two-second monotonic wall deadline
checked after posix_spawn returns; spawn/exec itself is not hard-bounded by this
in-process watchdog. A blocked spawn cannot block the entry caller, but would
leave the worker busy. External supervision would be needed to bound that case;
the child is reaped before accepting another request. The resident host must
grant the broker exclusive reaping ownership. ECHILD/ownership loss stops all
numeric-PID signalling; a competing-reaper fixture verifies that path. This
contract has not been established in the original Sony service. It uses a kernel flock lease to reject concurrent host instances; a leftover
lock file carries no PID or request. Startup invalidates any old enable marker.
It does not use PID files or waitpid(-1). The original service/host branch never calls exit from the entry.
The synthetic host's `_start` exits only when its complete test program ends.

The fresh runner validates a fixed `plugin.meta` version, fixed `plugin.so`
ELF/size/hash and a build-time whitelist. All capabilities, supplementary groups
and inherited descriptors are removed before dlopen. UID/GID become 65534;
no_new_privs and resource limits are set before constructors execute. During
loading, only the bounded-result pipe and read-only verified plugin descriptor
remain. The input descriptor closes after dlopen. No parent-memory capability,
address interface, native syscall broker or display overlay is implemented.

These are fault-containment measures, **not a sandbox for malicious native
code**. There is no seccomp filter or chroot. A native plugin still has system
calls and can access whatever its unprivileged credentials permit. This test
loads only independently written, hash-pinned fixtures, including intentional
crash/hang fixtures. It does not justify loading arbitrary third-party libraries.

## Simulated card and file lifetime

The test creates a dedicated tmpfs mount at `/tmp/sd-route/card` inside the
single-use QEMU guest. Both broker and runner parse that guest's mountinfo and
reject absence of that exact tmpfs mount, unsafe parent ownership/modes and
symlink targets. This is an explicit simulation fixture, not a claim about the
real camera's SD pathname or its `/tmp` filesystem. Original firmware mounts
were previously found to include VFAT; those findings remain unchanged.

The fixture places `runner`, `plugin.meta` and `plugin.so` on that mount, then
remounts **only this dedicated fixture** read-only. Hashes are compiled into our
trusted host/runner; no untrusted SD manifest can authorize a new payload. The
same open runner inode is used for exec, and the same plugin descriptor is used
for dlopen. Root-owned fixture directories, the read-only mount and trusted
original runtime libraries bound this simulation's TOCTOU/dependency assumptions.
They do not solve hostile-card replacement on a real camera. Exact interpreter,
NEEDED libraries and symbol versions of our binaries are exported in the build
receipt. The dependency bytes are the pinned original guest runtime, not SD
search paths; the exec environment does not carry LD_PRELOAD/LD_LIBRARY_PATH.

Missing cards and pre-launch unmounts fail closed. A separate live-removal
fixture detaches only this mount after the plugin constructor reports its
restrictions, then requires the same wall timeout and reaping. This models mount
disappearance with held references, not real SD electrical/IO failure. The noexec and executable-permission tests
must fail without a remount or built-in executable fallback. Successful cleanup
unmounts the disposable fixture and removes its enable marker. Nothing is
registered for boot or service startup. A new VM does not consume a stale request.
The harness only runs when explicitly requested through the fixed CI command.

## Evidence levels and tests

The guest test runs a **synthetic multithreaded host using the original guest
libc/loader ABI** alongside the original camera UI. It is stronger than a
single-threaded qemu-user/distro-library test, but is not the original USB service
calling dlopen. UI input and response after native failures are checked using
original input press/release events, a recognized native screen, changed
selection pixels and exact restoration. No nonempty-image-only assertion or
fake overlay is used as UI responsiveness evidence.

The suite covers normal operation, disabled operation, missing/ejected media,
missing files, symlinks, wrong version, invalid ELF, hash mismatch, oversized
files, exec permission/noexec errors, real constructor/runtime SIGSEGV,
constructor/runtime hangs and wall timeout, repeated dlopen/dlclose while busy,
FD sentinels (directory/device/socket/high-number descriptor), pre-constructor
privilege restrictions, targeted reaping and recovery to another normal run.
Fresh-VM checks cover no marker/mount residue and responsive original UI.

There is no arbitrary plugin enumeration, writable shared bridge, firmware patch,
persistent Backup write, startup configuration, WBI operation or real USB call.
The fixed `sd_suite` controller action runs only the synthetic guest harness;
`sd_clean` checks its fixed marker/mount names. Existing bytecode HelloWorld is
separate and unchanged. This route's HelloWorld is the fixed text result through
a pipe, not an overlay and not access to parent camera RAM.

## Reproduction

Use the existing QEMU Actions workflow on `ci/qemu-actions`, with `firmware=true`
and `sd_route_only=true` for an isolated iteration. Full regression uses
`sd_route_only=false`, `fl23_only=false`. The original firmware is supplied only
by the existing Actions secret, never stored in repository/cache/artifacts.
QEMU exact cache logic and the approved bwrap profile are unchanged. This stage
adds no real-device command. See the final result/build receipts for tested
commit, actual outcomes and limitations; source code alone is not a passing test.

## Failure assertions and trusted code

The runner rejects version mismatch with 22, a missing plugin with 23, hash
mismatch with 24, a symlink with 34, size violation with 35 and invalid ELF with
36. IO/permission failures have separate codes and cannot satisfy those tests.
Each pre-load rejection requires EXEC_READY but forbids PRELOAD_READY and the
constructor receipt. Missing media fails before exec; EACCES/noexec must fail
at spawn with no exec receipt. Crashes require actual SIGSEGV, and hangs require
SIGKILL from the wall watchdog, constructor constraint evidence and advancing
host heartbeat while the child is still unreaped.

The 15-line entry is not the whole trusted computing base. The resident
broker/reaper, mount/file/hash checks, whitelist, runner, original dynamic loader
and runtime libraries, and guest kernel are also trusted. The host source also
contains simulation-only fixture preparation and assertions; those are not a
camera deployment mechanism. Replacing a plugin requires a new reviewed build
and hash pin, which changes the runner pin too. There is no SD-supplied manifest
that can grant trust to new native code.

## Investigation history and evidence limits

The first instrumented build failure identified unavailable `__isoc23_sscanf`
and `__isoc23_strtol` symbols against the original glibc 2.25. The implementation
now uses the existing `__isoc99_sscanf` ABI and its own bounded FD-number parser;
it does not replace the original runtime libraries.

Run 41220562696 reached the original UI, returned from the entry in 4 ms, exec'd
the runner, completed the pre-load restrictions and then returned 31 from
`dlopen`; no constructor receipt was emitted. That run did **not** record the
file mode, actual dlerror text/class or inherited umask. In particular there is
no direct pre-fix evidence of `INPUT_MODE=256` (0400), `LOAD_ERROR=1` or umask 077.

The fixture copier previously passed 0444 to open without restoring permissions
after umask filtering. It now explicitly fchmods its own newly created fixture
to the requested mode. Run 41221698482 records `INPUT_MODE=292` (0444) and passes
normal loading with UID/capability/resource constraints retained. Permissions
are therefore a plausible explanation supported by the repair and outcome,
not a directly proven unique root cause of the earlier exit 31; other review
improvements were included in the same iteration. A typed dlerror classifier
is retained for future failures without exporting uncontrolled loader text.

The successful dedicated run at commit `1e2bea9` exercised 20 native cases and
original UI selection/restoration before faults, after faults and in a fresh VM.
Entry-return measurements were 0–7 ms in that run. Both VM closes succeeded on
the first attempt. Final stricter error-code, active-heartbeat and original-file
hash checks are part of the subsequent full-regression commit `07e4e04`.

The `reaped` result field means this broker performed the reap. In the deliberate
`ownership_lost` case it is zero because the test's competing thread has already
reaped the child; that thread's returned PID is checked, and the broker records
zero signal attempts. This does not establish a safe reaper contract in Sony's
unmodified service or eliminate races with an uncontrolled foreign reaper.

## Final delivery

[Full regression 41222065149](https://github.com/YLTai/a7c2-qemu/actions/runs/41222065149)
passed at `07e4e0450ff3761ae0eafad52da08e0b77f35b51`: original firmware boot,
existing bytecode HelloWorld/recovery, native SD route, and FL23 original menu,
parameter readback and rollback. The existing bytecode test needed one VM
cleanup retry; it is not an all-first-attempt-cleanup result.

A subsequent two-line per-case diagnostic reset is commit
`5126fe5744bf7bc035ed6827ce103b79340464da`.
[Targeted verification 41223725068](https://github.com/YLTai/a7c2-qemu/actions/runs/41223725068)
passed all 20 native cases, original UI checks, original appFw/Backup hashes
before/after, and fresh-VM recovery. The no-child missing-card case now correctly
reports zero active-child heartbeat ticks. Entry return was at most 11 ms in
that run. Both VM closes succeeded on their first attempt. Unchanged full-suite
areas were not rerun for this diagnostic-only reset.

[The evidence receipt](evidence.json) includes exact commits, artifact IDs,
case records, build hashes, ABI dependencies, cache keys and limits. Both exact
QEMU source and binary caches were restored during the full run. Own-program
NEEDED libraries are libc, libdl, libpthread and the AArch64 loader; imported
symbol versions are GLIBC_2.17, tested against the original guest's glibc 2.25.
The executable interpreter is `/lib/ld-linux-aarch64.so.1`.

| New source | Lines | Role |
|---|---:|---|
| `runtime/analysis/sd-route-entry.c` | 15 | Minimal fixed request entry |
| `runtime/analysis/sd-route-host.c` | 265 | Resident broker plus synthetic host/fixtures |
| `runtime/analysis/sd-route-runner.c` | 80 | Validation, restrictions, native load |
| `runtime/analysis/sd-route-common.h` | 57 | Mount, file and SHA checks |
| `runtime/analysis/sd-route-plugin.c` | 42 | Native success/fault fixtures |
| `runtime/analysis/build-sd-route.sh` | 50 | Original-ABI build and receipts |
| `tools/ci/sd-route-smoke.py` | 135 | Guest/native/UI assertions |

These seven files total 644 lines, excluding existing SHA code, integration
edits, documentation and JSON evidence. Final binaries: entry 3712 bytes,
runner 13144 bytes, synthetic host/broker 24064 bytes. Payload binaries are not
published in the CI artifacts; the source and metadata are reviewable.

The recovery screenshot is from successful dedicated run 41221698482 and was
visually inspected and saved to the user's Library. The final evidence receipt
pins its PNG hash and source run. It shows original UI selection after faults,
not a native plugin overlay or real-camera photo.

Remaining integration blockers are concrete: the unmodified Sony service has
no verified `sd_route_request_v1` broker ABI or exclusive-child-reaper contract;
physical SD path/filesystem behavior and the Sony USB invoke lifecycle are not
validated by this synthetic host. A stuck spawn needs external supervision for
a hard overall deadline. No hardware operation is pending, and the camera upload
CLI remains disabled. This is the completed QEMU fault-boundary prototype, not
an installable camera loader or a malicious-native isolation claim.
