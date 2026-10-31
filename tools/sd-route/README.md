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
