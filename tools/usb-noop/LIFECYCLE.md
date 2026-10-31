# ILCE-7CM2 2.01 lifecycle investigation

This is a static investigation of the original, pinned firmware, not a camera
test. No USB connection, hardware passthrough, target-native execution, startup
change, retained-image operation or camera upload was performed. The no-op CLI's
camera execution path remains disabled.

## Decision

**Do not enable the existing upstream upload chain under a RAM-only assumption.**
The original boot configuration and Jiritsu implementation contain VFAT-backed
paths for both `/tmp` and `/tmp/jiritsu`. A separate nested tmpfs used by another
Jiritsu execution path does not make the original uploaded file volatile.
An initialization path also requests loading an existing `libJit.so`; absence
of a startup registration by our payload cannot establish absence of firmware
consumers of residual files.

This blocks a dependent upload, not this offline analysis. No upload was tried,
and no additional permission was requested or denied. It is not necessary or
appropriate to upload a probe to establish the safety of uploading that probe.

## Inputs and evidence boundary

`tools/ci/lifecycle-static.py` reads only original files whose bytes and sizes
match `runtime/analysis/sony-assets.json`. Existing import verification pins the
official model, version, original partition images and initrd. Original and
derived/project-overlay files are distinguished; derived QEMU mounts are not
camera evidence. AP and CP are separate:

| Input | SHA-256 | Scope |
|---|---|---|
| AP appFw.so | `2ea02f7ecbc5bb917316fe8ef4ce5ffd87eb66efaae78ba2ce11420552df539b` | Original identity anchor |
| AP libJiritsu.so | `87dc24912938be8dd59965e62306e79fdd8c672e10ed6f9734c88454b1d144a8` | Loader/file-service analysis |
| CP cpapp-b.bin | `f5a477588698ef965748903b8959a39ce4f59ffd4aee4d4234ef1670f56a1428` | Identity/inventory only, no CP disassembly |
| initrc/fstab | `3936e6508ba89a025fc998c824434562c2d16234db96e179ec3f3a90a5a1d6f0` | Original mount declarations |

The analyzer exports a bounded JSON schema with hashes, line references, path
facts, symbols, direct branch/call targets and candidate argument values. No
original script bodies, raw instructions, binary fragments, firmware download
URL or full private preparation log is exported. Firmware and unpacked files
are not cached or included in artifacts. `lifecycle_audit=true` rejects combined
`firmware=true`, so this investigation cannot silently turn into a firmware run.

Argument tracking is deliberately limited linear static analysis, not a full
symbolic executor. Candidate values and zero/selector tests do not establish
dynamic reachability. Function/call limits are explicit in the report. Negative
string searches are not proof that a behavior is absent.

## 1. Mounts and canonical paths

Original `/sbin/initrc/fstab`, line 7, declares `/dev/nflasha10` at `/tmp`, type
`vfat`, options `rw,nodiratime,noatime,sync,posix_attr`. `/sbin/initrc/fstab.ext`
also declares that device for `/etc` and `/var`; runtime configuration therefore
cannot be inferred solely from the unmounted initrd's directory contents.
`/sbin/init2`, line 50, separately mounts tmpfs at **`/tmp_wbshd`**, not `/tmp`.
`setup_rootfs` includes a chroot/init2 transition. These are boot declarations
and paths, not a snapshot of the currently active camera mount table.

In the extracted image `/tmp` is a directory, not a symlink. `/tmp/jiritsu` and
`/etc/ld.so.preload` are absent there. This does not establish their runtime
absence after mounting other filesystems. Image path resolution is bounded to
the image root and never follows a guest absolute link into the CI host.

In libJiritsu, the SET_FILE2 and GET_FILE2 handlers have calls to `sys_mount`
with `/dev/nflasha6` and `/tmp/jiritsu`; the wrapper supplies `vfat` to
`CFileAccess::mount`. These are conditional service paths, not an assertion that
every request remounts the filesystem. If this mount is active it is a deeper
covering mount than `/tmp` for the upload target. Its success and the currently
active namespace still require live evidence.

A separate `jit_thread` path calls `ramdisk_mount` for
`/tmp/jiritsu/ramdsk_libJit`, copies a library to its `libJit.so`, then loads it.
`ramdisk_mount` calls the real `mount` API with type/source `tmpfs`.
That **nested copy** must not be conflated with the input file
`/tmp/jiritsu/libJit.so`. The upload handler itself has a direct dlopen path.

No new bind mount, symlink, ramdisk, or alternative upload location is created by
our tool. Current deepest mount, parent symlinks, mount namespace and mount
success cannot be certified from offline image entries alone.

## 2. Upload loader and existing-file consumers

The following are link-time virtual addresses in the pinned AP library, not
camera runtime addresses or write targets:

| Function/call | Address | Static evidence |
|---|---:|---|
| `adj_cmd_set_file2` | `0x986c` | File creation/write, fsync and close precede loader branch |
| `dlopen` call in SET_FILE2 | `0x9c4c` | Flags candidate is 1; filename comparison in this handler includes `/tmp/jiritsu/libJit.so` |
| Handle test | `0x9c50` | Nonzero returned x0 branches to `0x9c6c` |
| `dlclose` call | `0x9c6c` | Nonzero-handle cleanup branch; null handle follows a diagnostic branch, not proof of a particular protocol error reply |
| `CImJiritsu::init` | `0xba3c` | Creates an OSAL waitable thread |
| Initial request | `0xbb1c` | Request candidate 1 with `libJit.so` and `tmmc.jit` paths |
| `CImJiritsu::jit_thread` | `0xbc74` | Message reception, file checks, mount/copy/load and symbol lookup paths |
| Alternate `dlopen` | `0xc028` | Separate threaded execution path |

This is native library loading in the existing service process, not creation of
an isolated plugin process. ELF initialization runs as part of the loader; our
candidate must return rather than exit its host. A successful unlink only removes
the pathname; it does not prove the mapping is unloaded. A dlclose call site does
not prove successful dynamic unloading on a real camera.

`jiritsu_init` contains conditional mode/state handling, references `/tmp/jmode`,
and can construct and initialize `CImJiritsu`. The thread also references
`/tmp/jiritsu/jinit`, `tmmc.jit`, a backup archive/hash pair and `/tmp/jbusy`.
The initialization request demonstrates an existing-file consumer, not a proof
that every cold boot automatically executes every leftover library. The complete
startup callers, service re-entry conditions, mode values, asynchronous requests
and retained-image state are not exhaustively reconstructed here. Both claims
“always autostarts” and “never autostarts” would overstate this evidence.

## 3. Warm versus cold startup

Warm/resumed startup can preserve state beyond the lifetime assumed by a fresh
process model. This analysis does not equate a camera power-switch cycle with a
fresh kernel, new mount namespace or cleared retained image. No WBI drop, mode
change or boot-configuration write is allowed or performed.

A true fresh cold boot normally loses live RAM contents, but that fact does not
erase files on the declared VFAT block-device paths. Cleanup would require a
separate firmware policy, filesystem action, or explicit deletion. Such complete
cleanup has not been proven here. Boot scripts and file consumers must be
considered alongside the retained-image mechanism; neither a pathname `/tmp`
nor a claim that the user installed no modifications proves file removal.

## 4. Can an existing non-native read prove the live state?

The upstream host transport can select a path and issue GET_FILE2 without
uploading native code. That is a protocol capability, not yet a verified
side-effect-free acquisition method for procfs. The original GET_FILE2 handler
includes mount branches and a separate open/write/fsync/sync branch; its normal
file read path also calls stat before reading. Procfs files may have zero reported
length. Complete content retrieval, branch selection and absence of an
intermediate persistent file must be established before recommending a command.
The bounded selector trace found comparisons of internal message byte offsets
40–42 against 0, 1 and 255 in the SET/GET_FILE2 handlers. GET_FILE2 also has a
comparison against 768 before its write-capable branch. These are internal
handler offsets/candidates: a complete wire-packet-to-message mapping and all
branch predicates have not been verified. Do not turn these observations into
an unreviewed packet recipe or assume that choosing 255 avoids every side effect.

Minimum desired live evidence would include the **service process's** current
mountinfo, resolution/type of every parent of `/tmp/jiritsu`, the deepest covering
mount and relevant existing-file/mode state. `/proc/self/mountinfo` alone does not
prove all symlink targets. Merely reading `/proc/self/ns/mnt` as a regular file
does not substitute for a readlink/stat-capable interface. A host-side or QEMU
mount table is not the service namespace.

Therefore no camera read command is shipped or run by this stage. The smallest
next step is to finish validating a bounded non-native procfs/path-metadata
acquisition route (including its selector and zero-length-file behavior), then
seek separate authorization for a narrowly scoped live read. If the available
service API cannot provide it without writes, report that limit; do not fall back
to uploading a probe, mounting a new tmpfs, installing a startup shim, or changing
WBI. Runtime reads would still not prove all future startup consumers absent.

## Reproduction and validation

The final analyzer commit is `a4d0d3bbf4a745bc0bacd14969db711c8b9438f6`.
[Actions 41214574230](https://github.com/YLTai/a7c2-qemu/actions/runs/41214574230)
completed successfully with `lifecycle_audit=true`, `firmware=false` and the
existing exact QEMU source/binary cache hits. All original input hashes passed.
The no-op offline regression passed; Sony firmware boot, menu and plugin guest
execution steps were skipped. No target firmware executable was run by the audit.

Artifact `qemu-build-logs` (`13047289544`) includes the bounded
`lifecycle-static.json`, 204242 bytes, SHA-256
`517a8bf6b00f96236b10c3ae4bba3f0aacf307d0a87608431ddcd2a6614eaa24`.
[lifecycle-evidence.json](lifecycle-evidence.json) preserves a small curated
metadata subset in the repository. The full report has 46 selected Jiritsu
functions, without hitting its selected-function or per-function call limits;
this is not a complete application/boot call graph. Symbol selection and other
explicit scope limits still apply.

Earlier successful surveys: runs 41213255985 and 41213653397. Run 41214180981
hit the report size limit: pretty JSON for the final facts is 425189 bytes.
Compact JSON preserves the facts within the unchanged 400000-byte ceiling; no
raw private diagnostics were exported to resolve that failure. Local synthetic
checks covered fstab extraction, guest-absolute symlink confinement and AArch64
byte-selector comparison/branch provenance.
