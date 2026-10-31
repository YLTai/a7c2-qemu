# GET_FILE2: bounded offline investigation

No camera request was sent. No USB transport was added or enabled. The existing
no-op CLI still rejects camera execution even with its confirmation option.
This investigation does not establish a safe live procfs/metadata acquisition
route. It also does not claim that all Sony non-native interfaces are incapable
of providing such information.

## What the upstream client actually sends

Source: QAQLeonard/a7c2-fl23-research at
`ef7db116e13e37be91e9af20360dc9bba8d64a9b`, read without executing its code.

* `src/desktopapp/usbcheck.py:14,52–60` repeatedly reads the regular files
  `/usr/lib/appFw.so` and `/cp/cpapp-b.bin`, checks size bounds and compares bytes.
  It does not upload/invoke the native probe. A user-reported successful run of
  this test is not evidence that procfs files or symlink metadata were read.
* `src/looks/looktool/devicesession.py:101–102` prefixes each requested path with
  `/tmp/jiritsu/../../`. This is a pathname, not proof of canonical resolution,
  the service's mount namespace, or absence of intervening mounts/symlinks.
* `src/camera_runtime/transport.py:404–416` selects a path with command 15 and
  parameters `00`, ASCII path, `00`; then command 17 has parameters `00 ff 00`.
  Both use function `0x40`, a little-endian `0x1001` category and command number.
  The client decodes a status word and returns file bytes. It does not return
  stat/readlink records. Commands 16 and 18 are outside this read sequence.
* The 12-byte Senser header is `<IHHBBBB>`; its size is the body length. The
  request's `ff` is the second parameter byte, not the first mode byte. USB
  segmentation/response framing does not itself establish handler-field layout.

## What the pinned original handler establishes

All addresses below are link-time AP library addresses, not runtime write
locations. Original input hashes are checked against the existing firmware
manifest. CP is a separate regular-file read target, not executed by this audit.

| Evidence in libJiritsu.so | Meaning and boundary |
|---|---|
| GET_FILE2 entry `0xa1b8`; byte loads at record offsets 40, 41, 42 | Three distinct internal fields; their external mapping still requires the service conversion edge |
| `0xa224` compares field 40 with 1; `0xa230` compares it with 255; mount call `0xa25c` | Mode selection includes the `/dev/nflasha6` → `/tmp/jiritsu` VFAT path documented in LIFECYCLE.md; successful mounting/current namespace is not established |
| `0xa378` branches past the log-flush block unless the little-endian word at record+40 equals `0x0300` | A specific conditional write/fsync/sync block, not an unconditional write for every read; other global-state gates also apply |
| `0xa438` calls CFileAccess::stat with output at local-frame+2728; `0xa470` loads 64 bits at local-frame+4808 | The caller consumes the helper's output field at offset 2080 |
| `0xa524` calls CFileAccess::read; `0xa550` compares its result with that 64-bit field | A size-based completion criterion. This is not evidence of read-until-EOF support |
| Normal read path calls fsync (`0xa540`) and close (`0xa548`) | “Read request” must not be described as a proven side-effect-free firmware path |
| Registered callback at `0xb61c` loads a 16-bit selector at record+38, checks a 20-entry range and dispatches indirectly | Handler names alone do not prove command-to-branch mapping |

The ordinary request's first two parameter bytes represent `0xff00`; the
log-export pair `00 03` represents `0x0300`. **If** the service copies these
parameters unchanged into record+40, ordinary reads bypass the reviewed
log-flush gate and enter mode-zero processing. That processing has another
selector-validation branch at `0xa248` before its mount call; its predicate is
not yet resolved by this analyzer. This is a conditional inference,
not a claim that a live read has no writes or that its mount succeeded.

## Remaining mapping/length limits

The bounded analyzer follows direct control flow and conservatively discards
origins that disagree at branch joins. It does not resolve arbitrary virtual
calls or indirect switch tables. The first linear-origin survey was superseded
by CFG analysis; its early-return-contaminated expressions are not proof.

The final pass narrows the service conversion: in libsencore,
`TransactionStart` at `0xfd24` and `0xfd30` stores the two argument-3 halfwords
into subsystem-record offsets 36/38. `Serialize` at `0xfd5c` receives a destination
at object+64, i.e. subsystem-record+40. `MakeOsalMessage` is called at `0x10078`.
This is useful partial correspondence, but the Serialize callback/input cursor,
its length, final OSAL packing, indirect command switch and high-capacity wrapper
remain unresolved. These are the specific missing edges before claiming that
host command 17 reaches this handler with unchanged parameters. The callback
survey ends at the next named symbol; that range may include additional unnamed
functions and is not a proven single-function boundary.

The helper thunk at `0x122f0` moves its path/output arguments and tail-jumps to
`__xstat` at `0x122fc`; the misleading nearest-symbol label `libCommuMD5+8` is not
its behavior. This confirms a POSIX stat path, but the conservative analyzer
still loses the read length at unmodelled operations/joins. No inference is
upgraded merely because the three-byte request shape fits the handler.

The read helper has POSIX read paths, and the GET_FILE2 caller checks the result
against its stat-derived information field. A stat-sized one-shot read cannot
retrieve nonempty procfs content whose reported size is zero. Our fixtures
exercise that failure mode explicitly. Until the complete size/argument flow is
proven for the actual route, zero-length procfs support is **unverified**, not
promised. Neither a zero-byte result nor an error would prove that a proc file
has no content. Regular-file stability does not test this edge case.

The reviewed host operation exposes file bytes, not canonical-path, readlink,
mount-namespace identity or stat metadata. Reading a symlink as a file does not
return its target string. Even a complete mountinfo response would still need
the correct process namespace and path-resolution evidence. Offline image
entries and QEMU mount tables cannot fill those runtime gaps.

## Decision and next authorized boundary

No executable hardware request list is provided: the reviewed route is not yet
reliably established as sufficient for full `/proc/*/mountinfo`, canonical path
and namespace evidence. Merely asking to read those names would hide both the
mount side effect and the possible stat-size truncation. Uploading a probe,
creating a tmpfs/shim or changing WBI is not an allowed substitute.

Any future live attempt needs separate authorization after choosing a reviewed,
bounded non-native API that supplies both stream contents and path metadata.
There is no pending camera request, no denied action and no uncertain device
execution from this investigation. Existing upload remains blocked by the
VFAT/residue findings in [LIFECYCLE.md](LIFECYCLE.md).

## Independent verification

`get_file2_model.py` has no transport, USB/network imports or executable command
entry point. It parses only synthetic command-15/17 packets, models the observed
handler gates explicitly as a hypothesis, and models stat-sized reads.
`test_get_file2_model.py` tests wire fields, malformed input, mutating-command
rejection, zero-size truncation, missing metadata and conservative CFG joins.
The combined offline suite has 19 tests (10 existing no-op tests plus 9 new
protocol/provenance tests). Models validate boundaries, not real camera behavior.

The analyzer emits bounded semantic facts/hashes only, never raw instructions,
firmware files, script bodies or private download URLs. It does not run firmware.

## CI evidence

Final analyzer/model commit: `5d400aa71baff7021e2b4492580fdf6dcc52c307`.
[Actions 41216512832](https://github.com/YLTai/a7c2-qemu/actions/runs/41216512832)
succeeded with `firmware=false`, `lifecycle_audit=true`. It passed all 19 offline
Python cases, the six synthetic own-library loader scenarios and existing FL23
host regression. Sony firmware boot/menu/plugin guest tests were skipped. The
firmware-free model regression also passed in
[41216428376](https://github.com/YLTai/a7c2-qemu/actions/runs/41216428376).
Existing exact source/binary cache logic was preserved; no firmware cache was
added. [get-file2-evidence.json](get-file2-evidence.json) pins the three AP inputs,
report hash/size, artifact ID and selected semantic facts. The bounded full
report is in artifact `qemu-build-logs`; no firmware binary is included.
