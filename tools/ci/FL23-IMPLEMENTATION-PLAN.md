# FL2 / FL3 local implementation checkpoint

Status: preflight and transaction core implemented; no functional FL2/FL3 plugin
or guest verification yet.
Base: `e600c9ce34ad3253eb820aba043bb46f3bb70b14` (`ci/qemu-actions`).
Research reference: QAQLeonard/a7c2-fl23-research at
`ef7db116e13e37be91e9af20360dc9bba8d64a9b`.
No upstream scripts have been executed or upstream implementation copied.

## Scope and boundaries

First milestone: real firmware Creative Look menu visibility, selection and
parameter readback in temporary QEMU. This does not establish CP gamma routing,
ISP processing, final photo appearance or real-camera compatibility.

Keep the existing display bytecode language and confinement intact. Implement
only fixed semantic FL23 requests through a trusted narrow broker; requests must
never supply addresses, replacement bytes, native code, syscalls or shell text.
The exact request schema and transport still need design and validation.

Do not modify original firmware files or persist Backup. Do not download firmware
locally. Firmware input remains the Actions secret; neither its value nor firmware
contents may enter logs, caches, artifacts or repository files. This checkpoint
does not authorize push, dispatch, merge or a different runner sandbox profile.

## Source findings in this checkout

- `runtime/analysis/ram-plugin-boot.c`: fixed display-only case allowlist,
  validated bytecode snapshot, isolated child, bounded mask output. FL23 cannot
  be represented by the current mask protocol.
- `runtime/analysis/seed-power-on.c`: native Backup read/write/readback before
  application startup provides a precedent, not a ready-made FL23 implementation.
- `runtime/analysis/qemu-menu-probe.py`: Backup module defaults to `Backup_save=0`,
  but `MENU_BACKUP_SAVE=1` overrides it; settings persistence is independently
  controlled by `A7C2_SETTINGS_PERSIST`. A FL23 profile must reject either enabled
  persistence path before boot, rather than merely relying on defaults.
- `runtime/analysis/menu-observe.c`: mapped-ready setup precedes
  `observe_application_init`. Determine the exact safe point relative to firmware
  constructors before adding data changes; mapped-ready alone is insufficient
  evidence that a menu model can be updated safely.
- `tools/ci/ram-plugin-smoke.py`: retain the existing real guest Hello World,
  rejection, overlay removal, recovery and restart regression coverage.

## Implementation sequence

1. Independently inspect pinned research data and actual ELF segment metadata in
   authorized CI. Establish target firmware identity, complete expected bytes and
   field sizes. Resolve file offsets through PT_LOAD segments; do not apply a
   universal offset delta. Refuse unsupported identity, unexpected bytes, missing
   mappings or permission mismatches. Report fixed result codes only.
2. Add a host-testable fixed FL23 transaction validator. Validate every location
   before any write. Save bounded originals; verify all writes and rollback on
   failure. Cover unknown versions, invalid segments, partial failure, rollback
   failure, repeated requests and external mutation. No caller-defined patches.
3. Add the trusted guest broker and opt-in startup profile. Seed only verified
   FL23 Backup records before model initialization with Backup saving disabled;
   apply only the verified AP data transaction at the validated initialization
   point. Halt this milestone if it requires persistent file patching. Coordinate
   Backup and AP failure handling; do not report enabled after partial success.
4. Define lifecycle semantics explicitly: after the live model has initialized,
   restoring raw fields may not undo cached state. Until a validated live reset
   exists, disable by normal VM teardown and fresh startup without FL23. Failed
   rollback or teardown must remain a failure, not a successful disable.
5. Add CI probes using real MENU input and original OSD with plugin overlay off.
   Prove FL2 and FL3 visibility, selection and native parameter readback separately.
   Use fixed-schema evidence and approved QMP screenshots; never synthetic screens
   or firmware memory dumps. Keep CP/color-processing and final-image results
   explicitly unverified until separately measured.
6. After coordination permits remote work, build and run only in GitHub Actions
   using exact existing source/binary cache keys and the approved bwrap profile.
   Run Hello World regression and fresh-VM FL23 disabled/enabled checks. No merge
   to main. A successful menu test must not be labeled a complete color plugin.

## Resume state

Local branch: `fl23-local-checkpoint`. Implemented:

- `fl23_preflight.py`: pinned source SHA-256, ELF64/AArch64 ET_DYN checks,
  bounded PT_LOAD parsing and seven fixed menu field original-byte checks. No
  constant file-to-memory delta, patch-file output or user-provided offsets.
- `fl23-menu-transaction.h`: internal fixed semantic-ID transaction core, complete
  original-value validation before any write, immediate readback, reverse rollback
  including partially failed writes, and a poisoned state if rollback fails.
  Trusted callbacks require exclusive pre-initialization ownership. This is not
  yet a guest adapter or an interface callable by plugin bytecode.
- Launcher rejects `A7C2_FL23_MENU=1` before staging or boot: first rejects either
  persistence flag or settings restore; otherwise reports `guest_adapter_unverified`.
  Existing runs with no FL23 request are unaffected. No false enabled state.
- Seven Python unittest cases pass locally, including actual launcher rejection
  before loading guest dependencies. The C fault-injection harness passes
  under AddressSanitizer/UndefinedBehaviorSanitizer with warnings treated as
  errors, including failures at each of seven write/readback/rollback positions.
- Actions steps prepared for the same host tests and read-only original ELF
  preflight after private firmware import. Existing cache keys, runner sandbox,
  Hello World tests and artifact allowlists are unchanged. No CI run dispatched.

Research original bytes and source identity are confirmed against the pinned
upstream JSON and existing importer. Actual ELF segments have NOT been verified:
this environment must not download firmware, and remote CI is deferred. Thus no
guest writes, Backup changes, menu appearance, selection, native readback or
complete color behavior have been tested. Next: coordinate CI preflight, inspect
the verified mappings in private staging, then implement the trusted guest adapter
and Backup transaction before demonstrated menu-model initialization. The current
hook is after `dlopen` (and thus ELF constructors) but before
`Application_System_Init`; it is not a pre-ELF-constructor hook. Do not remove the
launch gate merely because host tests pass.

No remote write or Actions dispatch made.
This isolation environment has no configured secrets or outbound identities;
public repository fetch worked. CI execution is intentionally deferred to avoid
concurrent external changes with the previous task.

## First coordinated remote preflight

After coordination, commit `4414b51aeb715a018a9c20fb50189c27f9ad03cd` was
fast-forward pushed from the expected `e600c9c` head to `ci/qemu-actions`.
[Actions run 41191522158](https://github.com/YLTai/a7c2-qemu/actions/runs/41191522158)
passed host tests, exact QEMU source/binary cache checks, sandbox and synthetic
launcher checks, and private firmware import. Original ELF preflight rejected
`field_permissions`; therefore subsequent real guest tests were skipped.
No FL23 guest modifications ran. The source hash matched before the permission
failure; the run does not establish that all seven fields passed validation.

A follow-up read-only audit emits only the seven fixed fields' virtual offsets,
sizes, ELF permissions, and non-executable section/page classification. It never
prints firmware contents and does not relax the launch or write gate. Determine
whether the fields occupy data-only pages within an executable PT_LOAD segment
before designing a bounded permission transition. No W+X mapping is authorized.

## Verified original ELF mapping facts

[Run 41191873237](https://github.com/YLTai/a7c2-qemu/actions/runs/41191873237)
at `0306bd5c3a7b4feff4d3afff104c607de91de40e` passed nine host tests and
the transaction sanitizer harness, restored the same exact QEMU caches, and
confirmed all seven original fields through the read-only audit. The preflight
still intentionally rejected the RX PT_LOAD segments, so guest tests were skipped.

| Fixed field | Relative ELF VA | PT_LOAD flags | Entire 4 KiB page is non-executable data |
| --- | --- | --- | --- |
| selection | `0x4b2ed19` | RX | yes |
| FL2 Fade | `0x4b3b544` | RX | yes |
| FL3 Fade | `0x4b3b54c` | RX | yes |
| FL2 binding | `0x4b4a5e4` | RX | yes |
| FL3 binding | `0x4b4a5ec` | RX | yes |
| FL2 visible | `0x59992ca` | RW | yes |
| FL3 visible | `0x5999382` | RW | yes |

The follow-up preflight accepts the positively verified non-executable data-page
classification, including data pages in RX segments. This changes only source
validation: guest enabling remains rejected. These ELF flags are not proof of
actual live page permissions. The guest adapter still needs fixed-page mapping
validation, exclusive initialization ownership, bounded W^X-preserving permission
transitions, restoration of original permissions, and rollback across Backup and
AP data. Neither ELF constructor timing nor live menu model refresh is established.

## Guest adapter implementation (pending guest execution)

Run 41192190919 completed successfully: source preflight, real firmware startup,
Hello World and negative/recovery tests all passed at `3f328ac`.

The next implementation adds `fl23-menu-guest.c` to the trusted observer, invoked
immediately before original Application_System_Init. Its interface has no caller
addresses or data; the only boot request is `A7C2_FL23_MENU=1`. It verifies four
fixed private file mappings (including file offsets/inode and original page
permissions), seven zero-valued fields and two empty native Backup binding bytes.
The launcher verifies the original ELF and selected initramfs, forbids firmware
overlays and persistent instances, rejects both persistence flags, and creates a
root-only RAM receipt only after a fresh `Backup_save=0` module load succeeds.

The broker uses RX->RW->RX for three verified data pages (never W+X), applies
seven bounded AP fields and native Backup bindings 10/11, and verifies readback
and permission restoration. Any failure aborts this guest process before original
application initialization. Partial writes trigger a joint rollback; an uncertain
rollback/permission state never reports enabled. `fl23_status` is a fixed read-only
request in the existing framework that invokes a no-argument native binding
query. It reports explicitly that selected-look and color effects are unverified.

Host fault injection covers both Backup writes, each of four page acquisition and
restoration failures, partial mutations and failed rollback. A fixed rollback-only
test request is available to CI; it always aborts initialization after reverting.
CI menu tests use disposable VMs, turn the Hello World overlay off, reuse reviewed
native firstboot navigation, and capture the real MENU frame before navigating
unreviewed settings. The suite remains failed until menu/selection checks are
implemented and observed; no synthetic screenshot or forced-screen hook is used.

The first adapter CI (`41193122867` at `046ce9e`) passed all host checks but
failed guest-helper linkage before any guest boot. The original glibc requires
`__fxstat(0,...)`, as already used by the display plugin; the adapter is corrected
to that ABI and the legacy `sscanf` symbol instead of build-sysroot C23 aliases.
FL23 diagnostic prefixes are now mirrored to the bounded console channel, so
startup failures and rollback can be inspected without publishing private logs.

Run `41193864425` reached the real FL23 broker but rejected live mapping before
any writes (code 3). The test's late ready-channel diagnostics then attempted SD
save despite application initialization having aborted; all three normal close
attempts failed. That run is not recovery evidence. The next probe reads only its
new private run directory before the ready reply, so startup abort uses the
existing starting-VM close path instead of treating it as a running camera.

Live mapping checks now admit R-only loader reductions of the original ELF
permissions (including RELRO), still reject W+X/shared/unexpected mappings, compare
both device and inode, and verify the *exact* saved permissions after restoration.
Fixed numeric map diagnostics distinguish the rejection reason without exporting
memory. An opt-in read-only disabled-VM audit checks all seven original AP fields
and both Backup bytes before app init; a synchronized observer verifies the AP
fields again after the first original frame. The status test also checks guest
appFw and Backup file SHA-256 values against the pinned original inputs.

These changes still do not assert menu selection or color processing. The menu
probe deliberately remains unsuccessful until reviewed native navigation and
selection/readback assertions are added. Diagnostic-only CI iterations may use
`fl23_only=true`; final validation must use the default false and include all
existing regressions.

## Observed guest checkpoint (82753d4)

Run `41195359797` confirms actual private mappings RX/RX/RX/R, a successful
joint AP/Backup transaction, exact permission restoration, and all seven AP
fields still matching after the first original frame. The actual screenshot is
the original language setup page; this is not Creative Look visibility evidence.
The run closed normally on its first attempt. Its independent fixed binding
helper returned 127 before any binding/hash output, so selection, persistent-file
hashes, native forced rollback, and disabled restart are not yet verified.

Commit `93d5ca8` links that helper with the same original OSAL dependencies as
existing Backup helpers. Run `41195691450` tests this correction; its result is
failed on the second readback stage: native bindings were exactly 10/11 but
original BusyBox has no sha256sum applet. The fixed helper now hashes only the
two fixed paths internally, with its SHA-256 implementation tested against
Python hashlib across empty input, padding boundaries and streaming blocks.
Neither the earlier transaction receipt nor first-frame AP checks
prove the live Creative Look model was initialized with the new choices.

## Correction: Backup_save is not a global gate

Run `41196397614` at `a20c61d` proves a disabled fresh VM retains seven AP
originals and native bindings 0/0, but its tmpfs `/setting/Backup.bin` hashes to
`29b5c7d43721ba2117371aa61b48741730c9730a1ce3d20703c9425bf0be81f6`,
while immutable seed and appFw retain their pinned hashes. This is not a FL23
write: no plugin transaction ran. Existing `report/config-persistence-frontier.md`
already establishes that Backup_save=0 does not gate every native save path.
The earlier inference from that parameter alone is withdrawn.

The launcher now protects the fixed guest tmpfs Backup file using a read-only
bind mount before loading the original driver. The broker checks actual tmpfs
type and ST_RDONLY before any mutation, in addition to both persistence flags
and a fresh module-load receipt. DMM inputs are populated before protection.
Failure to mount or validate aborts this disposable guest; no host sandbox or
original firmware file is changed. Guest compatibility remains to be tested.

The same preflight run confirms the current Look model at relative VA 0x5bc35b0
is uniquely file-backed RW non-executable data at file offset 0x5bb35b0. The
trusted observer now reads only that scalar after original frames, validates
its complete live mapping/file identity, bounds values to 0..25 and logs at
most 64 changes. It exposes no read-address request and never writes the model.
Native selection still requires reviewed menu screenshots and original input.

Run `41196866130` at `68bb493` proves the read-only guest file protection is
compatible with original startup: disabled baseline, enabled startup and fresh
disabled restart all preserve original appFw/seed/Backup hashes, AP fields and
native bindings match their expected states. Forced native rollback completes
and aborts before Application_System_Init; all four VMs close on the first try.
Original input traverses language/date/setup pages, reaches shooting, then opens
the actual MENU Main grid (screenshot artifact `13041450686`). Overall CI remains
unsuccessful because Creative Look navigation/selection has not yet been tested.

Subsequent diagnostic-only runs reuse this known baseline and focus on menu
navigation; the full default run retains baseline, rollback, restart and Hello
World regression. The broker also adds same-VM Backup SHA checks immediately
before/after the transaction, and during rollback; mismatch is fail-closed.

## Correction: product model is not selected Look

The earlier description of relative VA 0x5bc35b0 as a current-Look scalar was
incorrect. Pinned upstream `core.py:parse_native('probe')` requires 16 for camera
product identification and returns product_column 9. Observations of 16 therefore
prove no Look selection at all. Old artifact fields named model_indices must be
read only as product identity, not FL2/FL3 acceptance. Code now names this
PRODUCT, samples it once, and explicitly excludes it from selection evidence.
Original menu confirmation/readback remains necessary. No passing selection
result was produced using the misidentified field.
