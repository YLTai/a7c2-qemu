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
