# Next boot plan — loader proof, process scaling, and SURT hardening

Date: 2026-07-15

Baseline: `main` at `0c7d677`, executive gate 170/0, winlogon stops in a repeated
loader-shaped syscall sequence and eventually faults below `STACK_GROWTH_FLOOR`.

## Audit corrections

- The exact repeatedly loaded DLL is still unproven. Existing diagnostics log
  `NtQueryAttributesFile` misses and demand-load misses, but do not retain the
  successful `NtOpenFile -> NtCreateSection -> NtMapViewOfSection` identity that
  forms the loop. Treat `sfc.dll` as a hypothesis until the successful path is
  traced.
- The DLL registry no longer has a five-process ceiling. Its per-process handle
  stores grow on demand and are covered by tests beyond the reserve.
- `MAX_PI` is already 16, so the fixed bookkeeping arrays no longer fail at the
  sixth slot. The effective five-process ceiling remains in the hardcoded
  badge-to-pi switch, five pre-created EPROCESS/ETHREAD sets, fixed executive VA
  aliases, and process-specific `NtCreateProcessEx` branches.
- The root cause underneath that ceiling is the executive allocator model.
  Durable runtime allocations are unsafe across the per-syscall bump-heap
  rewind, so processes, threads, handles, and vectors are pre-created or
  pre-reserved. This must be fixed before process creation can be genuinely
  dynamic.
- SURT's ring core is small, coherent, and well tested. The local `../surt`
  workspace passes all 30 unit, stress, binding, and doc tests.
- The implemented `surt-sel4` is intentionally only notification/wait-loop
  glue. The richer handshake, capability validation, connection lifecycle,
  teardown, and peer-fault behavior in `docs/architecture/surt_sel4_binding.md`
  are design text, not implemented APIs.
- NTOS currently uses published `surt-sel4 0.1.1`, not the adjacent checkout.
  The lockfiles match the adjacent repository today.
- NTOS stamps `feature::REQUIRED_V0_1`, including registered buffers, but its
  service channels pass `buffer_id = 0` and use raw offsets into sidecar request
  and reply frames. Servers do not consistently validate `offset + len` before
  constructing slices.
- Several SURT push loops collapse `Full` and `Closed` into the same retry path.
  A faulted or closed peer can therefore produce a permanent spin rather than a
  contained service failure.

## Increment 1 — prove the winlogon loop

1. Add a fixed-size, allocation-free loader trace in `.bss`.
2. Record winlogon's successful and failed `NtQueryAttributesFile`,
   `NtOpenFile`, `NtCreateSection`, `NtMapViewOfSection`,
   `NtProtectVirtualMemory`, and `NtFlushInstructionCache` transitions.
3. Retain the folded path or registry slot, returned handle/base, status, and a
   repetition count. Dump only the tail at the existing stop report so the
   diagnostic does not perturb scheduling with thousands of serial writes.
4. Re-run the 170/0 gate and name the repeated DLL from the trace.
5. Inspect the actual LiveCD binary's imports/exports/forwarders read-only. The
   image already contains `sfc.dll`, `sfc_os.dll`, and `sfcfiles.dll`, so a
   missing staged file is not assumed.

Acceptance:

- The normal gate remains 170/0 with paint unchanged.
- The stop report identifies the exact DLL and the first failing transition.
- No loader fix or new pinned DLL is accepted before this evidence exists.

## Increment 2 — fix the diagnosed loader failure

Choose the narrow branch selected by Increment 1:

- Resolve/open miss: fix canonical path, VFAT LFN, SxS/activation-context, or
  filesystem staging behavior at the real failing layer.
- Section/map/protect failure: implement the missing section or VM semantics and
  preserve the loader's returned base/size/protection contract.
- Forwarder failure before `NtOpenFile`: implement the activation-context and
  forwarded-module lookup path so `_vista` modules are ordinary resolvable
  dependencies; remove pins only after the real path is proven.
- Successful load followed by initialization failure: capture the exception or
  failing syscall and implement that contract rather than retrying or growing
  the stack.
- Setup policy loop: correct the LiveCD/setup registry state and continue toward
  setup completion rather than forcing a desktop boot.

Acceptance:

- Winlogon exits the repeated load sequence without relying on unbounded stack
  growth.
- The next stable checkpoint is recorded before changing unrelated syscall
  behavior.

## Increment 3 — replace the rewind allocator

1. Move the single-threaded component allocator to a reclaiming free-list (with
   split/coalesce) or an equivalently tested allocator that honors `dealloc`.
2. Put the allocator algorithm in a host-testable crate; test alignment,
   fragmentation, coalescing, exhaustion, and repeated allocate/drop cycles.
3. Remove `mark/reset_to` from the syscall loop and delete the "pin the heap
   high-water mark" escape hatches.
4. Remove pre-reservation that exists only to survive rewind. Retain reserves
   that are justified by performance or explicit resource policy.
5. Exercise long registry, loader, and SURT request loops under the reclaiming
   allocator before enabling runtime process-object allocation.

Acceptance:

- A long synthetic syscall loop has stable live heap usage.
- Durable objects allocated during a syscall survive after return.
- Dropped temporary vectors and strings are reusable without aliasing.

## Increment 4 — make hosted processes data-driven

1. Introduce one durable `HostedProcessRuntime` record keyed by EPROCESS pid and
   fault badge. Fold pml4, main-thread identity, scratch VA, stack/heap/image
   mirrors, fill bookkeeping, and loader state into it.
2. Allocate fault badges dynamically and replace the hardcoded badge-to-pi
   switch with a lookup. Keep thread badges linked to their owning process and
   thread record rather than special-casing listeners.
3. Allocate executive-side mirror/scratch windows from VA arenas. Target-process
   VAs may remain identical because each process has its own VSpace; only the
   executive aliases must be unique.
4. Create EPROCESS/ETHREAD objects at runtime through `nt-process`; remove the
   five pre-created process set and spare-thread pools.
5. Generalize SEC_IMAGE process creation so `NtCreateProcessEx` spawns any
   validated executable section from the real filesystem. Delete the dedicated
   services/lsass spawn branches after parity.
6. Add cleanup for process exit: revoke/delete caps, release badge and VA
   allocations, unmap mirrors, and retire loader/process bookkeeping.

Acceptance:

- A host/mechanism test creates and reclaims at least 32 processes without a
  source edit or fixed per-name branch.
- Existing smss, csrss, winlogon, services, and lsass checkpoints are unchanged.
- `userinit.exe` becomes the sixth process through the generic path and begins
  its real loader.

## Increment 5 — harden SURT as the isolation substrate

### 5A. Immediate NTOS fixes on SURT 0.1

1. Validate every SQE before forming a shared-memory slice: checked
   `offset + len`, frame bounds, opcode, and protocol-specific maximums.
2. Distinguish `PushError::Full` from `PushError::Closed`; bound waits and return
   peer/service failure instead of spinning forever.
3. Give every isolated service a fault endpoint and connect peer death to the
   channel error path.
4. Stop advertising registered-buffer support until the channel actually uses
   it, or register the sidecar frames and send real generation-bearing
   `buffer_id` values.
5. Add a destructive test: fault a service mid-request and prove the executive
   remains alive and receives a deterministic failure.

### 5B. SURT 0.2 in `../surt`

1. Reconcile the architecture document with the public API, then implement a
   small connection/control layer rather than duplicating setup in every NTOS
   component.
2. Add negotiated ABI/features, frame geometry validation, cap-role validation,
   READY/DRAINING/CLOSED/FAULTED transitions, and explicit teardown.
3. Expose lifecycle operations without weakening SPSC ownership or the current
   cached-geometry safety model.
4. Add real two-address-space rust-micro tests for setup, notification latching,
   backpressure, orderly close, and peer fault.
5. Release and update all standalone component lockfiles together. Avoid a
   permanent `../surt` path dependency; use the adjacent checkout for
   development and consume an exact released version or pinned git revision.

Acceptance:

- No malformed descriptor can create an out-of-bounds slice.
- Closed/faulted channels terminate requests instead of spinning.
- NTOS service bootstrap uses one reviewed connection primitive.

## Increment 6 — replace broad no-op success with real policy

Implement by observed boot demand, but never leave blanket success for an
unsupported information class:

1. Build per-process VM region/VAD tracking and implement
   `NtFreeVirtualMemory`; converge `NtAllocateVirtualMemory` and
   `NtProtectVirtualMemory` on the same page-state model.
2. Implement the information classes actually requested by
   `NtSetInformationProcess`, `NtSetInformationThread`, and
   `NtSetInformationObject`; return a truthful unsupported status for the rest.
3. Route file information classes through the I/O manager rather than accepting
   them generically.
4. Move process primary tokens, thread impersonation tokens, privilege enablement,
   and access checks onto `nt-security`; eliminate fake-SID and unconditional
   privilege success paths incrementally.
5. Add syscall contract tests for output writes, lengths, previous mode,
   process-local handles, and failure statuses before enabling each handler live.

## Increment 7 — registry durability and bootstrap-fake retirement

1. Make the isolated Configuration Manager the live registry authority instead
   of maintaining parallel executive-only behavior.
2. Preserve the overlay as a transaction layer, then add hive serialization and
   storage writeback with explicit flush/commit semantics.
3. Model volatile keys separately so not every successful write implies disk
   persistence.
4. Retire pi 0-2 registry/event fakes once their real manager-backed paths cover
   the same calls.
5. Remove hardcoded `SystemRoot` and setup/account/service defaults as the real
   hives and setup state become authoritative.

Acceptance:

- A value written through `NtSetValueKey`, flushed, and rebooted is read back.
- Volatile values disappear after reboot.
- Setup can advance using registry state produced by setup itself.

## Execution order

1. Loader trace and read-only confirmation.
2. Diagnosed loader fix.
3. Reclaiming allocator.
4. Generic process/thread runtime and sixth-process proof.
5. SURT 0.1 containment fixes, followed by the SURT 0.2 connection layer.
6. VM/information/security syscall correctness driven by the new boot frontier.
7. Registry writeback and remaining bootstrap-fake retirement.

Every increment must keep the previous boot gate, add a focused counted check,
and record the next real stop before widening scope.
