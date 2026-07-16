# ntdll port — BATCH 1: process-launch Rtl group (test-driven) + establish the Port Pattern

Picking up at HEAD `17ee42e` (Step 6.A native transport DONE). smss (flag ON) stops at
`NtRaiseHardError(190)` in `SmpExecuteImage` because `RtlCreateProcessParameters` +
`RtlCreateUserProcess` are still 4.0b seams.

## The batch (spec-critical: smss's SmpExecuteImage → csrss spawn)
- [ ] **RtlCreateProcessParameters** — port ppb.c body (pure heap/struct builder). PRIMARY WALL.
      Source: `references/reactos/sdk/lib/rtl/ppb.c:49`. No apitest → write I/O validation tests.
- [ ] **RtlDestroyProcessParameters** — RtlFreeHeap wrapper (ppb.c:242).
- [ ] **RtlNormalizeProcessParams / RtlDeNormalizeProcessParams** — pointer rebase (ppb.c:255/280).
- [ ] **RtlCreateUserProcess** — the syscall-driver (process.c:194). Port the LOGIC; if a syscall
      out-param/marshalling breaks, flag as transport wall.

## Pattern (document in ntdll_plan.md as "## Port Pattern")
1. Identify ReactOS source (file:function) + prototype.
2. Tests first (apitest port OR I/O validation test capturing the contract).
3. Port body to `crates/nt-ntdll/src/rtl/` (pure logic, host-tested).
4. Export C-ABI wrapper in `nt-ntdll-dll/src/exports.rs`.
5. Host-green: `cargo test -p nt-ntdll`.
6. Boot-verify (flag ON): smss runs further (oracle-diff vs flag-OFF).

## Steps
- [ ] Add pure `process_params` builder to `crates/nt-ntdll/src/rtl/` with host tests.
- [ ] Wire the 4 exports.
- [ ] Add executive SSN-50 (NtCreateProcessEx) arm IF smss emits SSN 50.
- [ ] Boot flag ON, oracle-diff, checkpoint.
- [ ] Commit flag OFF (main green), host tests green.
- [ ] Document pattern + batch results in ntdll_plan.md.

## Review — DONE (milestone: smss spawns csrss on OUR ntdll)
- RtlCreateProcessParameters/Destroy/Normalize/DeNormalize: ported from ppb.c, 7 host tests. Pure
  builder in `crates/nt-ntdll/src/rtl/process_params.rs`; exports in `nt-ntdll-dll`.
- RtlCreateUserProcess: ported from process.c (RtlpMapFile→NtCreateProcessEx→NtQuerySection→
  NtQueryInformationProcess→RtlpInitEnvironment→RtlCreateUserThread) in `on_target.rs`.
- Executive SSN-50 (NtCreateProcessEx) arm added (routes to NtCreateProcess handler; 49 is a prefix).
- **User pivot honored**: removed the real-ntdll fallback entirely. Our ntdll is now staged AS
  `\reactos\system32\ntdll.dll` (same name, overwriting the ReactOS one; real ntdll NOT on image).
  Removed the SMSS_USE_OUR_NTDLL flag + OUR_NTDLL_FS_PATH. Derive LdrpInitialize RVA from the loaded
  ntdll's export table; propagate to ALL spawns via img_spawn::OUR_LDRP_RVA.
- BOOT PROOF: smss runs FULLY on our ntdll → SmpExecuteImage → RtlCreateProcessParameters →
  RtlCreateUserProcess → NtCreateSection(52) → NtCreateProcessEx(50) → **csrss spawned**. csrss then
  runs on our ntdll too (snap resolved=10), reaching NtAllocateVirtualMemory/NtSetInformationProcess.
- Host tests: nt-ntdll 157 (+7). Gate 146/98 (spec-break, permitted — winlogon/paint pending later
  batches as csrss/winlogon climb on our ntdll).
- NEXT batches: csrss's Rtl surface (csrsrv), then winlogon/services/lsass, then string/time/security
  Rtl modules per spec-priority.
