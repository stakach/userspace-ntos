# PHASE B — Unified component-runtime harness (DESIGN APPROVED; harness-first)

Design note: `docs/component-harness.md`. Gate must stay **180/98** + clean qemu_exit at EVERY step.
Each step = one commit = one rollback point. win32k migrates LAST. READ-ONLY design done; this is the
implementation checklist. (Phase A = dead-code/diagnostic tidy — comes AFTER Phase B per user choice.)

## Key finding (shapes the plan)
Four components, but TWO families — not four variants of one:
- **Family A (persistent dispatch servers): npfs (FSD) + win32k.** Run `DriverEntry`, then loop
  `send_done → recv_req → dispatch → reply`; executive pumps them with an `ep_send(DISPATCH_LABEL)` +
  demand-map fault loop. Near-identical shape → the real consolidation target.
- **Family B (one-shot lifecycle runners): driver_host + kmdf_host.** Pre-map everything, run a fixed
  lifecycle, write a verdict, `SYS_SEND CT_RESULT_NTFN`, park. No dispatch loop, no demand-map pump
  (fault EP = crash-containment only). Only share `spawn_component` + `DriverExportRegistry`.

The launcher (`spawn_component`/`ComponentDescriptor`) is ALREADY shared. This work unifies the RUN loop.

## Step 0 — ABI scaffolding, wired to nothing (pure additive)  — DONE (commit a9b36d3)
- [x] Add `HostCaps` + `ReqKind` + `SH_REQ_KIND`(verify 0x38 free in both frames) to a shared const block.
- [x] Add `caps: HostCaps` field to `ComponentDescriptor` (`spawn_hosts.rs:88`); `HostCaps::default()` at
      all 6 descriptor sites (2 in `spawn_hosts.rs`, driver-host + kmdf inlined in `main.rs:6618/6708`,
      fsd `driver_launch.rs`, win32k builder).
- [x] Define `component_pump`, `component_main`, `run_once` — CALLED FROM NOWHERE yet.
- [x] VERIFY: gate 180/98 (byte-identical; no call sites touched).

## Step 1 — FSD executive pump → `component_pump`  — ACTUALLY DONE (gate 182/98)
> PRIOR STATE: Steps 1/2 had only landed `component_pump`/`component_main` as UNWIRED skeletons
> (zero call sites, dead code); the FSD still ran its bespoke `npfs_dispatch_irp`/inline loop. Step
> 4.5 kept that bespoke path and made it multi-instance. THIS batch actually wires the FSD through
> the shared harness.
- [x] Re-expressed BOTH executive-side FSD fault loops as `component_pump(&PumpChannel)` calls,
      `caps = { dispatch_server, kind: Irp }`, all win32k flags false:
      - `dispatch_irp(inst, …)` (the per-IRP loop; `npfs_dispatch_irp` is its instance-0 wrapper):
        `wake_first=true`, `image_frames=0`, `demand_cap=256`. Request-fill stays in `dispatch_irp`.
      - `load_driver`'s DriverEntry init loop: `wake_first=false` (the component is a blocked SENDER
        mid-init, not parked at a recv — the pump must RECEIVE first), `image_frames=FSD_IMAGE_FRAMES`,
        `code_va=run_va`, `demand_cap=512`, `trace_faults=true`.
- [x] Added `wake_first: bool` to `PumpChannel` (skeleton bug surfaced by wiring: the per-request
      shape wakes with a leading Send; the init shape must Recv first or it DEADLOCKS against the
      faulting sender — the design's pump always Sent first).
- [x] VERIFY: gate 182/98, all npfs specs PASS (see the harness proof spec below).

## Step 2 — FSD component entry → `component_main`  — ACTUALLY DONE
- [x] `fsd_component_entry` now delegates the whole DriverEntry-preamble + dispatch loop to
      `component_main(FSD_SHARED_VADDR, FSD_CODE_VA, DriverObjectSpec{size:0x150,ext:0x68,ext_size:0x50,
      mj:0x70}, SH_REQ_STATUS, FSD_DISPATCH_LABEL, fsd_dispatch, fsd_post_driver_entry)`. The FSD IRP
      router is `fsd_dispatch` (`major → MajorFunction[major] → run_irp`); `fsd_post_driver_entry`
      records the pool high-water + the `[fsd-host] DriverEntry returned` diagnostic line. BOTH the
      npfs instance AND `IrpFsdTest.sys` (they share `fsd_component_entry`) now run on the harness.
- [x] Retired the bespoke inline `dispatch_loop`/`send_done`/`recv_req` (now genuinely dead). The
      harness's `send_done_on(label)`/`recv_req_on()` are the shared implementation.
- [x] PROOF (durable, not green-alone): `component_pump` bumps `HARNESS_IRP_DISPATCHES` per serviced
      IRP dispatch; the counted gate spec `exec_fsd_on_shared_harness` asserts the live FSD traffic
      (both DriverEntry inits + npfs create/read/write/flush + the 2nd-driver IRP) flowed through the
      pump (`>= 8`). If the FSD were unwired the counter would be 0 → spec FAILS.
- [x] VERIFY: same npfs spec set PASS; gate 182/98; win32k `dispatch_loop` UNTOUCHED (migrates later).

## Step 3 — Family B fold → `run_once` (optional, do before win32k for confidence)
- [ ] `driver_host_entry` (`driver_host.rs:19-100`) + `kmdf_host_entry` (`kmdf_host.rs:766-779`) call
      `run_once(body, verdict_va)` (notify+park epilogue only; bodies stay bespoke).
- [ ] VERIFY specs: `exec_driver_host_drove_nic`, `exec_sys_driver_entry_ok`,
      `exec_sys_start_reached_real_nic`, `exec_kmdf_driver_create/_adddevice_queue/_prepare_hw_read_real_nic/`
      `_ioctl/_remove`, `exec_kmdf_read_real_nic`; gate 180/98.

## Step 4 — win32k LAST (capability-gate every specific)  — DONE (gate 183/98, paint 768/768)
- [x] 4a. `win32k_dispatch_wide` (`win32k_glue.rs`) is now a THIN caller wrapper: it fills the request
      (client_attach + SSN/args + wide-arg SH_REQ_A4../NARGS staging, exactly as before) then calls
      `component_pump(&ch)` with `caps = { all win32k flags true }`, `reply_cap = REPLY_W32_SLOT`,
      `client_pi = W32_CLIENT_PI`, `demand_cap=8192`, `kind=Syscall`. The fault loop's win32k specifics
      RELOCATED VERBATIM behind flags INSIDE `component_pump`: (f) foreign-frame sharing + internal-low
      zero-fill (behind `client_attach`), (g) int-0x2c assert-skip (behind `assert_skip`, `W32_ASSERT_LOG`
      + per-dispatch 4000 bound kept), (h) REPLY_W32 nested reply (behind `nested_reply_cap` — strictly
      gated, recv_full_r12/send_on_reply, NEVER collapsed into REPLY_MAIN), the WALL diag, backtrace.
      Forward arm `service_sec_image.rs` UNCHANGED.
- [x] 4b. `win32k_subsystem_entry` → `component_main(WIN32K_SHARED_VADDR, WIN32K_CODE_VA,
      DriverObjectSpec{size:0x200, size_field:336, ext:0x30, mj_table_off:MAX, pool:win32k pool},
      SH_REQ_STATUS(0x78), W32_DISPATCH_LABEL, win32k_dispatch, win32k_post_driver_entry)`. The SSN
      router + all per-dispatch pre/post (WindowListHead re-empty, BATCH-43 thread↔desktop re-assert,
      SSN_TEST_FAULT, NtUserInitialize event-register, post-init font/winsta seed, dispatch_ssn w/
      exact-arity transmute) live in the `win32k_dispatch` closure; `establish_client_and_dispatch` +
      `setup_dispatch_context` in `win32k_post_driver_entry` (establish→setup ordering preserved).
      Harness changes needed to fit win32k: `DriverObjectSpec` gained `size_field` (alloc 0x200 but
      Size=336), `pool` fn-ptr (win32k's OWN bump arena, not FSD's free-list), `mj_table_off` (win32k
      0x18 is SH_SSDT_BASE — must NOT be clobbered → MAX); `component_main` writes info-then-status so
      win32k's status@0x78==info@0x78 alias resolves to status. Skeleton's flag-gated branches were
      COMMENT-ONLY stubs — implemented them to reproduce `win32k_dispatch_wide` exactly.
- [x] VERIFY: gate 183/98, RUNEXIT=3, ZERO FAILs, `exec_win32k_desktop_painted` 768/768 @ 0x003a6ea5,
      `win32k_dispatch_fault_via_reply_cap` (SSN_TEST_FAULT nested-reply) PASS,
      `win32k_dispatch_loop_roundtrip` PASS, all FSD/npfs + `exec_fsd_on_shared_harness` PASS. NEW proof
      `exec_win32k_on_shared_harness` (HARNESS_SYSCALL_DISPATCHES=140 ≥4) PASS. Boot-serial diff vs
      `4a157f8` CLEAN: only 3 cosmetic diffs — 1 bring-up demand-fault timing shift (component_main's
      preamble zeroing pre-touches a page the old entry faulted lazily; same page, identical DriverEntry
      result) + 2 reported IPs shifted (refactored win32k dispatch code at new addresses). SSDT
      base/count(740), connect status, TEST_FAULT status all byte-identical.
- [x] Retired the dead bespoke win32k loop: `dispatch_loop`/`send_done`/`recv_req` deleted (replaced by
      `component_main` + `send_done_on`/`recv_req_on`); `win32k_dispatch_wide`'s inline fault loop gone.

## Step 4.5 — REUSABLE substrate for user-specified drivers  — DONE (gate 181/98, clean qemu_exit)
Requirement: users can specify drivers to run by-path; adding a driver = stage the .sys + declare a
class → runs on the SAME harness with ZERO bespoke code. Design: `docs/component-harness.md` §5.
Family-A IRP dispatch server is the DEFAULT driver path (Family B = test-lifecycle fixtures only).
NOTE (now HISTORICAL — superseded above): Steps 1/2 originally landed the `component_main`/`component_pump`
scaffolding but left them UNWIRED (the FSD still ran its bespoke `fsd_component_entry`/`dispatch_loop` +
inline executive pump). This has since been FIXED — the FSD (both instances) genuinely runs on the shared
harness now (gate 182/98; proven by `exec_fsd_on_shared_harness`, 96 IRP dispatches through
`component_pump`). Step 4.5 kept that
proven bespoke path and made it MULTI-INSTANCE — the substrate is now genuinely multi-driver regardless.
- [x] G1: `load_driver(fs,path,class)` routes `Fsd`/`Filter`/`Device` through the SAME IRP path (was
      `if class != Fsd { return None }`); gated by `caps_and_layout_for(class).dispatch_server` so only
      the GUI syscall server (win32k) is rejected. Class selects caps/policy, no per-driver branch.
- [x] Added `caps_and_layout_for(class) -> (HostCaps, wants_device_caps)` — the ONLY per-class code.
      Renamed `DriverClass::Subsystem` → `GuiSyscallServer` (win32k-only privileged class). Added `Filter`.
- [x] G2 (core enabler): de-singletoned the FSD path. Per-instance EXECUTIVE-side VA windows
      (`ExecVaWindow::for_instance`; instance 0 = fixed npfs VAs byte-identical, N≥1 = distinct high
      window at `FSD_EXEC_BASE`; PE relocated for the fixed component run VA via `load_pe_into`'s new
      `run_va`). `FSD_RIGHTS` → per-instance array. Replaced the `NPFS_*` atomics with a
      `[DriverInstance; MAX_DRIVER_INSTANCES]` table; `npfs_dispatch_irp` → thin wrapper over
      `dispatch_irp(instance, …)`.
- [x] G3: declarative `DRIVERS: &[DriverSpec{path,class}]` the boot iterates (npfs's rich data-plane
      specs stay inline; the list carries the 2nd driver). "User specifies drivers" surface.
- [x] Staged a 2nd GENUINE IRP driver by path: `IrpFsdTest.sys` (real PE, DriverEntry fills
      `MajorFunction[CREATE/READ/WRITE/DEVICE_CONTROL]`, handler sets STATUS_SUCCESS + Information=0x5A5A),
      emitted by `nt-driver-test-fixtures::irp_fsd_pe()`, staged via `make_image.sh` loop like the fixtures.
- [x] PROVED reuse: `exec_second_irp_driver_via_harness` — loads via `load_driver(path, Fsd)` + a
      `DriverSpec` ONLY (zero bespoke code): DriverEntry entered, MJ table built, OWN isolated PML4
      (distinct from npfs's + the executive's), IRP_MJ_CREATE round-trips status=0/info=0x5A5A through the
      shared `dispatch_irp` pump. Instance=1 confirmed in the boot log.
- [x] G4: unbound-import audit already in place (`fsd_export_addr` fails soft + logs) — the synthetic
      driver imports nothing, so no new exports needed.
- [x] VERIFY: gate 181/98 (180 + the new proof spec), ZERO FAILs, clean qemu_exit (RUNEXIT=3 sentinel).
      Canaries PASS: `exec_win32k_desktop_painted` 768/768, `npfs_isolated_vspace`,
      `exec_pipe_syscalls_routed_through_npfs`, `exec_npfs_flush_pending`, `exec_svc_rpc_listener_multiplex`.
      win32k dispatch path UNTOUCHED (only a 2-char doc-comment rename in win32k_subsystem.rs).

## Step 5 — retire duplicated bespoke loops
- [ ] Delete the now-dead inner loops (one commit each, guarded). Tail of Phase B.

## Uncertainties to confirm in-code before implementing
- [ ] `SH_REQ_KIND=0x38` free in BOTH frames? If not, key KIND off the descriptor (constant per
      component) instead — no component serves both KINDs today.
- [ ] Status offset 0x70 (FSD) vs 0x78 (win32k) — read by `caps.kind`, do NOT unify; confirm `SH_REQ_SEQ=0x80` shared.
- [ ] `establish_client_and_dispatch()` must run between DriverEntry and the FIRST `send_done` — preserve ordering.
- [ ] FSD init loop DEMAND_CAP=512 vs per-IRP guard=256 — make a `PumpChannel` field if they must differ.

---

# BATCH 35 — route the SCM per-connection RPC worker into the multiplex

## Review
- ROOT CAUSE of the stall: services' 2nd NtCreateThread (the per-connection worker, ssn 55)
  hit exec_handler's `(2..=4).contains → return 0xC000_009A` fallthrough → worker never spawned.
- BUILT the full dynamic-worker routing (SCM_WORKER_BADGE=15 + dedicated VAs + spawn_scm_worker_thread
  + recognizer + loop spawn + multiplex sub-select + mirror_ctx + NtResumeThread guard + terminate cell).
- BLOCKER: a running 3rd native hosted thread in services' VSpace faults at its trampoline VA
  (cr2=0, INDEPENDENT of VA window / transport / resume-timing; trampoline is byte-perfect + mapped
  with page_map_r=0). Needs a kernel gdb-stub on the worker TCB VSpace/CNode binding.
- GUARD: `const SCM_WORKER_ROUTE_ENABLED = false` (exec_handler.rs) — falls through to baseline
  0xC000_009A → clean quiesce. Gate 175 (≥174), clean qemu_exit, no regression, host green.
- Flip the const + resume=true once the trampoline fault is root-caused → round-trip fires.

---

# BATCH 34 — async ncacn_np server-completion edge + real paired server FCB

## Confirmed server wait model (boot34a.log evidence)
svc-listener (pi 3, badge 7) SSN sequence:
- #0 ssn=238 NtWaitForSingleObject(NtCurrentThread) — startup
- #1 ssn=37  NtCreateEvent → listen-completion event (handle 0x208/0x210)
- #2 ssn=88  NtFsControlFile(FSCTL_PIPE_LISTEN) FileHandle=0x200 Event=0x210 → PENDING (no client)
- #3 ssn=280 NtWaitForMultipleObjects([mgr_event, listen_event]) WaitAny → PARK
- #4 ssn=228 NtSetEvent(0x208), #5 ssn=280 re-park

Server FCB \ntsvcs IS created (real npfs, line 2724 `[nt-create-named-pipe] pi=3 leaf=\ntsvcs`).
Winlogon client connect got fid 0x0e802d50 (pairs by name in npfs prefix table).
=> The gap is the server's async FSCTL_PIPE_LISTEN completion + its Event signal on the client write.

## Part A — real paired server FCB (present; verify)
- [x] services NtCreateNamedPipeFile(\ntsvcs) → real npfs (pi 3)
- [x] winlogon NtOpenFile(\??\pipe\ntsvcs) → npfs IRP_MJ_CREATE client connect

## Part B — async FSCTL_PIPE_LISTEN completion → event signal (core)
- [ ] ExecNtHandler fields: pipe_listen_fid, pipe_listen_event_handle, pipe_listen_iosb_va
- [ ] NtFsControlFile pi3/4 FSCTL_PIPE_LISTEN(0x110008) PENDING → record async-listen, return PENDING, no IOSB
- [ ] main.rs PIPE_ASYNC_LISTEN static table + park/complete helpers
- [ ] peer WRITE → complete pending async listen: signal its Event obj idx via wait_wake_event_set
- [ ] server wakes → reads bind → bind_ack → re-drives winlogon read (batch 33 edge)

## Host tests
- [ ] nt-io-manager async-listen record + signal model tests
- [ ] nt-ntdll 168 green

## Verify
- [ ] cargo test both, build exec+kernel, boot foreground timeout 620
- [ ] server wakes? bind_ack? RROpenSCManagerW? gate >=171 clean qemu_exit

## Review — BATCH 34 DONE
- Part A confirmed: server FCB \ntsvcs is REAL npfs (pi 3); client connect pairs by name. Not the gap.
- Part B implemented: AsyncListen/AsyncListenTable (host-tested +6), NtFsControlFile arms pending
  async listen (event resolved in server's handle table + name-hash), client connect completes the
  matching-name listen + signals its event via wait_wake_event_set → server wakes.
- Load-bearing runaway fix: force FSCTL_PIPE_LISTEN=PENDING for pi 3/4 (was routing to npfs's state
  machine → SUCCESS → get_wait_array SetEvent → infinite create-instance runaway, 894 creates).
- Name-scoped completion: \ntsvcs connect never wakes \lsarpc/\samr (killed lsass co-runaway).
- Clean quiesce: SVC_LISTENER_TERMINATED + WINLOGON_SCM_PARKED → quiesce when listener exits.
- RESULT: server WAKES on winlogon connect, runs real rpcrt4 accept, spawns per-connection worker
  (NtCreateThread), re-arms, exits. Gate 174 (was 171), clean qemu_exit, host 70+168 green.
- NEXT WALL: the per-connection WORKER thread (svc-listener's NtCreateThread) is not routed into the
  multiplex → it never reads the bind / writes bind_ack. Batch 35 = route that worker (N-threads).
- Paint still 0/768 (after the SCM round-trip). No regression (same 5 pre-existing FAILs; +3 real
  terminate specs now PASS).

## Phase A — host-test backfill (DONE)
Backfilled meaningful HOST unit tests for under-covered subsystems from the recent arc. NO boot, NO
executive/rust-micro change (test-only additions in the crates). All three targeted crates green.
- **nt-io-manager 73 → 83** (+10): AsyncListenTable name-hash WILDCARD branches (stored `name_hash==0`
  matches any connect; query hash-0 matches first armed; first-of-same-name consumed once + re-arm is a
  new record); PipeWaiterTable `cancel_thread` clears `parked_on` + reopens slots (+ no-match no-op) +
  `drain_all` stable slot-order/lowest-free reuse; half-duplex OUTBOUND READ direction reject (only
  WRITE dir was covered); `dequeue(max=0)` no-drain; `enqueue` full-queue → 0 accepted; `transceive`
  propagates wrong-direction + disconnected write errors.
- **nt-ntdll 192 → 200** (+8): x64 SEH unwind opcodes that lacked coverage — `UWOP_SAVE_NONVOL_FAR`,
  `UWOP_SAVE_XMM128`, `UWOP_SAVE_XMM128_FAR`, `UWOP_PUSH_MACHFRAME` (terminates unwind, no retaddr pop;
  + error-code OpInfo=1 RSP adjust), and `UWOP_EPILOG`/`UWOP_SPARE_CODE` no-op slot-consumption; RTL
  string batch-32 edges — `create_unicode_string_from_asciiz` (no-NUL/leading-NUL/high-bit-widen) +
  `duplicate_unicode_string(false)` init-vs-create MaximumLength semantics.
- **nt-driver-test-fixtures 0 → 5** (+5): first host tests — `irp_fsd_pe()` well-formed PE + DriverEntry
  `lea`/MajorFunction[0,3,4,0xe] store shape + handler IoStatus.Status/Information(0x5A5A); `minimal_pe`
  headers; `pe_importing` walkable import descriptor/IAT/by-name; section characteristics; `build_pe`
  data-directory + SizeOfImage/Headers alignment.
- **NOT host-testable (documented, not gaps):**
  - `RtlQueryRegistryValues` REG_MULTI_SZ per-substring split + Context forwarding (batches 30/31): lives
    in `nt-ntdll-dll::on_target::dispatch_value`, `#[cfg(target_arch=x86_64)]`, raw-pointer + gs-relative
    PEB (inline asm) — target-gated + syscall/PEB-bound; the split is inline in the unsafe FFI fn with no
    extractable pure helper (refactoring it out is forbidden by the constraints).
  - Harness pure logic (`caps_and_layout_for`, `pts_for`, `HostCaps`, `DriverObjectSpec`,
    `HARNESS_*_DISPATCHES` selection): in `ntos-executive`, a `#![no_std] #![no_main]` seL4 binary with a
    custom target + its own workspace + zero host-test harness. `cargo test` cannot target it, and adding
    a test module is an executive src change (forbidden). Genuinely not host-testable here.

## Phase A — executive-tidy consolidation batch (DONE)
Four gate-verified tidy items on the executive (no rust-micro/src change; behavior-preserving). Gate
**183/98** green, RUNEXIT=3, `microtest sentinel`, `exec_win32k_desktop_painted` 768/768,
`exec_fsd_on_shared_harness` + `exec_win32k_on_shared_harness` PASS.
- [x] **1. Dual-path server modules — caller-graph.** VERDICT: all four SURT server-side modules
  (`server`/`cm_server`/`io_server`/`lpc_server`) are LIVE — each `*_entry` fn is passed by fn-ptr into
  `stand_up_service()` (main.rs:5144/5184/5205/5235) and exercised by the counted `exec_ob_*/exec_cm_*/
  exec_io_*/exec_lpc_*` specs. NOT dead duplicates → deleted nothing (kill-list §6 resolved).
- [x] **2. Annotate intentional future-wiring seams.** `#[allow(dead_code)]` + a one-line rationale on:
  `DriverClass::Filter`, `HostCaps::{usermode_callback,wide_arg_marshal}`, `ComponentDescriptor.caps`,
  `SpawnedComponent.cnode`, `Win32kPe.image_base`, `GrantedDevice.device` — all now stop warning +
  read as intentional (matching the pre-existing `DriverClass::Device` annotation).
- [x] **3. Gate grind-era verbose diagnostics behind `debug-trace` (OFF by default).** New cargo
  feature; `loader_trace_diag` fully `#[cfg]`-gated (no-op stubs when off); per-fault demand-map traces
  + the int-0x2c skip diagnostic guarded by `const DEBUG_TRACE = cfg!(feature="debug-trace")`. Milestone
  markers, spec PASS/FAIL, and the gate summary stay UNGATED (did not over-gate — verified in the boot
  serial). `build.sh` forwards args so `--features debug-trace` re-enables. Both feature states compile.
- [x] **4. Docs.** `docs/component-harness.md` header → IMPLEMENTED + a tight §6 consolidated-state note
  (unified harness, multi-driver substrate, isolated-vs-in-executive, diagnostics); `ntdll_plan.md`
  gained a one-line "consolidation complete" footer pointing at §6.
- [x] **5. Milestone-park consolidation — VERDICT: DOCUMENT, don't refactor.** Inventoried every park
  site + quiesce break-site in `service_sec_image.rs`. FINDING: the mechanism is ALREADY consolidated
  behind two helpers (`park_and_log!` crash parks; `mark_wait_parked!` wakeable waits) + two bitmasks
  (`crash_parked`/`wait_parked`). Every generic park routes through them. The residual ~7 direct-`break`
  quiesce sites are heterogeneous per-process steady-state predicates whose ordering is individually
  load-bearing — most critically the `LSA_RPC_SERVER_ACTIVE_SIGNALLED` guard that MUST hold winlogon in
  a WAKEABLE event-wait so lsass's SetEvent can wake it into `SwitchDesktop` → the
  `exec_win32k_desktop_painted` 768/768 paint. Collapsing these behind one predicate would risk exactly
  the quiesce-ordering / paint-timing regression the contract protects, for marginal tidiness. So:
  documented rather than refactored — added `docs/n-threads-multiplex.md` §1a (authoritative catalog:
  the two bitmasks, the two helpers, a table of all 8 park kinds, the special break-sites, and WHY not
  further unified) + a `★★ PARK + QUIESCE CONTRACT` anchor comment in the source pointing at it. Purely
  docs/comment — behaviour-preserving. Gate re-verified green.

## Desktop/logon-UI frontier — winlogon crosses the SAS message loop (2026-07-20, gate 184/98)
- [x] Diagnosed: winlogon was NOT reaching PostMessage/GetMessage — **InitializeSAS FAILED entirely**
  (`NtUserSetLogonNotifyWindow` returned FALSE → `ExitProcess(2)`). Root cause: `PsLookupProcessByProcessId`
  was an unbound `s_zero` stub → `co_IntRegisterLogonProcess` set `gpidLogon` from an uninitialized
  `*Process` → the logon-process access check `gpidLogon == PsGetCurrentProcessId()` failed.
- [x] FIX chain (executive-only; see `ntdll_plan.md` §B-RESOLVED): bind `PsLookupProcessByProcessId` +
  seed EPROCESS.UniqueProcessId@0xd0; back `Control\Nls\Language\Default` (real hive) + fix NtQueryValueKey
  BUFFER_OVERFLOW header fill; register `NtSetDefaultLocale` (224) no-op; seed THREADINFO
  `PostedMessagesListHead`@0x188 (NtUserPostMessage null-deref at cr2=8).
- [x] Result: winlogon posts WLX_WM_SAS + GetMessage RETRIEVES it (real win32k `co_IntGetPeekMessage`,
  status=1) + DispatchMessage + re-polls empty queue = steady state. New MESSAGE-LOOP MILESTONE PARK;
  counted spec `exec_winlogon_sas_message_pumped`. Gate 184/98, RUNEXIT=3, paint 768/768.
- [x] SUPERSEDED (re-diagnosed 2026-07-20): the SAS dispatch is CLIENT-SIDE (user32 `IntCallMessageProc`,
  message.c:1990 — NO syscall / NO KeUserModeCallback), NOT `NtUserDispatchMessage`. See below.

## Desktop/logon-UI frontier — win32k desktop-heap CLIENT-WINDOW mapping → SASWindowProc RUNS (2026-07-20, gate 185/98)
- [x] Diagnosed: `DispatchMessageW(WLX_WM_SAS)` runs `SASWindowProc` CLIENT-SIDE via
  `user32!IntCallMessageProc` (message.c:1990) — `ValidateHwnd(0x2002e)` → `DesktopPtrToUser` must resolve
  the SAS PWND out of win32k's heap into winlogon's client view. Our host mapped only a placeholder
  DESKTOPINFO → ValidateHwnd NULL → DispatchMessageW returned 0 → SASWindowProc never ran (invisible in trace).
- [x] KEY FINDING: our host allocates ALL window objects (PWND/CLS/handle-table) from the ONE USER heap
  (`WIN32K_HEAP_VADDR`, `s_rtl_allocate_heap` ignores the desktop-heap handle) — already RO-mapped into
  winlogon at `CSRSS_W32_SHARED_VA`. BUT the DESKTOP body + its DESKTOPINFO come from `pool_alloc`
  (`WIN32K_POOL_VADDR`) — a SEPARATE arena NOT mapped into clients. So two windows must be readable client-side.
- [x] REAL FIX (executive-only; win32k_subsystem.rs/service_sec_image.rs/win32k_glue.rs/main.rs):
  1. **RO-map win32k's POOL** into winlogon at `CSRSS_W32_POOL_VA=0x9900_0000` (`map_win32k_pool_into_csrss`)
     so the bound DESKTOPINFO (`pci->pDeskInfo`) is client-readable — the USER heap was already mapped.
  2. **Seed winlogon's TEB.Win32ClientInfo** (was forced to a placeholder each dispatch): `pDeskInfo` =
     `BOUND_DESK_PDESKINFO − pool_delta`, `Win32ThreadInfo` = dispatch `pti` (== window `head.pti`, so
     IntCallMessageProc's same-thread check passes), `ulClientDelta` = USER-heap delta (maps PWND/pcls/spwnd).
     win32k publishes DESKTOPINFO+pti server VAs via new shared-page fields `SH_SAS_DESKINFO/PTI` and sets the
     DESKTOPINFO's `pvDesktopBase/pvDesktopLimit` to bracket the whole USER heap (range check accepts any PWND).
  3. **WM_CREATE callback bridge persists the Session** into `WND.dwUserData` (WND+0x110): the synthetic
     KeUserModeCallback WINDOWPROC stub never ran the real WM_CREATE `SetWindowLongPtr(GWLP_USERDATA, Session)`,
     so client-side `GetWindowLongPtr` returned 0 → `DispatchSAS(NULL)` crash. The bridge now resolves HWND→PWND
     via the published `SH_SAS_AHELIST` (USER handle table, index=(hwnd&0xffff−0x20)>>1) and stores
     `CREATESTRUCT.lpCreateParams` (the Session) into the real PWND's dwUserData.
- [x] RESULT: `SASWindowProc` RUNS client-side (was proven mid-batch by the crash moving from user32
  DispatchMessageW → winlogon+0x55a0 = DispatchSAS). DispatchSAS at `STATE_INIT` sets
  `Session->LogonState = STATE_LOGGED_OFF (1)` + calls `WlxDisplaySASNotice`, then RETURNS to the message loop
  and re-parks cleanly. PROOF: the executive reads `Session->LogonState==1` (was 0) via winlogon's own heap
  mirror → new counted spec `exec_winlogon_sas_windowproc_ran`. Gate **185/98**, RUNEXIT=3, sentinel,
  paint 768/768, `exec_winlogon_sas_message_pumped` still PASS. Boot QUIESCES at the message-loop park.
- [x] DONE (gate **186/98**, RUNEXIT=3, sentinel, paint 768/768, executive-only, rust-micro clean, deterministic
  ×2): INJECTED the 2nd SAS (the CAD a headless host lacks) via the SAME real path winlogon used for SAS#1 —
  `win32k_dispatch(NtUserPostMessage 0x100e, SAS_HWND, WLX_WM_SAS 0x659, WLX_SAS_TYPE_CTRL_ALT_DEL 1, 0)` when
  `LogonState==STATE_LOGGED_OFF`. Evidence: PostMessage ret=1; winlogon's GetMessage retrieved
  `MSG{msg=0x659, wParam=1}` ret=1 (queue carries the SAS end-to-end). **winlogon's REAL `WlxLoggedOutSAS`
  RUNS at STATE_LOGGED_OFF** — PROVEN by msgina's `GUILoggedOutSAS` reopening `HKLM\...\Winlogon` (LegalNotice
  read): `WINLOGON_KEY_OPENED` went 2→3 after the SAS. (LogonState is unreliable here: DispatchSAS sets
  STATE_LOGGED_OFF_SAS=2 then DoGenericAction(NONE) resets to 1.) New counted spec
  `exec_winlogon_logged_out_sas`. Files: `win32k_subsystem.rs` (SH_SAS_HWND publish), `service_sec_image.rs`
  (inject + key-reopen detect), `main.rs` (statics + spec). Boot QUIESCES at the message-loop park.
- [x] DIALOG BATCH (gate **186/98 HELD**, RUNEXIT=3, sentinel, paint 768/768, crate-side only, rust-micro clean):
  built the REAL PE `.rsrc` resource walker behind ntdll `LdrFindResource_U`/`LdrFindResourceDirectory_U`/
  `LdrAccessResource` (were stubs → `STATUS_RESOURCE_DATA_NOT_FOUND`). Pure host-tested core
  `crates/nt-ntdll/src/rtl/pe_resource.rs` (faithful ntdll `find_entry`, +10 tests, nt-ntdll 216→226); DLL
  wrappers resolve the resource section + walk + return the mapped data entry. SCOPED to msgina via
  `image_export_name_is(dll_handle, "msgina")` so the proven boot path stays byte-identical (global enablement
  diverts winlogon's early user32/gdi32 cursor init into the win32k GDI blit cascade `NtGdiOpenDCW` wall =
  project_win32k_graphics, tracked separately). No regression; boot QUIESCES at the SAS message-loop park.
- [ ] NEXT FRONTIER (RE-DIAGNOSED — the wall is a PRE-resource blocker, not the stub): msgina's base
  (`0x82290000`) is NEVER queried for a resource — `FindResourceW(msgina, IDD_LOGON)` never fires (proven by
  on-target `int-0x2d` handle diagnostics: the only post-SAS `.rsrc` queries are winlogon.exe's OWN image
  `0x10000560000`). Yet `GUILoggedOutSAS`'s reg-read runs (WINLOGON_KEY_OPENED 2→3). So `GUILoggedOutSAS`
  reaches its LegalNotice `RegOpenKeyExW` (gui.c:1492) but NOT `WlxDialogBoxParam(hDllInstance=msgina,
  IDD_LOGON)` (gui.c:1527). DIAGNOSE-FIRST NEXT: trace winlogon's client-side run after the reg-read to find
  where `GUILoggedOutSAS` stops before the dialog call — check `pgContext->hDllInstance` (msgina `WlxInitialize`
  = msgina DllMain `hinstDLL`), the `LegalNotice` HeapFree path (gui.c:1521-1525), the client-side
  `WlxDialogBoxParam` WLX-dispatch fn-pointer. Once `FindResourceW(msgina, IDD_LOGON)` fires, the now-REAL
  walker returns the template → `DialogBoxParamW → NtUserCreateWindowEx(#32770)` + control creates.
