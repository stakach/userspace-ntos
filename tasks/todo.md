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
