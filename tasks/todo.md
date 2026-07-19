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

## Step 0 — ABI scaffolding, wired to nothing (pure additive)
- [ ] Add `HostCaps` + `ReqKind` + `SH_REQ_KIND`(verify 0x38 free in both frames) to a shared const block.
- [ ] Add `caps: HostCaps` field to `ComponentDescriptor` (`spawn_hosts.rs:88`); `HostCaps::default()` at
      all 6 descriptor sites (2 in `spawn_hosts.rs`, driver-host + kmdf inlined in `main.rs:6618/6708`,
      fsd `driver_launch.rs`, win32k builder).
- [ ] Define `component_pump`, `component_main`, `run_once` — CALLED FROM NOWHERE yet.
- [ ] VERIFY: gate 180/98 (byte-identical; no call sites touched).

## Step 1 — FSD executive pump → `component_pump`
- [ ] Re-express `npfs_dispatch_irp` inner loop (`driver_launch.rs:1584-1654`) as a `component_pump`
      call, `caps = { dispatch_server, kind: Irp }`. Request-fill stays in `npfs_dispatch_irp`.
- [ ] Migrate the FSD init-time fault loop (`load_driver:1402-1455`) too (same shape).
- [ ] VERIFY specs: `npfs_isolated_vspace`, `npfs_dispatch_roundtrip`, `npfs_create_named_pipe_complete`,
      `npfs_client_connect_finds_fcb`, `npfs_set_pipe_information`,
      `exec_pipe_syscalls_routed_through_npfs`, `exec_pipe_data_plane_*`, `exec_npfs_flush_pending`;
      gate 180/98.

## Step 2 — FSD component entry → `component_main`
- [ ] `fsd_component_entry` (`driver_launch.rs:785-852`) → `component_main` with IRP dispatch closure
      (`major → run_irp`), `post_driver_entry = no-op`, `DriverObjectSpec{size:0x150, ext:0x68}`.
- [ ] Hoist `send_done`/`recv_req` into the harness (parameterised by `dispatch_label`).
- [ ] VERIFY: same npfs spec set; gate 180/98.

## Step 3 — Family B fold → `run_once` (optional, do before win32k for confidence)
- [ ] `driver_host_entry` (`driver_host.rs:19-100`) + `kmdf_host_entry` (`kmdf_host.rs:766-779`) call
      `run_once(body, verdict_va)` (notify+park epilogue only; bodies stay bespoke).
- [ ] VERIFY specs: `exec_driver_host_drove_nic`, `exec_sys_driver_entry_ok`,
      `exec_sys_start_reached_real_nic`, `exec_kmdf_driver_create/_adddevice_queue/_prepare_hw_read_real_nic/`
      `_ioctl/_remove`, `exec_kmdf_read_real_nic`; gate 180/98.

## Step 4 — win32k LAST (capability-gate every specific)
- [ ] 4a. `win32k_dispatch_wide` (`win32k_glue.rs:388-614`) loop → `component_pump`, `caps = { all win32k
      flags true }`, `reply_cap = REPLY_W32_SLOT`, `client_pi = W32_CLIENT_PI`. Relocate VERBATIM behind
      flags: (c) client-attach, (e) wide-arg staging, (f) foreign-frame sharing, (g) int-0x2c skip,
      (h) REPLY_W32 nesting. Keep the forward arm `service_sec_image.rs:3120-3122`.
- [ ] 4b. `win32k_subsystem_entry` (`win32k_subsystem.rs:2662-2717`) → `component_main`, SSN dispatch
      closure (`ssn → dispatch_ssn`, retains exact-arity transmute (e)),
      `post_driver_entry = establish_client_and_dispatch`, `DriverObjectSpec{size:0x200, ext:0x30}`.
- [ ] VERIFY (CRITICAL): `exec_win32k_desktop_painted` == 768/768 @ 0x003a6ea5 (`main.rs:8048`);
      `SSN_TEST_FAULT` nested-reply round-trip; win32k connect specs; gate 180/98. Diff boot serial
      `[w32disp]`/`[w32attach]` lines vs a pre-migration reference boot (byte-identical dispatch).
- [ ] Rollback 4a/4b independently if any regression.

## Step 4.5 — REUSABLE substrate for user-specified drivers (do AFTER Step 2; around/independent of Step 4)
Requirement: users can specify drivers to run by-path; adding a driver = stage the .sys + declare a
class → runs on the SAME harness with ZERO bespoke code. Design: `docs/component-harness.md` §5.
Family-A IRP dispatch server is the DEFAULT driver path (Family B = test-lifecycle fixtures only).
- [ ] G1: make `load_driver(fs,path,class)` (`driver_launch.rs:1330`) route `Fsd` AND `Device`/`Filter`
      through the SAME `component_main`/`component_pump` (`:1335-1338` currently returns None for
      non-Fsd). Class only changes caps/regions.
- [ ] Add `caps_and_layout_for(class) -> (HostCaps, GrantedCapsPolicy, &[Region])` — the ONLY per-class
      code; no per-driver branch. Rename `DriverClass::Subsystem` → `GuiSyscallServer` (win32k-only,
      unique privileged class; its caps NEVER set for a normal user driver). Add `Filter`.
- [ ] G2 (core enabler): de-singleton the FSD path so N IRP drivers coexist. Parameterise per-instance
      VA windows (currently fixed `FSD_CODE_VA:54`, `FSD_POOL/DATA/SHARED/ARG/STACK_VADDR`), replace the
      single `FSD_RIGHTS:1319` / `FSD_EXPORTS:668` / `NPFS_PML4/FAULT_EP/MJ_TABLE/DEVOBJ:1546-1550`
      atomics with a small `[DriverComponent; N]` instance table; `npfs_dispatch_irp` → `dispatch_irp(instance,…)`.
- [ ] G3: add a declarative `DRIVERS: &[DriverSpec{path,class}]` list the boot iterates (currently ONE
      hardcoded call site `main.rs:7165`). This is the "user specifies drivers" surface (registry
      `\Services` / boot-arg population is a later increment; static list proves reuse).
- [ ] Stage a 2nd synthetic IRP driver by path (add to `rust-micro/scripts/make_image.sh:159` loop like
      the fixtures) that registers `IRP_MJ_CREATE`/`IRP_MJ_DEVICE_CONTROL`.
- [ ] PROVE reuse: new spec `exec_second_irp_driver_via_harness` — the 2nd driver loads via
      `load_driver(path, Fsd)` + a `DriverSpec` ONLY (zero bespoke executive code), enters DriverEntry,
      builds its MajorFunction table in its OWN isolated VSpace (PML4 != npfs), and round-trips one IRP
      through `component_pump`. Exercises G1+G2+G3.
- [ ] G4 (note, not a code change): a new driver importing an unbound ntoskrnl API fails soft + audits
      (`fsd_export_addr:745-774`) — implement the missing export per the standing backlog; expected, not a hang.
- [ ] VERIFY: full gate stays 180/98 + the new spec passes; win32k-last order UNCHANGED.

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
