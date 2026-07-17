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
