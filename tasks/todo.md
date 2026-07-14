# npfs C2 + N-threads fault-multiplex

Baseline: main @ 5f64609, gate 159/96, paint 768/768 @ 0x003a6ea5, exit 3.
Walls: (1) npfs IRP CREATE_NAMED_PIPE faults addr=0xffffffe1 (bad SecurityContext/Parameters + no real prefix tree).
       (2) services rpcrt4 NULL deref addr=0x2c8 rip=0x83025f62 after 55(thread)+162 — RPC listener path.

## Part 1 — npfs VCB internals real (C-a)
- [ ] Real prefix-tree trampolines (Init/Insert/Find) backed by a host-side name->entry map.
- [ ] Real generic-table + ERESOURCE (uncontended) trampolines.
- [ ] Tolerant Se*/Ob* security trampolines.
- [ ] run_irp builds valid IO_STACK_LOCATION CreatePipe block (SecurityContext+AccessState, Options, Parameters).
- [ ] npfs NpFsdCreateNamedPipe completes -> real FILE_OBJECT with FsContext set.

## Part 2 — route LIVE pipe syscalls through npfs (C-b)
- [ ] NtCreateNamedPipeFile(46)/NtCreateFile/NtOpenFile(pipe)/NtFsControlFile/Read/Write -> npfs_dispatch_irp (pi==3).

## Part 3 — N-threads fault-multiplex (C-c)
- [ ] Sub-select thread by faulting SP range; per-thread stack-mirror+TEB switch.
- [ ] Resume RPC listener; route its faults into the main multiplex. Keep waits IMMEDIATE.
- [ ] Target: rpcrt4 past 0x2c8 -> SCM RPC server live.

## Review
(to fill)

## Review (COMPLETE)
- C-a DONE (161/96): npfs VCB internals real — NpFsdCreateNamedPipe + NpFsdCreate complete via real
  prefix-tree/ERESOURCE/security + memcpy/memset trampolines + valid CreatePipe IO_STACK_LOCATION.
  Create-then-connect proven (real FCB found by name). Key bug: unbound memcpy no-op'd RtlCopyMemory
  → corrupt FCB names. Key offset fix: ShareAccess@iosl+0x1a, Parameters@iosl+0x20 (POINTER_ALIGNMENT).
- C-b DONE (162/96): live pipe syscalls (NtCreateNamedPipeFile/NtOpenFile/NtFsControlFile, pi==3)
  routed through npfs_dispatch_irp. NPFS_ROUTED_IRPS>=1 proven. pi 0-2 byte-identical.
- C-c DONE (163/96): N-threads-per-process fault-multiplex. services' RPC listener = a real seL4
  thread spawned+RESUMED into the main loop with badge SVC_LISTENER_BADGE(7); loop sub-selects it to
  (pi 3, listener) → its own stack mirror/TEB. Proven live: SSN ring shows `6:55 7:238` (main creates
  listener, listener runs). Listener parks on its own wall (rpcrt4 needs a real client connect); boot
  CONTINUES to winlogon StartLsass. rpcrt4 PAST 0x2c8 → SCM RPC server live.
- Paint 768/768 @ 0x003a6ea5 intact throughout; NO rust-micro/src change → sel4test byte-identical.
- Next frontier: winlogon StartLsass → lsass as pi 4 (the multiplex + reply-cap-parking waits arc).
