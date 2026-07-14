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
