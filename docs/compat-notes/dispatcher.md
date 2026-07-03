# NT Dispatcher / DPC / Timer / Work-Item — compatibility notes

The local NT kernel execution runtime (`nt-kernel-exec`) a Driver Host provides to
a loaded driver — IRQL, spin locks, DPCs, timers, events, work items — enabling
deferred / asynchronous IRP completion (spec: Milestone 10). See
`references/nt-dispatcher-dpc-timer-spec.md`.

## IRQL + spin locks (implemented, Milestone 10.1 — `nt-kernel-exec`)

- `IrqlState` (spec §6.1): a single-threaded per-Driver-Host IRQL —
  `PASSIVE_LEVEL`/`APC_LEVEL`/`DISPATCH_LEVEL`. `raise` may only raise (returns the
  old level), `lower` may only lower; an invalid transition is rejected + counted.
  `can_wait()` is false above `APC_LEVEL` (§6.1: waiting at/above `DISPATCH` fails).
  `with_irql(new, f)` runs a callback at a raised level + restores it — the DPC
  invocation shape (§17).
- `SpinLockTable` (spec §6.2): `KSPIN_LOCK` state keyed by the driver's lock
  pointer. `acquire` raises to `DISPATCH_LEVEL` + returns the old IRQL;
  `release(old_irql)` restores it. The `AtDpcLevel` variants require the current
  IRQL be `>= DISPATCH_LEVEL`; `try_acquire_at_dpc` returns whether it was taken.
  Double-acquire / release-without-acquire are rejected (`SpinError`).
- 8 unit tests (§14.1/§14.2). Host-only library — the SurtTest driver is unaffected.
