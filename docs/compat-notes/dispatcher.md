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

## DPC queue (implemented, Milestone 10.2 — `nt-kernel-exec::dpc`)

- `DpcQueue` (spec §6.3): one DPC queue per Driver Host. A `KDPC` is opaque driver
  storage; the runtime keeps its metadata (routine, deferred context, queued state,
  importance) in a side table keyed by the driver's `KDPC` pointer.
  - `initialize` = `KeInitializeDpc`; `insert` = `KeInsertQueueDpc` (returns `false`
    if already queued — queued-once); `remove` = `KeRemoveQueueDpc`;
    `set_importance` / `set_target_processor`.
  - `drain(irql, invoker, budget)` runs queued DPCs (highest importance first, then
    FIFO) each at `DISPATCH_LEVEL` via a `DriverCallbackInvoker`
    (`Routine(Dpc, DeferredContext, Arg1, Arg2)`), copying the metadata + marking
    the DPC unqueued **before** calling (spec §17: no runtime borrow across the
    driver callback). The `budget` bounds work so a hostile driver can't livelock
    (spec §7.3). `KeFlushQueuedDpcs` = unbounded drain.
- `DriverCallbackInvoker` (spec §7.2): calls DPC / work-item routines (driver
  function pointers). Host tests use a recording mock; the real Driver Host impl
  makes a Microsoft-x64 call. 3 tests (§14.3: insert-once, importance ordering,
  budget).

## Timers + fake clock (implemented, Milestone 10.3 — `nt-kernel-exec::timer`)

- `TimerQueue` (spec §6.4): a `KTIMER` keyed by the driver's pointer.
  `initialize` = `KeInitializeTimer[Ex]`; `set` = `KeSetTimer[Ex]` (100ns
  `LARGE_INTEGER` due time — negative relative / non-negative absolute; `period_ms`
  0 = one-shot); `cancel` = `KeCancelTimer`; `read_state` = `KeReadStateTimer`.
  `run_due(clock)` expires due timers (sets signaled, reschedules periodic ones) and
  returns the associated `KDPC` pointers to queue. Resetting bumps a per-timer
  generation, invalidating the old due time (spec §6.4).
- `Clock` trait + a deterministic `FakeClock` (`advance_100ns`/`advance_ms`/
  `set_system_time`) for reproducible tests (spec §10.3). 5 tests (§14.4: relative +
  absolute fire, reset invalidates old expiry, periodic requeue, cancel).
