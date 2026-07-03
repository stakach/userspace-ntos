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

## Events + waits (implemented, Milestone 10.4 — `nt-kernel-exec::event`)

- `EventStore` (spec §6.5): a `KEVENT` keyed by the driver's pointer, with
  `Notification` (manual-reset) + `Synchronization` (auto-reset) kinds. `initialize`
  = `KeInitializeEvent`; `set` = `KeSetEvent` (returns previous state); `reset` =
  `KeResetEvent`; `clear` = `KeClearEvent`; `read_state` = `KeReadStateEvent`.
- `poll(ptr, irql)` = the `KeWaitForSingleObject` core: a signaled event succeeds
  (auto-resetting a Synchronization event); otherwise times out. Waiting above
  `APC_LEVEL` fails (`WaitResult::BadIrql`, spec §6.1). Blocking waits integrate at
  the runtime level (advance clock / drain, re-poll). 4 tests (§14.5).

## Work items (implemented, Milestone 10.5 — `nt-kernel-exec::work_item`)

- `WorkQueue` (spec §6.6): work-item callbacks run at `PASSIVE_LEVEL` (unlike DPCs).
  Two flavours:
  - `IO_WORKITEM`: `allocate` = `IoAllocateWorkItem(DeviceObject)` (returns an opaque
    handle tied to the device), `queue_io` = `IoQueueWorkItem` (queued-once), `free`
    = `IoFreeWorkItem`. Drained via `call_work_item(Routine, DeviceObject, Context)`.
  - `WORK_QUEUE_ITEM`: `initialize_ex` = `ExInitializeWorkItem`, `queue_ex` =
    `ExQueueWorkItem`. Drained via `call_ex_work_item(Routine, Parameter)`.
  - `drain(irql, invoker, budget)` runs queued items at `PASSIVE_LEVEL`, copying
    metadata + marking unqueued before the callback (a callback may `IoFreeWorkItem`
    itself). 3 tests (§14.6). 23 `nt-kernel-exec` unit tests total.

## Runtime + drain hooks (implemented — `nt-kernel-exec::runtime`)

- `KernelExecRuntime<C: Clock>` (spec §7.1) ties together IRQL, spin locks, the DPC
  queue, timers, events, and work items over a clock source, exposing each
  sub-store plus `set_timer` (against its clock).
- `drain_ready(invoker, budget)` (spec §7.3): expire due timers → their DPCs onto
  the DPC queue → run queued DPCs (DISPATCH) + work items (PASSIVE) until quiescent
  or `budget` callbacks run. `budget` bounds a driver that re-queues work forever.
  `on_after_driver_dispatch` / `on_before_block` are the event-loop drain points.
- 27 `nt-kernel-exec` unit tests: DPC drains at DISPATCH, timer→DPC, work at PASSIVE,
  budget cap.

## AsyncTest.sys in QEMU (implemented, Milestone 10.6 — `driver-host-async`)

The `driver-host-async` seL4 component loads the real MSVC-built `AsyncTest.sys`
(W^X + NX), runs `DriverEntry`, and drives the three asynchronous completion paths.
Each `DeviceIoControl` marks the IRP pending, queues deferred work, and returns
`STATUS_PENDING`; the Driver Host then advances its clock (for timers) and drains
the `nt-kernel-exec` runtime, running the deferred callback which completes the IRP:

- `IOCTL_ASYNC_COMPLETE_VIA_DPC` → a KDPC runs at `DISPATCH_LEVEL`, completes "DPC!".
- `IOCTL_ASYNC_COMPLETE_VIA_TIMER` → a KTIMER fires → its KDPC completes "TMR!".
- `IOCTL_ASYNC_COMPLETE_VIA_WORKITEM` → an IO_WORKITEM runs at `PASSIVE_LEVEL`,
  completes "WKI!".

The component adds the compat exports the driver imports (KeInitializeDpc/
KeInsertQueueDpc, KeInitializeTimer/KeSetTimer, KeInitialize/Set/ClearEvent,
KeWaitForSingleObject, ExAllocate/FreePoolWithTag, IoAllocate/Queue/FreeWorkItem,
IoCreateDevice with a device extension). Driver callbacks run via a win64 gate with
**no runtime borrow held** across the call (`take_ready`/`finish_callback`, spec §17),
so the callback can re-enter the runtime. Verified in QEMU: all async paths complete
with the correct value + IRQL (bad-IRQL count 0, spec §20 quality gate).

## Simulated interrupt bridge (implemented, Milestone 10.7 — `nt-kernel-exec::interrupt`)

- `InterruptTable` (spec §11): a `KINTERRUPT` keyed by the driver's pointer.
  `connect` = `IoConnectInterrupt[Ex]` (ISR `KSERVICE_ROUTINE`, service context,
  vector, synthetic DIRQL); `disconnect` = `IoDisconnectInterrupt[Ex]`;
  `find_vector` resolves the ISR bound to a vector.
- `KernelExecRuntime::inject_interrupt(vector)` runs the spec §11 simulated flow:
  raise to the synthetic DIRQL and return the ISR (`ReadyIsr`). The Driver Host runs
  the `KSERVICE_ROUTINE` (no runtime borrow held, §17) — the top half typically
  queues a DPC bottom-half — then `finish_isr` lowers the IRQL and the DPC queue
  drains at `DISPATCH_LEVEL`. Real seL4 IRQ notifications arrive in the later
  HAL/device-resource milestone. 2 tests (connect/find/disconnect; ISR→DPC bottom
  half). 29 `nt-kernel-exec` unit tests total.

## Deferred IRP completion — exactly-once + cancellation (implemented — `nt-kernel-exec::completion`)

- `CompletionTracker` (spec §7.7, §12) tracks the Driver Host's local projected IRP
  pointers (the I/O Manager stays the canonical owner). State machine
  `Pending → {Completed | Cancelled}`, both terminal:
  - `mark_pending` = `IoMarkIrpPending` (records `request_id` for the I/O Manager).
  - `complete` = `IoCompleteRequest` — completes **exactly once**; a second
    completion, or one racing a prior cancel, returns `AlreadyFinal` and is dropped.
  - `cancel` — conservative; wins only while pending, loses to a published
    completion (`TooLate`). The four §12 race cases are unit-tested.
- Wired into `KernelExecRuntime` (`mark_irp_pending`/`complete_irp`/`cancel_irp`).
  `driver-host-async` routes the real driver's `IofCompleteRequest` through the
  guard, so the three async completions are exactly-once-checked; verified in QEMU
  (`no_valid_completion_dropped`, `double_complete_rejected`,
  `cancel_prevents_double_complete`). Closes the spec §20 gates "pending IRP
  completes exactly once" + "cancellation cannot double-complete". 34 unit tests.
