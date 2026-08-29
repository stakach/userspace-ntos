# NT Power Manager — compatibility notes

The minimal WDM power lifecycle (spec: NT Power Manager, Milestone 13). Test driver:
`PowerPnpMmioTest.sys` — extends `PnpMmioInterruptTest` with `IRP_MJ_POWER` dispatch;
SET_POWER D3 marks `Powered=0` + cancels the pending wait, D0 marks `Powered=1`;
IOCTLs + interrupt delivery are gated on `Powered`.

## Power types + ABI (implemented, Milestone 13.1 — `nt-power-types`, `nt-power-abi`)

- `nt-power-types`: `SystemPowerState` (Working=1 … Shutdown=6) + `DevicePowerState`
  (D0=1 … D3=4), both `#[repr(u32)]`; `IRP_MJ_POWER`=0x16, minors (WAIT_WAKE=0,
  POWER_SEQUENCE=1, SET_POWER=2, QUERY_POWER=3); the `Parameters.Power` stack layout
  (`Type`@16, `State`@24 within an `IO_STACK_LOCATION`); `STATUS_DEVICE_POWERED_OFF`.
  `DevicePowerState::is_on()` is true only for D0. The crate also owns the exact NT5
  execution-state flags and distinguishes the native accepted mask
  (`ES_SYSTEM_REQUIRED | ES_DISPLAY_REQUIRED | ES_CONTINUOUS`) from the internal
  `ES_USER_PRESENT` flag.
- `nt-power-abi`: opcodes `POWER_OP_*` (0x7000..=0x70ff); `#[repr(C)]`
  `PowerStateWire`, `PowerSetDeviceReq`, `PowerRegisterDeviceReq`. Responses use
  `detail0` = old state, `detail1` = new state. 6 layout tests.

## Power Manager core (implemented, Milestone 13.2 — `nt-power-manager`)

- `PowerManager`: growable per-devnode power records; no driver pointers, only IDs +
  states. `prepare_device` creates a non-queryable record before `AddDevice` so a
  driver's initial `PoSetPowerState` report is retained. `complete_start` makes that
  exact record queryable after successful `IRP_MN_START_DEVICE`, preserving a reported
  initial state and otherwise initializing it to D0/Working. `unregister_device` removes
  the record on teardown; `mark_remove` rejects new transitions (§11.3).
- `report_device_state` and `report_system_state` update only the addressed devnode and
  return its previous state. Invalid or absent records fail explicitly; one device can
  never overwrite another device's state.
- Per-thread execution-state records are keyed by dynamic thread ID. Continuous requests
  replace only the current thread's persistent system/display assertions and update
  aggregate reference counts. Noncontinuous requests are one-shot pulses and do not
  overwrite that record. Thread rundown removes the exact record and releases only its
  assertions; repeated rundown is idempotent. Activity generations expose real policy
  transitions without storing a process/image-specific summary.
- Process wakeup-latency records are keyed by dynamic process ID. `LT_LOWEST_LATENCY`
  contributes one idempotent process reference to the aggregate low-latency attribute;
  `LT_DONT_CARE` and process rundown remove only that process's reference. The resulting
  policy constrains a deeper normal sleep maximum to the configured reduced-latency state
  without deepening an already stricter policy.
- `begin_device_transition(devnode, target)` validates the devnode is registered, not
  removing, and has no power IRP in flight (one-in-flight, §16.1) — else
  `NotRegistered`/`Removed`/`Busy`/`InvalidState` — and marks it in-flight, returning
  the old state. `complete_device_transition(devnode, target, success)` moves to
  `target` on success or preserves the old state on failure (§9.4), always clearing
  in-flight. `is_on` is true only for a started device in D0 (§8.1 I/O + interrupt
  gating). Nine device-lifecycle tests cover prepared/start lifecycle, AddDevice report
  preservation, independent per-devnode reporting, D0→D3→D0, one-in-flight,
  transition failure, removal, invalid states, and stale devnodes. Three execution-state
  tests cover independent thread assertions, pulse behavior, and exact thread rundown. Two
  wakeup-latency tests cover process ownership, aggregate accounting, exact rundown, and the
  effective sleep-policy constraint.

## Po exports + full lifecycle in QEMU (implemented, Milestones 13.3-13.7 — `driver-host-power`)

- Po exports: `PoCallDriver` = `IoCallDriver` (the PDO completes a forwarded power
  IRP with success, non-pending so the driver's synchronous forward proceeds);
  `PoStartNextPowerIrp` a no-op with a call count (spec §14.3); `PoSetPowerState`
  resolves the exact FDO/PDO binding, updates that devnode's reported system or device
  state, and returns the previous state. During `AddDevice`, a bounded call context
  validates the new device object's provider and associates its report with the PDO
  being prepared; there is no global device-state fallback.
- Native `NtGetDevicePowerState` (SSN 90) validates the process-local file handle and
  resolves its live I/O Manager route to the related hosted PDO. It returns only the
  authoritative state of a successfully started devnode. Non-device files, stale
  handles, unstarted devices, and absent bindings fail explicitly.
- Native `NtSetThreadExecutionState` (SSN 252) validates the exact NT5 flag mask, probes
  the aligned previous-state output, resolves the current dynamic thread, and mutates the
  same focused Power Manager authority. It returns the thread's prior persistent flags
  with `ES_CONTINUOUS`, implements one-shot pulse semantics, and relies on common thread
  teardown for assertion rundown. The executive owns no parallel execution-state cache.
- Native `NtRequestWakeupLatency` (SSN 209) accepts only the NT5 `LATENCY_TIME` values,
  resolves the current live process dynamically, and mutates that same Power Manager.
  Repeated requests are idempotent and common process teardown releases the exact process
  contribution. No image-specific policy or executive-side scalar cache exists.
- **`Parameters.Power` layout (discovered)**: the `Power` fields are `POINTER_ALIGNMENT`
  8-byte slots (same as `DeviceIoControl`): `Type`@**16**, `State`@**24** within the
  `IO_STACK_LOCATION` — *not* 12/16 (packed) as a naive reading suggests.
- Power IRP dispatch: `IRP_MJ_POWER`=0x16, `IRP_MN_QUERY_POWER`=3, `IRP_MN_SET_POWER`=2.
  A device transition = Power-Manager `begin` (one-in-flight) → QUERY (fail aborts) →
  SET → `complete`.
- HAL power gating (§12.1): `inject_interrupt` drops the interrupt (ISR not called)
  while not D0.
- Verified in QEMU (20/20) with the real `PowerPnpMmioTest.sys`: START→D0 registered →
  IOCTL works → SET_POWER D3 (Powered=0, IOCTL rejected, interrupt dropped) →
  SET_POWER D0 (resumes, pended IOCTL completed by injected interrupt) → REMOVE
  (resources revoked, power record unregistered). No callback at the wrong IRQL.
