# NT Power Manager — compatibility notes

The minimal WDM power lifecycle (spec: NT Power Manager, Milestone 13). Test driver:
`PowerPnpMmioTest.sys` — extends `PnpMmioInterruptTest` with `IRP_MJ_POWER` dispatch;
SET_POWER D3 marks `Powered=0` + cancels the pending wait, D0 marks `Powered=1`;
IOCTLs + interrupt delivery are gated on `Powered`.

## Power types + ABI (implemented, Milestone 13.1 — `nt-power-types`, `nt-power-abi`)

- `nt-power-types`: `SystemPowerState` (Working=1 … Shutdown=6) + `DevicePowerState`
  (D0=1 … D3=4), both `#[repr(u32)]`; `IRP_MJ_POWER`=0x16, minors (WAIT_WAKE=0,
  POWER_SEQUENCE=1, SET_POWER=2, QUERY_POWER=3); the `Parameters.Power` stack layout
  (`Type`@12, `State`@16 within an `IO_STACK_LOCATION`); `STATUS_DEVICE_POWERED_OFF`.
  `DevicePowerState::is_on()` is true only for D0.
- `nt-power-abi`: opcodes `POWER_OP_*` (0x7000..=0x70ff); `#[repr(C)]`
  `PowerStateWire`, `PowerSetDeviceReq`, `PowerRegisterDeviceReq`. Responses use
  `detail0` = old state, `detail1` = new state. 6 layout tests.

## Power Manager core (implemented, Milestone 13.2 — `nt-power-manager`)

- `PowerManager`: per-devnode power records; no driver pointers, only IDs + states.
  `register_device` (D0 at Working on START), `unregister_device` (on REMOVE),
  `mark_remove` (rejects new transitions, §11.3).
- `begin_device_transition(devnode, target)` validates the devnode is registered, not
  removing, and has no power IRP in flight (one-in-flight, §16.1) — else
  `NotRegistered`/`Removed`/`Busy`/`InvalidState` — and marks it in-flight, returning
  the old state. `complete_device_transition(devnode, target, success)` moves to
  `target` on success or preserves the old state on failure (§9.4), always clearing
  in-flight. `is_on` is true only in D0 (§8.1 I/O + interrupt gating). 6 unit tests
  (register→D0, D0→D3→D0, one-in-flight, set-failure-preserves-old, no-transition-
  after-remove, stale-devnode).
