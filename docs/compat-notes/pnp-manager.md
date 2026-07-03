# NT PnP Manager — compatibility notes

The minimal AddDevice / StartDevice device lifecycle (spec: NT PnP Manager,
Milestone 12). Test driver: `PnpMmioInterruptTest.sys` — no hard-coded resources;
`DriverEntry` sets `DriverExtension->AddDevice` (@48→@8) + `MajorFunction[IRP_MJ_PNP]`;
`AddDevice` creates an FDO + `IoAttachDeviceToDeviceStack`; `IRP_MN_START_DEVICE`
forwards down (`IofCallDriver`), parses the translated `CM_RESOURCE_LIST`, then maps
MMIO + connects the interrupt; `IRP_MN_REMOVE_DEVICE` disconnects/unmaps/detaches.

## PnP ABI (implemented, Milestone 12.2 — `nt-pnp-abi`)

- `no_std`, no alloc/seL4/pointers. Opcodes `PNP_OP_*` (0x6000..=0x60ff), PnP IRP
  constants (`IRP_MJ_PNP`=0x1b; `IRP_MN_START_DEVICE`=0, `QUERY_REMOVE`=1, `REMOVE`=2,
  `STOP`=4, `QUERY_STOP`=5).
- `DeviceState` (`#[repr(u32)]`, spec §8.1): the 14-state devnode machine
  (Uninitialized → … → Started → … → Removed / Failed).
- `#[repr(C)]` `PnpDevnodeReq` / `PnpLifecycleReq` / `PnpDevnodeInfo`. 4 layout tests.

## PnP Manager core (implemented, Milestone 12.3 — `nt-pnp-manager`)

- `PnpManager`: a devnode table over static fixtures; no driver pointers, only IDs +
  resource values. `create_mmio_fixture_devnode` enumerates the `MmioInterruptTest`
  fixture (memory `0x1000_0000`/`0x1000`, interrupt vector 5) in state `Enumerated`.
- `can_transition(from, to)` encodes the §8.2 state machine; `transition` validates
  it (invalid → `InvalidTransition`) and rejects a `Removed` devnode (`StaleId`). No
  `START` before AddDevice; no duplicate `START` without a Stop; `Failed` from any
  active state.
- `mapping_allowed(id)` is true only in `Started` (spec §15.2 resource gating);
  `is_live` false after `Removed`. `set_fdo`/`set_driver`/`resources`/`pdo`/`fdo`
  accessors. 5 unit tests (fixture, full start lifecycle, invalid transitions, no
  duplicate start, remove-then-stale).

## Full lifecycle in QEMU (implemented, Milestones 12.4-12.8 — `driver-host-pnp`)

The `driver-host-pnp` component orchestrates the real `PnpMmioInterruptTest.sys`
lifecycle against an in-process HAL + PnP Manager. Verified in QEMU (17/17):
DriverEntry sets AddDevice + PnP dispatch → PnP Manager enumerates the fixture devnode
+ creates the PDO → AddDevice builds the FDO→PDO stack → an IOCTL before START fails
`STATUS_DEVICE_NOT_READY` → START_DEVICE delivers a translated CM_RESOURCE_LIST; the
driver parses it, maps MMIO + connects the interrupt, devnode → Started → GET_ID works,
a pended WAIT_FOR_INTERRUPT is completed by an injected interrupt (count = 1) →
REMOVE_DEVICE disconnects/unmaps/detaches, resources revoked, devnode → Removed. No
callback at the wrong IRQL. See docs/compat-notes/device-stack.md for the stack/IRP
mechanics.
