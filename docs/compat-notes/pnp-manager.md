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

## SURT PnP Manager isolation (implemented — `pnp-svc`)

The `pnp-svc` broker spawns **two fully-isolated seL4 components** (own CSpace +
VSpace): a Driver Host (loads `PnpMmioInterruptTest.sys`, hosts the in-process HAL —
Resource Manager + simulated device + kernel runtime, all on its RW state page) and a
PnP Manager (owns the canonical devnode table + state machine + fixture resources).
The Driver Host drives the lifecycle locally — driver callbacks (AddDevice, PnP
dispatch, ISR/DPC) must run in its address space — and reports each transition +
queries resources over a SURT ring pair; the isolated PnP Manager validates every
transition and never touches driver code (spec §7.5).

- PnP requests ride the `SurtSqe` (opcode + `arg0` = devnode ID); the resource
  payload is written to a shared frame on `PNP_OP_QUERY_DEVNODE`. Opcodes drive a
  lifecycle phase's transitions: `CREATE_DEVNODE` → devnode ID; `LOAD_DRIVER`,
  `CALL_ADD_DEVICE` (→ DeviceStackBuilt), `START_DEVICE` (→ Started), `REMOVE_DEVICE`
  (→ Removed) each apply an ordered transition chain, failing the request on the first
  invalid step.
- Verified in QEMU (14/14) across the boundary: create devnode + query resources →
  **an out-of-order START on a second devnode is rejected by the isolated manager** →
  AddDevice (local) + transition → pre-start IOCTL `STATUS_DEVICE_NOT_READY` →
  START_DEVICE (local, CM_RESOURCE_LIST from queried resources) + transition to Started
  → GET_ID + injected-interrupt completion → REMOVE_DEVICE (local) + resources revoked
  → the isolated manager reports the devnode Removed.
