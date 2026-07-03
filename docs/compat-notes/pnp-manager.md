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
