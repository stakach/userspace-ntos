# Device stack — compatibility notes

The FDO→PDO device stack + PnP IRP routing for `IRP_MN_START_DEVICE` (spec: NT PnP
Manager, Milestone 12, §12).

## Implemented (Milestones 12.4-12.8 — `driver-host-pnp`)

- **DriverExtension / AddDevice** (§11): `DRIVER_OBJECT.DriverExtension`@48 →
  `DRIVER_EXTENSION.AddDevice`@8. The Driver Host pre-allocates the DriverExtension +
  wires `DriverObject[48]` before `DriverEntry`, which sets `AddDevice` there +
  `MajorFunction[IRP_MJ_PNP]`@112. The PnP Manager then calls `AddDevice(DriverObject,
  PDO)`; the driver creates the FDO (`IoCreateDevice`) + `IoAttachDeviceToDeviceStack`.
- **Device stack** (§12): `IoAttachDeviceToDeviceStack(FDO, PDO)` returns the lower
  device (PDO) + records the edge; `IoDetachDevice` drops it. `IofCallDriver` on the
  PDO completes the forwarded PnP IRP with success (returns non-pending, so the
  driver's synchronous forward proceeds without waiting).
- **PnP IRP** (§13): the START IRP's `IO_STACK_LOCATION` carries `MajorFunction`=
  `IRP_MJ_PNP`, `MinorFunction`@1, and `Parameters.StartDevice.AllocatedResources`@8 /
  `AllocatedResourcesTranslated`@16 pointing at a `CM_RESOURCE_LIST` blob. The IRP's
  `CurrentStackLocation` is placed with a spare lower location so the driver's inline
  `IoCopyCurrentIrpStackLocationToNext` has room.
- **Lifecycle**: resources are assigned to the Resource Manager only at `START` (so a
  pre-start `MmMapIoSpace` / IOCTL fails — `STATUS_DEVICE_NOT_READY`, §15.2). On
  `START` the driver parses the translated list → maps MMIO + connects the interrupt →
  devnode `Started`. `REMOVE_DEVICE` disconnects/unmaps/detaches → resources revoked →
  devnode `Removed`. Verified in QEMU (17/17) with `PnpMmioInterruptTest.sys`; no
  hard-coded resources in the driver.
