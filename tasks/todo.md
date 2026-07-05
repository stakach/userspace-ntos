# Milestone: PnP-Manager-driven driver binding (WDM path) — increment 1

Spec: NT PnP Driver Binding + Devnode Lifecycle. User chose: WDM first (PnpMmioInterruptTest),
lowest risk (driver-host-pnp already runs the WDM PnP lifecycle as a direct harness).

## Transition this increment delivers
From "harness hardcodes the driver + calls AddDevice inline" TO "the PnP Manager binds from a
service database + drives the lifecycle through a real root-bus PDO", with traced state transitions.

## What exists (reuse)
- nt-pnp-manager: 14-state devnode FSM + ResourceAssignment (create_mmio_fixture_devnode, transition).
- nt-config-manager: DevnodeRecord (service, hardware/compatible IDs) + register_devnode/register_service.
- nt-cm-resources: CM_RESOURCE_LIST build. nt-pnp-abi: IRP_MJ_PNP + IRP_MN_* constants.
- driver-host-pnp: loads PnpMmioInterruptTest, DriverEntry sets DriverExtension->AddDevice +
  MajorFunction[IRP_MJ_PNP]; harness calls AddDevice + dispatch_pnp(START/REMOVE); IoAttach/MmMapIoSpace/
  IoConnectInterrupt via ResourceManager. IoCallDriver simulated. PDO = plain blob. No QUERY ops.

## Genuinely new (this increment)
- [ ] 1. nt-root-bus (NEW host-testable crate): a synthetic root PDO — create_pdo(device_id, hw_ids,
        compat_ids, instance_id, caps); query_id(pdo, kind) -> wide string / double-null multi-sz for
        BusQueryDeviceID/HardwareIDs/CompatibleIDs/InstanceID; query_capabilities(pdo) -> DEVICE_CAPABILITIES.
- [ ] 2. Service-database-driven bind: component registers the service (PnpMmioInterruptTest) + a devnode
        (service=..., device_id=ROOT\..., hw/compat IDs, resources) in nt-config-manager; resolve the
        service FROM the devnode; load the driver named by the service (a service->image table) — prove
        the driver-to-load is DB-derived, not hardcoded.
- [ ] 3. Refactor driver-host-pnp run() into a PnP-Manager sequence: Enumerate (create root-bus PDO,
        QUERY_ID it) -> ServiceSelected -> DriverLoaded -> PnP calls DriverExtension->AddDevice ->
        FdoAttached (verify FDO above PDO) -> StartPending (START_DEVICE raw+translated CM_RESOURCE_LIST)
        -> Started -> REMOVE teardown. Each step logs a traced pnp_* event.
- [ ] 4. I/O gating retained (IOCTL before start -> NOT_READY; works after Started); REMOVE releases
        resources; traced pnp_state_transition events + a serial compat-report.
- [ ] 5. Acceptance checks: service_selected_from_devnode, root_bus_query_id, root_bus_query_caps,
        pnp_called_add_device, fdo_attached_above_pdo, start_device_with_resources, remove_teardown.
- [ ] 6. Build + run in QEMU; commit; docs/compat-notes; memory.

## Deferred (later increments)
KMDF WDF AddDevice bridge (increment 2 -> the spec's KMDF acceptance); STOP/SURPRISE_REMOVE; full
QUERY-minor set + QUERY_DEVICE_RELATIONS; device-interface present-after-start (KMDF); pnpctl; the
other ~10 proposed crates (fold into nt-pnp-manager/nt-root-bus for now); user-mode interface open.

## Review (increment 1 done 2026-07-06)
Steps 1-5 complete. driver-host-pnp is now PnP-Manager-driven from the service database.
23 PASS / 0 FAIL + 185 kernel checks, no faults. New checks:
  service_selected_from_devnode, driver_loaded_by_service, root_bus_query_id_device,
  root_bus_query_id_hardware, root_bus_query_capabilities, pnp_called_add_device,
  fdo_attached_above_pdo, start_device_with_resources (+ existing gating/interrupt/remove).
New nt-root-bus crate (4 host tests); nt-config-manager devnode_service/devnode_hardware_ids accessors.
Traced pnp_* events + a compat report. Next: KMDF WDF AddDevice bridge (increment 2 -> spec acceptance).

## Increment 2 done (2026-07-06): KMDF WDF AddDevice bridge
Evolved driver-host-direg from a direct KMDF host to PnP-Manager-driven with the WDF AddDevice
bridge. WdfDriverCreate installs wdm_add_device_bridge into DriverExtension->AddDevice; PnP calls it
-> EvtDriverDeviceAdd -> WdfDeviceCreate -> FDO. 27 PASS / 0 FAIL + 185 kernel. New checks:
wdf_add_device_bridge_installed, root_bus_query_id_device/capabilities, pnp_add_device_created_
device_queue, fdo_attached_above_pdo, interface_not_present_before_start, devnode_started_interface_
present, devnode_removed. Trace: pnp_add_device_enter -> wdf_add_device_bridge_enter ->
wdf_evt_driver_device_add_enter. nt-pnp-manager: added create_devnode (no-resource devnode).
This hits the spec's KMDF acceptance (PnP-called AddDevice via WDF bridge, interface after start).

## Increment 3 done (2026-07-06): real PnP IRP dispatch through the device stack (KMDF)
START/REMOVE are now real IRP_MJ_PNP IRPs traveling FDO -> PDO, not direct framework calls.
WdfDriverCreate installs fx_device_pnp_dispatch into DriverObject->MajorFunction[IRP_MJ_PNP]; PnP
builds the IRP + IoCallDriver(FDO) -> the framework dispatch runs EvtDevicePrepareHardware + D0Entry
and forwards the IRP down to the root-bus PDO (root_bus.dispatch_pnp) which starts/completes it.
29 PASS / 0 FAIL + 185 kernel. New: start_device_irp_dispatched_through_stack (IRP completed +
PDO started), remove_device_irp_dispatched_through_stack (PDO stopped). nt-root-bus: Pdo.started +
dispatch_pnp + pdo_started (5 tests). prepare_hardware_and_d0_entry now driven by the IRP path.

## Increment 4 done (2026-07-06): WDM PnP IRP-through-stack (symmetry with KMDF)
driver-host-pnp's IofCallDriver now routes the forwarded PnP IRP to the root-bus PDO instead of
simulating success. The real PnpMmioInterruptTest FDO forwards START/REMOVE down the stack ->
root_bus.dispatch_pnp(PDO) starts/stops the PDO. dh().pdo (bottom of stack) + dh().pnp_minor (in-flight
minor, stashed by dispatch_pnp). 25 PASS / 0 FAIL + 185 kernel. New: start_device_irp_reached_pdo,
remove_device_irp_reached_pdo. Now BOTH WDM (driver-host-pnp) + KMDF (driver-host-direg) dispatch PnP
IRPs through a real FDO->PDO device stack with the synthetic root bus at the bottom.
