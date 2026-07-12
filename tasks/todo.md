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

## Increment 5 done (2026-07-06): enumerate all fixture devnodes as a real device tree
driver-host-pnp now enumerates a 5-child device tree under \Device\RootBus (a FIXTURES table:
PnpMmioInterruptTest + MmioInterruptTest + PowerPnpMmioTest + DmaPnpPowerTest + KmdfInterfaceRegistry
Test). Each registered as a service + Enum\ devnode + a root-bus child PDO. QUERY_DEVICE_RELATIONS
(BusRelations) returns all children; each service is resolved from its devnode; the primary (driver
in store) binds+starts through the full IRP-through-stack lifecycle. 28 PASS / 0 FAIL + 185 kernel.
New: bus_relations_lists_all_children, device_tree_services_resolved, device_tree_has_bindable_driver.
nt-root-bus: query_device_relations() (6 tests).

## Increment 6 done (2026-07-06): live PnP-Manager state per tree child
Every device-tree child now has a PnP Manager state entry (not just the primary). The enumerate loop
creates a pnp devnode per fixture (all Enumerated); the primary reuses pnp_devnodes[0] for the bind
and advances to Started. Live-tree snapshot shows per-child state. 30 PASS / 0 FAIL + 185 kernel.
New: device_tree_all_children_enumerated (all 5 Enumerated), device_tree_live_states (primary Started,
siblings Enumerated). state_label() DeviceState->str helper.

## Increment 7 done (2026-07-06): TWO real drivers bound + Started in one host
driver-host-pnp now loads + binds TWO distinct driver binaries: PnpMmioInterruptTest (device 0 @
0x140000000) + PowerPnpMmioTest (device 1 @ 0x160000000), both reaching Started. Per-device state
(DH[2] + CURRENT index; per-device pdo_object_id/device_owner_id/code_base/int_resource_id), two
mapped bases, distinct resources (MMIO 0x10000000/vec5 vs 0x20000000/vec6). Added Po* export stubs
(PoCallDriver/PoSetPowerState/PoStartNextPowerIrp). bind_secondary() does the core lifecycle. Live
tree: two children Started, rest Enumerated. 31 PASS / 0 FAIL + 185 kernel. New: second_driver_bound_
and_started, device_tree_two_children_started. KEY BUG fixed: ntos_io_connect_interrupt hardcoded
INT_RESOURCE_ID -> per-device int_resource_id (the 2nd driver's interrupt was assigned as +1).

## Increment 8 done (2026-07-06): KMDF driver as a SECOND FAMILY in the WDM host
driver-host-pnp now binds a KMDF driver (KmdfLoaderCompatTest, device slot 2 @0x180000000) alongside
the two WDM drivers, proving the WDF runtime coexists with the WDM export surface in one host. Added
a minimal WDF surface: WdfVersionBind (negotiate 1.15) + 444-entry function table + WdfDriverCreate
(installs the WDM AddDevice bridge + framework PnP dispatch) + WdfDeviceCreate (FDO) + WdfObjectGet
TypedContextWorker (context) + the WdfDeviceInit setters + CFG fixup. PnP calls the bridge ->
EvtDriverDeviceAdd -> WdfDeviceCreate (FDO). This driver's FULL EvtDeviceAdd (registry params + device
interface + I/O queue) needs direg's complete WDF runtime, so WdfDriverOpenParametersRegistryKey/
WdfDeviceCreateDeviceInterface/WdfIoQueueCreate report failure -> EvtDeviceAdd unwinds cleanly after
the FDO. 32 PASS / 0 FAIL + 185 kernel. New: kmdf_family_binds_alongside_wdm, two_wdm_started_plus_
kmdf_bound. Fixes: CODE_FRAME_CAPS [[u64;16];3], HEAP 128K->1M (3 drivers' pe.map). KMDF child reaches
AddDeviceCalled (FDO created); full Started for KMDF is direg's runtime.

## Increment 9 done (2026-07-06): KMDF child to Started via the shared nt-wdf-kmdf crate
driver-host-pnp's KMDF child (KmdfInterfaceRegistryTest, FIXTURES[2]) now reaches Started through the
shared crate: bind_kmdf uses nt_wdf_kmdf::{init, config_mut (seed service + Answer=42/Greeting + devnode),
export_addr, cfg_dispatch_addr, add_device_bridge_addr, device, set_devnode, set_driver_service, wdf}.
Full EvtDeviceAdd (WdfDeviceCreate + registry params + device interface + I/O queue) runs via the crate;
the component's kmdf_fx_pnp_dispatch (MajorFunction[IRP_MJ_PNP]) drives START (prepare_hardware + D0 via
nt_wdf_kmdf::wdf(), forward down to PDO). 32 PASS / 0 FAIL + 185 kernel. THREE children Started in one
host, TWO families: PnpMmioInterruptTest (WDM) + PowerPnpMmioTest (WDM) + KmdfInterfaceRegistryTest (KMDF).
The crate is now consumed by both direg (29/29) and driver-host-pnp (KMDF to Started) — factoring complete.

## Cross-VSpace SURT client done (2026-07-06): 49 PASS
A genuinely isolated seL4 component (own CSpace/VSpace, spawned by the driver-host root task) opens
the KMDF child's device interface + issues an IOCTL entirely over a SURT ring. Server = the root task
(hosts the KMDF device + shared nt-wdf-kmdf runtime); it spawns ONE isolated client and mediates every
device touch. New: src/surt_client.rs (alloc-free client_entry), SURT broker/server block in main.rs
(KernelEnv, vaddr layout at 0x1_0080_0000, su_* cap helpers, su_build_client_vspace, run_surt_interface
_client), surt-sel4="0.1" dep. Protocol: OP_OPEN(guid)->detail0=fdo+rep=symlink, OP_IOCTL(user_data=fdo,
req=[ioctl])->rep=output. 3 checks: surt_open_interface_over_ring, surt_ioctl_ping_over_ring,
surt_xvspace_client_verdict_all_passed. First QEMU run clean, no #PF/hang.

## MILESTONE (started 2026-07-06): Isolated-driver NT kernel — crash-survivable, no bluescreens
Vision (user): isolate ALL drivers (WDM/KMDF/UMDF) into their own seL4 processes; the driver-host is
the "NT kernel" (WDF runtime + device model + hardware caps) reached over the SURT reflector ring; a
driver crash is caught on a fault endpoint — the kernel survives (no bluescreen). Reuse nt-pe-loader +
nt-wdf-kmdf + the ring for both driver styles; the only difference is in-process vs out-of-process.

- [ ] Part A — Crash survival: give the isolated driver component a FAULT ENDPOINT (tcb_set_space
      fault_ep). It does its ring work (open interface + IOCTL), then deliberately faults. The NT-kernel
      side (driver-host root task) catches the fault via ep_recv on the fault EP, decodes it (fault
      type + address), reports "isolated driver crashed, kernel survived", and continues run() (proving
      liveness). Checks: driver_fault_caught_by_kernel, kernel_survives_driver_crash.
- [ ] Part B — Fully separate binary: port kernel src/elf.rs into a userspace loader; separate driver-
      host-um crate -> own ELF, embedded + loaded by driver-host-pnp into a PRIVATE VSpace (own image).
      Re-run ring + crash-survival from the separate binary.
- [ ] Later: load a real KMDF/UMDF driver in the isolated host via nt-pe-loader; restart-after-crash.

## Part B + Restart/health milestone (started 2026-07-06)
- [ ] Part B: fully separate binary. nt-um-abi crate (shared ABI consts); src/elf_loader.rs (port
      kernel elf.rs); components/driver-host-um (own ELF @0x1_0090_0000); driver-host-pnp loads its
      PT_LOAD segments into a private VSpace + spawns; build.sh builds um first.
- [ ] Restart supervisor (nt-driver-supervisor crate, host-tested): on caught fault, restart the
      driver; exponential backoff (BASE<<n) on repeated rapid crashes; "healthy uptime" = the driver
      reached a health checkpoint over the ring (crash-before-health = rapid crash); after MAX_RAPID
      consecutive rapid crashes -> DISABLE: write a flag to the service's ConfigManager registry
      (Start=4 / CrashCount) so userspace can see/disable it; no infinite crash loop. QEMU demo shows
      restart + backoff + disable-in-registry; unit tests cover health-reset + backoff + threshold.

## Win32k Milestone C (session) — build lesson + winsrv wall
- BUILD: `build_kernel.sh extern-rootserver` only REPACKAGES a pre-staged
  `.tmp/rootserver.elf`. Run `components/ntos-executive/build.sh` FIRST (or use
  `scripts/run-executive.sh`) or you boot a STALE executive (edits have no effect).
- DONE: win32k comes up + parks BEFORE csrss; SSN>=0x1000 forward wired in
  service_sec_image → win32k_dispatch. Gate 105/105 green.
- WALL (winsrv deferred): re-enabling ServerDll=winsrv loads the full 14-DLL Win32
  client stack, but user32 DllMain (UserClientDllInitialize, RVA 0x45ac0) null-derefs
  the client-shared win32k connection global (gSharedInfo/USERCONNECT). Next grind =
  the win32k↔user32 client connection + fix the csrss fault-loop hang on that null-deref.
