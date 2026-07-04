# KMDF / WDF runtime — compatibility notes

The first Kernel-Mode Driver Framework compatibility layer (spec: NT KMDF/WDF Runtime).
Target driver `KmdfBasicTest.sys` — KMDF **v1.15**, binds via `WDFLDR.SYS` (`WdfVersionBind`
fills the driver's `WdfFunctions` table + `WdfDriverGlobals`), then WDF calls go through
`WdfFunctions[index](WdfDriverGlobals, ...)`. FuncCount = 444 (`WdfFunctionTableNumEntries`).
Authoritative headers: `references/windows-kits/10/Include/wdf/kmdf/1.15/`.

## WDF object core (implemented, Milestone 1 — `nt-wdf-object`)

- `WdfHandle` = `[type:8 | generation:24 | slot:32]`, never zero for a live object; opaque
  to the driver. Generation-validated so a stale/reused slot is rejected (spec §8.2).
- `WdfObjectTable`: `create` (typed, optionally parented), `validate`/`object_type`/`parent`,
  `reference`/`dereference` (refcount, spec §7.4), `set_callbacks`, `set_context`/`get_context`
  (one typed context per object, spec §18), `delete`. Handle validation rejects
  Null/Stale/WrongType/Deleted.
- Parent/child tree: a driver owns devices, a device owns queues (spec §7.3). `delete` walks
  children **depth-first** and returns the ordered `PendingCallback` list (cleanup before
  destroy, each once) for the runtime to invoke **after** the table borrow is released — the
  Driver Host re-entrancy discipline. Destroy is deferred until the last reference drops.
- 5 unit tests: create/validate/wrong-type/stale, depth-first delete, cleanup→destroy order,
  deferred destroy, context storage.

## WDF ABI types + I/O model (implemented, Milestone 15.2 — `nt-wdf-types`, `nt-wdf-request`, `nt-wdf-queue`)

- `nt-wdf-types`: KMDF 1.15 constants from the WDK headers — version (1.15, FuncCount 444),
  `WDF_BIND_INFO` offsets, the `WDFFUNCENUM` indices the runtime implements (WdfDriverCreate=116,
  WdfDeviceCreate=75, WdfDeviceCreateSymbolicLink=80, WdfIoQueueCreate=152,
  WdfDeviceInitSetIoType=61/SetDeviceType=66/SetPnpPowerEventCallbacks=55,
  WdfRequestComplete=263/WithInformation=265, RetrieveInput/OutputBuffer=269/270,
  WdfCmResourceListGetCount/GetDescriptor=304/305, WdfObjectDelete=208,
  WdfDeviceWdmGetDeviceObject=31), and the config struct offsets a driver fills
  (WDF_DRIVER_CONFIG EvtDriverDeviceAdd@8/Size0x20; WDF_OBJECT_ATTRIBUTES cleanup@8/destroy@16/
  parent@32/ctxinfo@48/Size0x38; WDF_IO_QUEUE_CONFIG EvtIoDeviceControl@40/DefaultQueue@13/Size0x60;
  WDF_PNPPOWER_EVENT_CALLBACKS D0Entry@8/D0Exit@24/PrepareHardware@40/ReleaseHardware@48). 3 tests.
- `nt-wdf-request`: the WDFREQUEST presented→completed state machine (complete exactly once,
  spec §16.3) + `WdfRequestRetrieveInput/OutputBuffer` selection & min-length validation
  (STATUS_BUFFER_TOO_SMALL / INVALID_DEVICE_REQUEST). 5 tests.
- `nt-wdf-queue`: the WDFQUEUE dispatch policy — sequential (one in flight) / parallel (all) /
  manual (driver pulls via retrieve_next), with power-managed gating: a power-managed queue
  holds requests until D0 entry then releases per policy (spec §15.3-§15.4). 5 tests.
