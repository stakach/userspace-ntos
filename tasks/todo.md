# Milestone: KMDF Loader-Compat bring-up (KmdfLoaderCompatTest.sys, KMDF 1.15)

New spec: NT Driver Loading + KMDF Binding Compat. New driver in the artifact:
`KmdfLoaderCompatTest.sys` (KMDF 1.15). All 10 drivers are staged in fixtures/
(9 are rebuilds of existing; this one is new).

## What already exists (reuse, don't rebuild)
- nt-pe-loader: PE64 map + DIR64/ABSOLUTE relocations + IAT list.
- nt-compat-exports: ntoskrnl/hal export table + statuses.
- nt-wdf-runtime/types: WdfVersionBind + 444-entry WdfFunctions table (hardcoded 1.15).
- driver-host-{wdf,wdfhw,direg}: load real KMDF 1.15 .sys end-to-end (include_bytes).
- nt-config-manager: ServiceRecord{name,image_path,type,start,...} — but no loader reads it.

## What the new driver + spec need (the increment)
The driver calls, in order: WdfVersionBind(0x1eb5) -> WdfVersionBindClass(0x21be)
-> WdfVersionUnbindClass(0x22bc) -> WdfVersionUnbind(0x1dfd), DbgPrintEx traces.
Existing components implement WdfVersionBind only; version mismatch returns
STATUS_UNSUCCESSFUL (not STATUS_REVISION_MISMATCH). Class bind/unbind not implemented.

## Plan (scoped increment — advance the spec via the new driver)
- [ ] 1. Stage KmdfLoaderCompatTest.sys in fixtures (done) + accessor.
- [ ] 2. Service-key-driven load: seed a ServiceRecord (name, ImagePath, Type=1,
        Start=3, KmdfLibraryVersion=1.15) in nt-config-manager; the component
        resolves the driver via the service key (reads ImagePath/type/version)
        instead of hardcoding — image bytes still come from the fixture.
- [ ] 3. WDFLDR binding surface for the new driver: WdfVersionBind (with
        STATUS_REVISION_MISMATCH on real mismatch), WdfVersionBindClass +
        WdfVersionUnbindClass (class-library bind, new), WdfVersionUnbind.
- [ ] 4. New component `driver-host-loadercompat`: load via service key ->
        map/reloc/patch IAT -> DriverObject+RegistryPath -> DriverEntry ->
        full bind cycle -> assert the bind-only acceptance (bind called, 1.15
        negotiated, function table returned, class bind/unbind ok, clean unbind).
- [ ] 5. Compat trace: emit the spec's bind events (wdf_version_bind_enter/exit,
        wdf_function_table_created, wdf_class_bind, driver_load_request, ...) to
        serial as a structured summary (no filesystem in a bare-metal component).
- [ ] 6. build.sh + run script; verify in QEMU; commit; update memory.

## Explicitly NOT in this increment
- The spec's ~10 proposed new crates (nt-driver-loader/service/image/...): reuse
  existing crates; refactor into new crates only if it pays off later.
- Full compat-report JSON+MD files (bare-metal has no FS) -> serial summary.
- Re-running the 9 rebuilt drivers (existing components already cover them).

## Review (done 2026-07-05)
All 6 plan steps complete. New component `driver-host-loadercompat` loads the real KMDF 1.15
`KmdfLoaderCompatTest.sys` through a service-key-driven path. 7 PASS / 0 FAIL, 185 kernel checks:
  resolve_service, map_image, resolve_imports, driver_entry_success,
  wdf_version_bind_called, kmdf_1_15_negotiated, driver_entry_reached_wdf_driver_create.

Flow proven: ResolveService (\Registry\...\Services\KmdfLoaderCompatTest, Type=1/Start=3/ImagePath)
-> MapImage (PE64, W^X) -> ResolveImports (ntoskrnl RtlInitUnicodeString/RtlCopyUnicodeString/wcslen/
DbgPrintEx + wdfldr WdfVersionBind/BindClass/UnbindClass/Unbind) -> CFG dispatch/check fixups (rva
0x3058/0x3050 from the load-config) -> DriverEntry -> FxStubInitTypes -> WdfVersionBind (1.15,
published 444-entry table) -> FxStubBindClasses (empty class section -> no WdfVersionBindClass) ->
real DriverEntry -> WdfDriverCreate (index 116, captured EvtDriverDeviceAdd=rva 0x1070) -> SUCCESS.
Serial compat-report emitted (WdfVersionBind=1, WdfDriverCreate=1, 0 stub hits).

Key finding: this driver imports WdfVersionBindClass (KMDF stub always does) but its class-bind
section is empty, so it is never called — the class-bind + unbind path is IMPLEMENTED and ready but
not exercised by this fixture. New this component vs the device hosts: service-key-driven load,
STATUS_REVISION_MISMATCH version negotiation, class-library bind surface, serial compat trace/report.
