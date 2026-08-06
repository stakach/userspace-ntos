# Kernel Completion Plan

Last updated: 2026-08-07

## Objective

Move from the current ReactOS desktop frontier toward a small, durable NT kernel that hosts
ReactOS through real NT mechanisms. The kernel should provide core traits only: object identity,
process/thread execution, virtual memory and sections, I/O and driver dispatch, registry hives,
security/synchronization, and IPC. Service policy, launch policy, and compatibility shaping belong
in SCM, user-mode system processes, and our ntdll where possible.

## Working Rules

- Keep the kernel mechanism-only. Do not add process-name, service-name, or executable-order policy
  unless it is bootstrapping state that NT itself owns.
- Do not add fallback success paths. Missing behavior should return the real failure and get tracked.
- Prefer host-testable crates for registry, VAD, cache, security, and service metadata before wiring
  behavior into the executive.
- Replace old machinery when a dynamic path supersedes it. Do not leave parallel special cases behind.
- Validate one build/spec path at a time; do not run kernel builds or boot specs in parallel.
- Commit each green, meaningful slice.

## Status Legend

- `[ ]` pending
- `[~]` in progress
- `[x]` complete

## Workstreams

### A. SCM-Controlled Service Startup

- `[x]` A0: Inventory the current SCM/service startup path and mark the static boundaries still in
  use.
- `[x]` A1: Define typed service metadata in the Configuration Manager for `Type`, `Start`,
  `ImagePath`, `ErrorControl`, load group, tag, object name, dependencies, display name, and account
  data.
- `[x]` A2: Provide host-tested service selection helpers for auto-start Win32 services and
  boot/system driver candidates, without embedding launch policy in the kernel.
- `[~]` A3: Route SCM start requests through generic process creation or `NtLoadDriver` based on
  service metadata.
- `[ ]` A4: Remove remaining executive service-name/executable-name launch decisions once SCM owns
  the policy boundary.
- `[ ]` A5: Add boot gates proving the first auto-start service and demand-start service are selected
  dynamically from registry state.

### B. Driver Stack Bring-Up From Service Metadata

- `[x]` B1: Unify `NtLoadDriver`/`NtUnloadDriver`, SCM driver start/stop, and boot/system driver
  launch on one service-key to driver-object path.
- `[x]` B2: Order boot/system drivers by `Start`, group, and tag metadata instead of compiled-in
  driver lists.
- `[~]` B3: Bind PnP devnodes to driver services from registry `Enum`/`Services` data and let
  drivers create device objects/interfaces through I/O Manager mechanisms.
- `[x]` B4: Replace fixture-specific driver proof paths with generic driver lifecycle gates:
  load, `DriverEntry`, dispatch, stop, unload, object teardown.

### C. Memory Manager And VAD Correctness

- `[ ]` C1: Compare live executive `NtAllocateVirtualMemory`, `NtFreeVirtualMemory`,
  `NtProtectVirtualMemory`, `NtMapViewOfSection`, and fault handling with `nt-address-space`.
- `[ ]` C2: Move process address-space state onto a host-tested VAD model with reserve, commit,
  decommit, release, protect, query, and unmap semantics.
- `[ ]` C3: Wire image and data section views into the VAD/fault path so mapped files own page fill
  and dirty writeback.
- `[ ]` C4: Add regression gates for overlapping VADs, partial decommit, protection changes,
  `MEM_TOP_DOWN`, guard/no-access faults, and view teardown.

### D. Registry And Filesystem Durability

- `[ ]` D1: Audit mutable registry and writable filesystem paths: `NtFlushKey`, `NtSaveKey`,
  `NtLoadKey`, `NtUnloadKey`, file writeback, rename/delete, and profile hive usage.
- `[ ]` D2: Make the Configuration Manager/Hive Manager the live authority for mutable hives rather
  than executive-local mirrors.
- `[ ]` D3: Implement explicit flush and reboot persistence proofs for system hive, user profile
  hive, and writable filesystem overlay changes.
- `[ ]` D4: Complete volatile-key, transaction/log replay, setup-state, and user-profile durability
  behavior needed for repeat boots.

## Immediate Iteration

1. Continue B3 cleanup after the NDIS-backed PCI path for ReactOS `e1000.sys`: generated SYSTEM hive
   state carries the registry-selected `E1000` service, PCI `Enum` devnode, class driver key, and
   explicit `Linkage\Export`; `E1000` completes `AddDevice` and `START_DEVICE` with
   `STATUS_SUCCESS`; the generic grant path proves NT-style PCI config reads, full
   MMIO/I/O/interrupt resource-list projection, multiple common-buffer allocations from the
   per-devnode DMA grant, cap-backed inline `out dx,eax` I/O-port service,
   `IoSetDeviceInterfaceState` publication, connected-ISR dispatch, and KDPC bottom-half delivery.
   Hosted PCI and root-bus resource grants now use selected per-devnode component windows instead
   of NIC-named globals or root-bus proof VAs, publication is selected from the boot/system PnP
   launch plans, and the PCI broker discovers grant material for every registry-selected eligible
   PCI function. Existing `E1000` PCI grant registration, DMA grant allocation, and IOMMU mapping now
   flow through generic broker helpers that derive BAR size and DMA domain/request identity from the
   enumerated PCI device. Hosted PCI/root resource publication now allocates component resource VAs
   from the real hosted-driver VA arena and reports VA exhaustion instead of using fixed PCI/root
   window caps. Hosted driver instance, reply-cap, and executive alias bookkeeping now grows on
   demand; per-instance executive VAs come from a checked high arena with on-demand PD/PT coverage.
   Hosted common-buffer allocation records now use the per-instance shared arena capacity instead of
   a fixed eight-record table, and hosted device bindings, root-PDO bindings, and registry identities
   now grow on demand while reusing teardown holes. The raw direct TX proof remains only as a hardware
   liveness proof before VT-d mapping. The next B3 target is replacing remaining small launch-state
   caps such as driver registry handles, hosted interface registrations, driver-object extensions if
   real drivers need more, and DPC queue policy; then retire the direct raw proof once generic PCI
   evidence fully covers it.
2. Continue A3 for Win32 service starts: SCM-owned service metadata should choose process creation;
   the kernel should only expose generic process/section/token/thread primitives.
3. Audit remaining static driver-object construction sites that are not service-key-derived,
   especially video and object-server tests, and classify whether they are fixtures or real debt.
4. Add boot gates for the first auto-start and demand-start service selections once SCM is consuming
   the seeded Configuration Manager authority.

## Review Log

### 2026-08-05

- Created this plan after closing the dynamic shell paint debt at commit `9bb1bcf`.
- Current boot frontier before this plan: desktop gate passes `285/285`, genuine explorer launch,
  shell chrome framebuffer pixels proven.
- A0 started. Existing dynamic driver launch can read `Services\<Name>` values from the SYSTEM hive,
  but selection still happens through named service probes in the executive. The first cleanup target
  is typed service metadata in `nt-config-manager`, then converging executive service/driver readers
  onto that API.
- A0/A1/A2 complete. `nt-config-manager` now exposes a registry-authoritative
  `ServiceMetadata` view, `REG_MULTI_SZ` dependency decoding, typed service constants, and
  host-tested selectors for SCM auto-start Win32 services and boot/system drivers. This keeps
  policy out of the kernel while giving SCM/driver launch code a shared typed metadata boundary.
  Validation: `cargo test -p nt-config-manager` and `cargo test -p nt-config-store`.
  Review adjustment: A3 should replace executive-local service value parsing helpers with this
  metadata boundary, then delete the duplicate parser code.
- A3 started. Driver service `Type` decoding moved behind `nt-config-manager`'s
  `driver_service_class_from_type`, and the executive's SYSTEM-hive driver lookup now has one
  parameterized helper for boot/system and demand-start routes. The old demand-start duplicate
  parser was removed. Validation: `cargo test -p nt-config-manager` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: next A3 slice should move the actual early-boot hive import toward
  `ConfigManager::service_metadata_list()` or an equivalent snapshot-backed live CM view so the
  executive stops naming individual services while selecting driver candidates.
- A3 continued. `nt-hive-core` now imports `ControlSetXXX\Services` into a `ConfigManager`
  registry subtree, preserving values and nested service keys. The generated config-hive driver
  proof uses that import plus `boot_system_driver_candidates()` to select its second driver and
  derives `\Driver\<ServiceName>` from the selected service metadata; it no longer probes
  `IrpFsdTest` by name. Validation: `cargo test -p nt-hive-core` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: real `REGF` SYSTEM hive import is still needed so `Npfs` and demand
  `NtLoadDriver` service reads can use the same live CM metadata path.
- A3 continued. `nt-hive-regf` now preserves original-case subkey enumeration and imports real
  `REGF` `ControlSetXXX\Services` trees into `ConfigManager`, including nested service keys and
  typed values. The executive's real SYSTEM hive driver lookup now imports services and reads
  `ServiceMetadata` for both the existing NPFS boot proof and dynamic `NtLoadDriver` demand-start
  requests; the old local raw `ImagePath`/`Type`/`Start` parser was removed. Validation:
  `cargo test -p nt-hive-regf` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: A3 still needs the actual SCM service-start request path to choose Win32
  service process creation from `ServiceMetadata`, and B2 should replace the NPFS-specific boot
  proof with ordered boot/system driver enumeration.
- A3 continued. `nt-config-server` can now be constructed around an already-seeded
  `ConfigManager`, and the client/server host test proves a seeded `Services\<Name>` tree is visible
  through the existing CM wire API. This is the construction hook needed for a single boot-seeded CM
  authority instead of a fresh empty registry service. Validation: `cargo test -p nt-config-client`
  and `cargo test -p nt-config-server`. Review adjustment: the executive still has to pass imported
  boot hive state into the isolated CM service, or retire the parallel executive-local registry read
  path behind that service.
- B2 started. `nt-config-manager` now reads `Control\ServiceGroupOrder\List` and orders boot/system
  driver candidates by `Start`, service group order, `Tag`, and name. Validation:
  `cargo test -p nt-config-manager`. Review adjustment: the executive still needs to consume this
  full ordered candidate list for boot/system driver bring-up rather than explicitly asking for
  NPFS as a proof-only service.

### 2026-08-06

- B2 continued. `nt-hive-regf` now imports `ControlSetXXX\Control\ServiceGroupOrder` alongside
  `Services` for boot-driver selection snapshots, and the executive's real SYSTEM-hive
  `ConfigManager` view uses that broader import. Validation: `cargo test -p nt-hive-regf`. Review
  adjustment: the ordered metadata is now available from real REGF hives; the next B2 slice should
  replace the remaining NPFS-named launch proof with an ordered boot/system launch plan.
- B2 complete for the current hosted FSD boundary. The executive now builds an ordered boot/system
  driver launch plan from real SYSTEM-hive service metadata, narrows it to the registry `File System`
  load-order group that the current FSD host can execute, launches those candidates through the
  generic driver path, and discovers the named-pipe provider by the `\Device\NamedPipe` object it
  publishes rather than by `Npfs` service name. Validation: `cargo test -p nt-hive-regf` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: B3/B4 now own expanding the same ordered plan to boot bus, device, filter, and
  PnP-bound drivers instead of filtering to the FSD load group.
- B1 started. Boot FSD launch and `NtLoadDriver` now consume the same `DriverServiceLaunchSpec`
  shape: registry service name, derived `\Driver\<Service>` object path, normalized image path, and
  driver class. `NtLoadDriver` no longer keeps a separate image-path/class tuple parser or local
  driver-object path builder. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: finish B1 by routing SCM driver start/stop onto the same spec and making unload
  policy share service metadata rather than only the derived object path.
- B1 complete. `nt-config-manager` now owns the NT service-key to driver-object path rule:
  driver `ObjectName` wins when present, filesystem/recognizer services derive `\FileSystem\<Name>`,
  and device/kernel services derive `\Driver\<Name>`. The executive consumes that single resolver
  for generated-hive driver proof launch, ordered SYSTEM-hive boot FSD launch, `NtLoadDriver`, and
  `NtUnloadDriver`; the old local `\Driver\<Service>` builder was removed. ReactOS SCM driver
  start/stop was reviewed and confirmed to enter the kernel through `NtLoadDriver`/`NtUnloadDriver`,
  so no extra SCM-specific kernel hook is required. Validation: `cargo test -p nt-config-manager`
  and `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: B4 should now turn the existing named driver proof into generic lifecycle
  gates, while B3 owns expanding beyond the current registry `File System` group filter.
- B4 complete. The service-selected driver proof now validates the full generic lifecycle: registry
  service metadata selects the driver, `load_driver` runs `DriverEntry`, the driver object route is
  published through the Object/I/O Manager path, IRP dispatch runs through the shared harness, a real
  `DriverUnload` is invoked, and the I/O route, Object Manager path, and live instance are gone after
  unload. The synthetic `IrpFsdTest.sys` fixture now installs a no-op `DriverUnload` so the proof
  exercises the same stop/unload path that `NtUnloadDriver`/SCM stop use. Plan review found and
  fixed the matching namespace prerequisite: Object Manager bootstrap now creates `\FileSystem` and
  `\FileSystem\Filters`, so filesystem driver objects can be created under the NT FSD namespace
  rather than relying on `\Driver`. Validation: `cargo test -p nt-object-manager`,
  `cargo test -p nt-driver-test-fixtures`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: B3 is now the main driver-stack gap. The current boot/system plan is still
  filtered to the registry `File System` load group because hosted device/bus/filter bring-up needs
  devnode-to-service binding and PnP-owned device creation.
- B3 started. `nt-config-manager` can now persist and index `Enum\<InstanceId>` devnodes from the
  registry tree, including `Service`, `PdoName`, `HardwareID`, and `CompatibleIDs`, and can enumerate
  devnodes by bound service without requiring fixture registration. Both generated hives and REGF
  hives now import `ControlSetXXX\Enum` into the live Configuration Manager registry and build that
  devnode index after import. Validation: `cargo test -p nt-config-manager`,
  `cargo test -p nt-hive-core`, `cargo test -p nt-hive-regf`, and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next B3 slice should feed these registry-indexed devnodes into the PnP
  Manager's lifecycle model, replacing static fixture devnode creation with service-bound devnode
  creation and preserving the kernel/policy split.
- B3 continued. `nt-pnp-manager` now models service-bound devnodes directly: callers pass the
  Configuration Manager-selected `Enum\<InstanceId>`, optional service, PDO object id, and resource
  assignment, while PnP owns only lifecycle/resource state. The existing `driver-host-pnp` proof now
  creates PnP lifecycle entries from its CM-materialized root-enumerated devnodes and uses each
  devnode's assigned resources for START instead of the MMIO fixture constructor. Validation:
  `cargo test -p nt-pnp-manager` and
  `cargo check --manifest-path components/driver-host-pnp/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the old fixture constructor still exists for `driver-host-power`,
  `driver-host-dma`, and isolated `pnp-svc`; the next B3 slice should move `pnp-svc` to
  descriptor/resource payloads and then retire or test-scope the compatibility helper.
- B3 continued. The isolated `pnp-svc` SURT path now creates devnodes from a fixed
  `PnpCreateDevnodeReq` shared-frame payload containing `Enum\<InstanceId>`, service, PDO id, and
  resource assignment. The PnP manager child validates that payload and calls the same
  `create_service_bound_devnode` API as the in-process PnP proof; query still returns the PnP-owned
  resources from the canonical devnode table. Validation: `cargo test -p nt-pnp-abi` and
  `cargo check --manifest-path components/pnp-svc/Cargo.toml --target x86_64-unknown-none`. Review
  adjustment: remaining B3 debt is now the executive boot plan filter: registry-indexed devnodes need
  to drive service-bound device-driver bring-up, after which the MMIO fixture helper can be made
  test-only or removed from production components.
- B3 continued. `nt-config-manager` now has a host-tested
  `boot_system_pnp_driver_candidates()` selector: boot/system device-class services are selected only
  when imported `Enum` state binds at least one devnode to the service. The executive boot-driver plan
  now uses that same CM authority inline: registry `File System` services still launch through the
  persistent IRP host, and device-class services enter the plan only through `Enum` service binding.
  Validation: `cargo test -p nt-config-manager` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next B3 slice should carry the selected devnode descriptors/resources into
  hosted device-driver start/AddDevice, then retire production uses of the legacy MMIO fixture helper.
- B3 continued. Production hosted-driver proofs no longer call fixture devnode constructors:
  `driver-host-power`, `driver-host-dma`, and `driver-host-direg` all create service-bound PnP
  devnodes with explicit resources or `NO_RESOURCES`, and the public `nt-pnp-manager` fixture
  constructors were removed. Validation: `cargo test -p nt-pnp-manager`,
  `cargo check --manifest-path components/driver-host-power/Cargo.toml --target x86_64-unknown-none`,
  `cargo check --manifest-path components/driver-host-dma/Cargo.toml --target x86_64-unknown-none`,
  and `cargo check --manifest-path components/driver-host-direg/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: B3's remaining integration work is executive-owned AddDevice/StartDevice for
  registry-selected devnodes, not local component fixture cleanup.
- B3 continued. Config Manager now exposes `boot_system_pnp_driver_bindings()` so callers can carry
  selected device-driver service metadata with the exact imported `Enum` devnode records that bind
  to it. The executive's `DriverServiceLaunchSpec` now includes copied devnode descriptors
  (`instance_id`, `PdoName`, `HardwareID`, `CompatibleIDs`) for both boot and demand driver launch
  specs, and the boot trace prints the selected devnode count/first instance. Validation:
  `cargo test -p nt-config-manager` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next B3 slice should consume these descriptors by invoking AddDevice and
  StartDevice through the hosted driver path once device resources are assigned.
- B3 continued. Hosted driver launch now captures `DriverExtension->AddDevice` after `DriverEntry`
  and preserves it in the live driver instance table. This gives the executive a real per-driver
  AddDevice entrypoint for the registry-selected devnodes now carried in `DriverServiceLaunchSpec`;
  it does not yet invoke AddDevice or project the PDO/start IRP. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next B3 slice should add an executive dispatch path for AddDevice, backed by
  service-bound PDO projection and a subsequent `IRP_MN_START_DEVICE` dispatch with assigned
  resources.
- B3 continued. Device-class boot launch specs now invoke the hosted driver's real
  `DriverExtension->AddDevice` through the shared component pump. The component side allocates a
  WDM-shaped PDO, calls AddDevice inside the hosted driver's address space, and returns the FDO
  created by the driver's own `IoCreateDevice`; the executive publishes that FDO as an unnamed I/O
  Manager device and records the canonical device-id to hosted `DEVICE_OBJECT` binding for later IRP
  routing. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next B3 slice should replace the structural PDO placeholder with
  registry/devnode-backed PDO identity and send `IRP_MN_START_DEVICE` with assigned resource lists.
- B3 continued. The generic WDM stack writer now models
  `Parameters.StartDevice.AllocatedResources{,Translated}` and the hosted driver IRP builder carries
  PnP minor functions. Device-class boot launch now follows successful AddDevice with a real
  `IRP_MJ_PNP/IRP_MN_START_DEVICE` dispatch through the hosted FDO, passing an explicit empty
  resource list for no-resource devnodes and preserving real failure statuses for drivers that need
  hardware resources. Validation: `cargo test -p nt-io-manager` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: B3 still needs resource assignment from devnode/bus state, root-bus PDO
  identity/forwarding, and the device-driver ntoskrnl exports (`IoCallDriver`, `MmMapIoSpace`,
  `IoConnectInterrupt`) before hardware-backed StartDevice can replace the old NIC proof.
- B3 continued. Hosted AddDevice now preserves both sides of the WDM stack (`PDO` and `FDO`), PnP
  lifecycle IRPs no longer fabricate a `FILE_OBJECT`, and PnP dispatch reserves a lower
  `IO_STACK_LOCATION` for forwarding. The shared ntoskrnl import registry now binds stack-location
  helpers plus `IoCallDriver`/`IofCallDriver`/`PoCallDriver`, with forwarded IRPs completing only
  when the target matches the PDO carried from AddDevice. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: B3 still needs real root-bus PDO objects/state and assigned hardware resource
  lists; after that, bind `MmMapIoSpace`/`IoConnectInterrupt` to resource-manager grants and retire
  the old bespoke NIC driver proof.
- B3 continued. `nt-pnp` now parses registry PCI IDs (`PCI\VEN_...&DEV_...`, `PCI\CC_...`, and
  `PCI#...`) and resolves imported `Enum` devnodes to enumerated PCI functions by hardware IDs,
  instance path fallback, and compatible IDs. This keeps PCI identity matching host-testable and out
  of the executive. Validation: `cargo test -p nt-pnp`. Review adjustment: the next B3 slice should
  use this matcher in the executive boot plan to assign per-devnode `CM_RESOURCE_LIST`s, map the
  matching BAR into the hosted component, and bind `MmMapIoSpace`/`IoConnectInterrupt` to the grant.
- B3 continued. The executive boot plan now resolves each registry-selected PCI devnode through the
  `nt-pnp` matcher, builds a physical-address `CM_RESOURCE_LIST` for START, maps the already-claimed
  BAR into the hosted driver's VSpace, and binds `MmMapIoSpace`, `MmUnmapIoSpace`,
  `IoConnectInterrupt`, and `IoDisconnectInterrupt` to the active grant instead of the unbound-import
  fallback. If a devnode resolves to hardware the broker has not granted yet, START is still sent
  without resources and the driver's real failure is preserved. Validation: `cargo test -p nt-pnp`
  and `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: B3 still needs devnode-backed root-bus PDO state and generic interrupt/DMA
  resource-manager grants before the old bespoke NIC driver proof can be removed.
- B3 continued. Hosted AddDevice now registers the component-local PDO with the executive's
  `nt-root-bus` table using the imported `Enum` instance path, hardware IDs, and compatible IDs.
  Lower-stack `IoCallDriver` records forwarded PnP minors in the shared frame, and successful hosted
  START applies the forwarded minor to root-bus PDO lifecycle state instead of leaving the PDO as a
  stateless structural placeholder. `nt-root-bus` also has a host-tested split helper for
  `Enum\<DeviceID>\<InstanceID>`. Validation: `cargo test -p nt-root-bus` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the remaining B3 gap before retiring the old NIC proof is real interrupt/DMA
  resource-manager grant state plus a boot proof that the generic registry-selected driver reaches
  the same hardware-backed lifecycle evidence.
- B3 continued. Hosted device-driver MMIO and interrupt grants now flow through the canonical
  `nt-resource-manager`: per-devnode resource owners and deterministic resource IDs are registered
  before `START_DEVICE`, stale no-resource projections are cleared, and post-START `MmMapIoSpace`
  / `IoConnectInterrupt` evidence is replayed into the resource manager with no success fallback.
  `nt-resource-manager` now replaces repeated assignments and can revoke all resources/usages for a
  single driver/device owner. Validation: `cargo test -p nt-resource-manager` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: DMA/common-buffer ownership is still fixture-hosted; the next B3 slice should
  expose `IoGetDmaAdapter`/common-buffer allocation on the generic hosted-driver path using
  `nt-dma-manager`, then add the boot evidence needed to retire the bespoke NIC proof.
- B3 continued. Generic hosted device drivers now have a resource-bound DMA surface:
  `nt-dma-manager` can register broker-provided common buffers at a fixed logical address/IOVA,
  the executive binds `IoGetDmaAdapter` plus `AllocateCommonBuffer`/`FreeCommonBuffer` projections,
  maps the broker-owned DMA frame into the hosted driver's VSpace, creates a canonical adapter for
  the devnode owner, and records post-START common-buffer evidence back into `nt-dma-manager`.
  Validation: `cargo test -p nt-dma-manager` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: MMIO, interrupt connection, and DMA/common-buffer ownership are now on the
  generic registry-selected boundary. The remaining B3 work before removing the old NIC proof is a
  boot gate showing the generic path reaches real hardware evidence and real interrupt delivery to
  the connected ISR token.
- B3 continued. The generic hosted-driver path now exposes a service-agnostic
  `HostedHardwareEvidence` snapshot after `START_DEVICE`, covering MMIO map evidence, interrupt
  connection evidence, DMA adapter/common-buffer evidence, and root-PDO started state. The boot
  driver loop prints per-devnode and aggregate hardware evidence when any registry-selected device
  driver receives a grant, without adding a service-name gate or making absent hardware evidence
  pass. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the next B3 slice should run the boot, inspect this generic evidence trace, and
  convert the dynamic evidence into real gates once the registry-selected path is confirmed.
- B3 continued. Headless boot `desktop-render-r104-generic-hw-evidence-20260806-093752` reached
  winlogon profile loading but stopped at the executive bump allocator after writable overlay mount.
  The trace showed no generic hardware evidence because the real SYSTEM hive currently selected only
  FSD boot services (`Msfs`, `Npfs`) for the hosted path, and the service-loop heap watermark was
  already `5957452/6291456` before profile loading. The executive boot/system driver plan now copies
  CM-selected service/devnode metadata into a bounded static snapshot and rewinds the large
  ConfigManager import scratch before loading drivers; AddDevice/PnP resource helpers now consume
  borrowed devnode ID slices so the snapshot does not need heap-backed `String` clones. Validation:
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: rerun the boot to confirm the heap regression is gone, then add a
  registry-selected device-driver proof fixture or real seeded service/devnode so the generic
  hardware evidence path can be gated and the bespoke NIC proof can be retired.
- B3 frontier validation continued. Headless boot
  `desktop-render-r109-dispatch-frame-split-20260806-102452` passed the previous boot/system plan
  heap wall and advanced through real winlogon dialog paint into profile loading. The trace shows
  real api0 `WM_PAINT` dispatches plus `NtUserBeginPaint`, `NtUserEndPaint`, and
  `NtGdiGetTextExtentExW`; it then stopped on an executive stack fault while servicing
  `NtQueryAttributesFile` during `LoadUserProfileW`. The large `ExecNtHandler::handle_service`
  frame has been split behind raw service-entry veneers, and the SSN 145 path now uses bounded
  no-allocation object-name/path buffers plus host-tested `nt-fs` relative-path helpers instead of
  growing `Vec`/`String` state at the profile frontier. Validation: `cargo test -p nt-fs` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: run a staged release boot to confirm profile loading passes this stack wall,
  then reclassify the next real frontier before adding the generic hardware evidence gate.
- B3 frontier validation passed through the profile path and restored the full desktop baseline.
  `NtQueryAttributesFile` now runs through the split raw service entry with fixed-size object-name
  and folded relative path scratch buffers, and the old allocating attribute-query wrappers in the
  executive filesystem bridge were removed. Spawned service heap reservation was reduced to the
  smaller working set the current services actually use, restoring untyped-pool headroom without
  hiding failure paths. Validation: `cargo test -p nt-fs`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and `./run.sh` passing `287/287` gates including
  `exec_explorer_shell_chrome_painted` and `exec_vm_pool_headroom`. Review adjustment: B3 remains
  active, but the baseline is clean again; resume with a registry-selected device-driver hardware
  proof and turn the generic hardware evidence trace into a gate before retiring the old NIC proof.
- B3 continued. The generated SYSTEM hive now seeds a root-enumerated
  `ROOT\USERSPACE_NTOS_DMA\0001` devnode for `DmaPnpPowerTest` instead of binding the proof driver
  to a real e1000 PCI identity, and `nt-pnp` owns a host-tested root-bus resource profile for that
  class. The executive grants the registry-selected root devnode a seeded MMIO page, interrupt
  vector metadata, and a common DMA buffer, then sends the real `IRP_MN_START_DEVICE` through the
  hosted AddDevice/FDO path. A Win64 dispatch-guard alignment bug exposed by the driver's MSVC
  `movaps` memset helper was fixed by force-aligning the guarded outbound call frame while preserving
  bugcheck unwind. Validation: `cargo fmt --all`, `cargo test -p nt-pnp`,
  `cargo test -p nt-hive-core`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and `./run.sh`. The boot reached genuine explorer shell
  chrome pixels with `284/286` gates, and the generic hardware gates now pass:
  `exec_generic_hw_registry_selected`, `exec_generic_hw_mmio_interrupt_dma`, and
  `exec_generic_hw_root_pdo_started`. Review adjustment: B3's remaining cleanup is to deliver a real
  interrupt through the connected ISR token on the generic grant and then remove the older bespoke
  NIC proof machinery.
- B3 continued. Generic hosted device drivers now keep the canonical
  `nt-resource-manager` interrupt connection id in their shared evidence, and the executive can
  inject that exact id through the existing hosted-component dispatch pump. The component dispatcher
  executes the registered ISR in the driver's own VSpace using the `IoConnectInterrupt`
  PKINTERRUPT/service-context projection, records claimed/vector/delivery-count evidence, and the
  generated root-bus DMA proof asserts its test MMIO status register before requiring ISR claim plus
  MMIO acknowledgement in the new `exec_generic_hw_interrupt_delivered` gate. Validation so far:
  `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  and `./components/ntos-executive/build.sh`. Review adjustment: run the staged boot and inspect the
  new gate before removing any bespoke NIC proof machinery; the old NIC proof should remain until the
  generic path proves equivalent hardware interrupt/DMA behavior.
- B3 validation update. `./run.sh` booted through genuine explorer shell chrome again with
  `285/287` checks passing; the only failing checks in the streamed summary were the known
  `exec_irp_transport_call_bound` and `exec_client_reply_bound` transport-accounting gates. The new
  `exec_generic_hw_interrupt_delivered` gate is therefore green along with the existing generic
  registry/MMIO/interrupt/DMA/root-PDO gates. Review adjustment: do not delete the old raw NIC proof
  yet. The generic path now proves dynamic hosted-driver MMIO, DMA, and connected-ISR delivery for
  the root-bus DMA fixture; the remaining B3 cleanup is to move real PCI interrupt/DMA hardware
  evidence onto the same generic resource boundary, then remove the bespoke NIC-specific proof once
  that equivalence is demonstrated.
- B3 continued. Generic hosted device drivers now drain bounded KDPC work queued by the connected
  ISR before returning from the interrupt-dispatch pump. `KeInsertQueueDpc` records real KDPC
  pointers and system arguments in the hosted shared frame, the component dispatcher invokes each
  driver's deferred routine in the hosted driver address space, and boot evidence requires
  zero-drop DPC delivery in the new `exec_generic_hw_dpc_delivered` gate. Validation:
  `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and `./run.sh` through genuine explorer shell chrome with
  `286/288` checks passing. The only failing checks remain the known
  `exec_irp_transport_call_bound` and `exec_client_reply_bound` transport-accounting gates. Review
  adjustment: the generic root-bus fixture now proves MMIO, DMA common-buffer allocation,
  connected-ISR execution, and DPC bottom-half execution. The next B3 slice should move the old real
  PCI/NIC hardware proof onto this generic resource boundary, then remove the bespoke NIC proof only
  after equivalent PCI-backed evidence is green.
- B3 cleanup continued. The SYSTEM-hive boot loop and generated-hive hardware proof now use one
  hosted-devnode resource grant helper for PCI and root-bus resources. The helper owns the dynamic
  devnode-to-resource selection, hosted resource-manager/DMA-manager grant, and START resource bytes;
  callers only decide whether a no-resource devnode may start with an empty list. Grant failures no
  longer fall through to an empty START list. Validation: `cargo fmt --all` and
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`.
  Review adjustment: the old NIC proof still remains because the available WDM fixtures expect test
  register banks (`MMIO`/`DMA1`), and ReactOS `e1000.sys` requires the NDIS frontier. The next useful
  B3 work is either a real PCI-capable hosted test driver that consumes the e1000 BAR honestly, or
  enough NDIS/ReactOS driver support to let `e1000.sys` bind through the same generic grant helper.
- B3 cleanup continued. The hosted FSD PE import resolver no longer has a generic success fallback:
  unknown imports now fail image loading before `DriverEntry`. The old prefix-matched no-op
  machinery was replaced with exact bindings for the
  ReactOS `npfs.sys`/`msfs.sys` surface, including Unicode string helpers, optional registry query
  defaults, security/object helpers, cancel-safe queue callbacks, dynamic IRP allocation, timers,
  probes, and cleanup routines. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and `./run.sh` through genuine explorer shell chrome with
  `286/288` checks passing; the only failing checks remain the known
  `exec_irp_transport_call_bound` and `exec_client_reply_bound` transport-accounting gates. Review
  adjustment: with the hosted FSD fallback removed, resume B3 at the PCI/NDIS equivalence frontier
  before deleting the old bespoke NIC proof.
- B3 cleanup continued. The hosted driver PE resolver is now provider-DLL-aware: imports are resolved
  as `dll!symbol`, `ntoskrnl.exe`/`hal.dll` exact imports bind through the executive registry, malformed
  import tables and ordinal imports fail closed, and unsupported dependency DLLs such as `ndis.sys`
  report the missing `dll!symbol` before `DriverEntry` instead of colliding on name-only exports.
  `hal!KeStallExecutionProcessor` is explicitly bound as a HAL timing primitive for the ReactOS e1000
  import surface, but `ndis.sys` remains a real dependency image frontier rather than an executive shim.
  Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and `./run.sh` through genuine explorer shell chrome with
  `286/288` checks passing; the only failing checks remain the known
  `exec_irp_transport_call_bound` and `exec_client_reply_bound` transport-accounting gates. Review
  adjustment: next B3 work should load and resolve real dependency images such as `ndis.sys` (or add an
  honest PCI WDM fixture) before retiring the bespoke NIC proof.
- B3 cleanup continued. Hosted driver launch now discovers real dependency provider DLLs from raw
  import descriptors without heap allocation, maps `ndis.sys` into the same hosted image window after
  the primary image, and resolves `ndis.sys!symbol` from that loaded support image's export directory.
  The executive trampoline registry remains limited to the kernel providers (`ntoskrnl.exe` and
  `hal.dll`); `ndis.sys` is a real PE image, not an executive shim. The support image is not yet run
  through its own driver initialization, so loading ReactOS `e1000.sys` will now get as far as the
  real `ndis.sys` import surface and still fail truthfully on missing NT/HAL exports until those core
  imports are implemented. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and `./run.sh` through genuine explorer shell chrome with
  `286/288` checks passing; the only failing checks remain the known
  `exec_irp_transport_call_bound` and `exec_client_reply_bound` transport-accounting gates. Review
  adjustment: next B3 work should implement the real NT/HAL import surface required by ReactOS
  `ndis.sys`, then initialize the NDIS support driver before binding `e1000.sys` through generic PCI
  grants.
- B3 cleanup continued. The hosted component harness can now initialize an optional support driver
  image before the primary hosted driver's `DriverEntry`, and support failure prevents the primary
  image from being marked entered or registered. ReactOS `ndis.sys` remains a real loaded PE support
  image: all NT/HAL imports from its import table have exact trampoline bindings, including RTL
  ANSI/Unicode/integer helpers, driver-object extensions, interlocked lists/SLists, work items,
  MDL/memory helpers, timers/DPC/spin helpers, bounded Zw registry/file failures, and grant-bound HAL
  bus translation/interrupt/PCI config reads. Generic hosted resource grants now also carry bus
  identity, PCI address, vendor/device/class, and interrupt line/pin so `IoGetDeviceProperty` and
  `HalGetBusDataByOffset` answer from assigned devnode state instead of hardcoded process identity.
  Validation found and fixed one harness-limit regression: the shared `DriverExportRegistry` was
  still capped at 160 entries while the real FSD/NDIS surface now binds 184 names, causing late
  imports such as `DbgPrint` to fail silently and preventing `Msfs`/`Npfs` from loading. The registry
  cap is now 256, exhaustion is tracked/tested, and FSD registration panics if capacity is exceeded.
  Validation: `cargo fmt --all`, `cargo test -p nt-compat-exports`, static `ndis.sys`/`npfs.sys`/
  `msfs.sys` import comparison against `register_fsd_trampolines()`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, and `./run.sh` through genuine explorer shell chrome with
  `286/288` checks passing; the only failing checks remain the known
  `exec_irp_transport_call_bound` and `exec_client_reply_bound` transport-accounting gates.
  Review adjustment: `e1000.sys` still cannot complete AddDevice because NDIS asks for
  `DevicePropertyDriverKeyName`/miniport `Linkage` registry data, and the hosted driver registry
  handle is currently an empty key that returns truthful missing/unsupported statuses. The next B3
  slice should project devnode-backed driver-key registry state, then run the staged boot and convert
  the real NDIS/e1000 startup evidence into gates before removing the old bespoke NIC proof.
- B3 cleanup continued. Devnode-backed driver registry identity is now carried by Config Manager and
  the executive boot plan: `ServiceMetadata` includes `ClassGUID`, `DevnodeRecord` includes the
  imported Enum `Driver` value, and hosted AddDevice receives both so `IoGetDeviceProperty` can
  answer `DevicePropertyDriverKeyName` and the hosted registry path can expose the miniport
  `Linkage` key without falling back to an empty registry handle. The staged boot initially exposed a
  separate rootserver infrastructure limit: the NT executive root task entered the guard page during
  ReactOS process bring-up after `NtQuerySection(csrss.exe)`. `rust-micro` now sizes the guarded
  rootserver stack separately for `extern-rootserver` builds and the loader spec asserts the mapped
  aux page count. Validation: `cargo fmt --all`, `cargo test -p nt-config-manager`,
  `cargo test -p nt-exe-image`, `cargo test -p nt-io-manager`, `cargo test -p nt-process`,
  `cargo test -p nt-address-space`, `cargo test -p nt-user-callback`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and headless boot `.tmp/full-boot-larger-rootstack-20260806.log` to genuine explorer shell chrome
  with `286/288` checks passing. The only failing gates remain the known
  `exec_irp_transport_call_bound` and `exec_client_reply_bound`; the generic hardware gates pass for
  registry selection, MMIO/interrupt/DMA, root-PDO start, ISR delivery, and DPC delivery. Review
  adjustment: B3 remains active until real `ndis.sys` initialization and ReactOS `e1000.sys` miniport
  startup run through the same generic PCI grant, after which the old raw NIC proof can be removed.
- B3 cleanup continued. The generated-hive PnP hardware proof no longer collapses
  `boot_system_pnp_driver_bindings()` to a single selected service. It now materializes an inline
  boot PnP launch plan, copies each selected devnode descriptor into the fixed executive plan buffer,
  and launches every eligible config-hive binding through the hosted AddDevice/START/resource path.
  The old owned-vector conversion used only by the single-binding path was removed. Validation:
  `cargo fmt --all`, `cargo test -p nt-config-manager`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./run.sh` through genuine explorer shell chrome with `286/288` checks passing. The generic
  hardware gates stayed green for registry selection, MMIO/interrupt/DMA, root-PDO start, ISR
  delivery, and DPC delivery.
  Review adjustment: the B3 frontier is still real NDIS/e1000. The proof selector is now dynamic
  enough to exercise multiple boot/system PnP bindings when the registry supplies them; next work is
  support-driver/miniport startup and then replacing the old raw NIC proof with PCI-backed generic
  evidence.
- B3 cleanup continued. Service-bound devnode start is now factored into `hosted_pnp_start`: the
  executive publishes the discovered PCI/NIC/root-bus resource context once, boot/system device
  services and the generated-hive hardware proof call the same AddDevice/resource-grant/StartDevice
  helper, and `NtLoadDriver` demand-start device services with Enum-bound devnodes use that helper
  after `DriverEntry`. The previous empty-resource START convenience path was removed; a selected
  devnode without an assigned resource now reports `STATUS_INVALID_DEVICE_REQUEST` instead of
  succeeding synthetically. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and `./run.sh` through genuine explorer
  shell chrome with `286/288` checks passing. The generated-hive hardware gates still pass for
  registry selection, MMIO/interrupt/DMA, root-PDO start, ISR delivery, and DPC delivery. Review
  adjustment: continue B3 at the NDIS boundary: support-driver initialization, miniport
  AddDevice/StartDevice, and adapter resource queries should now ride the generic demand-start PnP
  path.
- B3 cleanup continued. The generated SYSTEM hive now seeds a real registry-selected E1000 PCI
  service/devnode/class-linkage identity, and boot imports `Control\Class` alongside `Services`,
  `Enum`, and service-group order into Config Manager. The generated hive moved to the second
  storage shared page to avoid import-table overlap. Hosted registry identity is now explicit:
  devnodes carry `Linkage\Export` from the class key, hosted registry handles copy that identity,
  AddDevice publishes it through the shared frame, and the driver launch path rejects missing exports
  instead of deriving synthetic device names. Hosted driver instance slots now reserve the first free
  slot, clear stale mappings before reuse, and record exec-frame mappings for teardown. Validation:
  `cargo fmt --all`, `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `cargo test -p nt-config-manager`, `cargo test -p nt-hive-core`,
  `cargo test -p nt-hive-regf`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and `./run.sh` proof
  `.tmp/full-boot-e1000-pci-proof-5-20260806.log`. The boot reached genuine explorer shell chrome
  with `288/291` checks passing; `exec_generic_pci_registry_selected`,
  `exec_generic_pci_support_driver_entry`, and `exec_generic_pci_add_device_reached` are green. The
  remaining failures are the known transport-accounting gates
  `exec_irp_transport_call_bound`/`exec_client_reply_bound` plus `exec_vm_pool_headroom`. Review
  adjustment: B3 remains open at real ReactOS NDIS/e1000 `START_DEVICE`, which currently returns
  `STATUS_INVALID_DEVICE_REQUEST` before MMIO, interrupt, or DMA evidence is produced.
- B3 continued. The registry-selected ReactOS `e1000.sys` PCI path now receives a full
  memory+I/O-port+interrupt `CM_RESOURCE_LIST`, accepts NT `PCI_SLOT_NUMBER` config reads through
  real `ndis.sys`, maps the 128 KiB BAR, registers the 64-byte I/O port BAR, and allocates all three
  observed common buffers from one per-devnode DMA grant (two 2048-byte descriptor rings plus the
  262144-byte receive-buffer window). `nt-dma-manager` now scopes logical DMA addresses by
  `DmaOwner`, so multiple devices may reuse the same logical IOVA in separate domains, and hosted
  common-buffer evidence records each active allocation rather than one synthetic global result.
  The NDIS diagnostic interposition used to find the boundary was removed; dependency imports now
  call the real mapped `ndis.sys` export. Validation: `cargo fmt --all`,
  `cargo test -p nt-cm-resources`, `cargo test -p nt-pnp`, `cargo test -p nt-dma-manager`,
  `cargo test -p nt-hive-core`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and headless boot
  `.tmp/full-boot-e1000-cleaned-counts-20260806.log` through genuine explorer shell chrome with
  `284/291` checks passing. Generic config-PnP instrumentation is now count-based:
  `selected=2 attempted=2 add=2 started=1`, with PCI separately reported as
  `pci_selected=1 pci_attempted=1 pci_support=1 pci_add=1 pci_started=0
  pci_first_error=0xc0000001`. The remaining B3 frontier is inside real e1000 miniport start after
  resource and common-buffer setup, before interrupt connection. Review adjustment: do not claim
  arbitrary NIC/driver scale yet; hosted instance/device tables, shared-frame allocation-record
  slots, and fixed proof BAR/DMA windows are still bounded. The next cleanup should replace those
  fixed hosted arenas with per-devnode dynamic resource/window allocation before multi-NIC support is
  considered complete.
- B3 continued. Hosted hardware drivers now receive real x86 I/O-port caps for PnP-granted I/O BARs,
  and the component pump services only validated x86 #GP `out dx,eax` faults against the projected
  cap, resource range, opcode byte, and thread registers. Multi-instance hosted drivers now carry an
  executive image alias into the pump for instruction validation, the old send-only port-I/O helpers
  were replaced by shared error-reporting helpers, and boot evidence/gates now track generic PCI
  port-write service instead of relying on NIC-specific code. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `.tmp/boot-ioport-out32-20260806.log`. Result: `exec_generic_pci_io_port_out32` passed, E1000
  evidence reported `io_out32=1 io_out32_count=4`, and the boot reached genuine explorer shell
  chrome with `285/292` checks passing. Review adjustment: the B3 frontier has moved past inline
  port I/O. The next target is the rootserver `RingChannel::raw` null destination fault at
  `rip=0x10000455944/cr2=0` during E1000 `START_DEVICE`, while longer-term multi-NIC support still
  needs dynamic per-devnode hosted instance/resource windows rather than fixed proof arenas.
- B3 continued. `IoSetDeviceInterfaceState` no longer mutates Object/I/O Manager state from hosted
  driver import context. The hosted call captures the requested interface link, target, and
  enable/disable state in the driver's shared frame, and the executive applies the symbolic-link
  create/delete after the parked `START_DEVICE` dispatch returns. Repeated enable/disable transitions
  are idempotent at the import boundary, and the executive's Object Manager/Configuration Manager
  clients are now heap-pinned for the rootserver lifetime instead of leaving raw global pointers to
  `_start` stack locals. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `.tmp/boot-device-interface-idempotent-20260806.log`. Result: E1000 `AddDevice` and
  `START_DEVICE` both return `STATUS_SUCCESS`, `exec_generic_pci_io_port_out32` remains green, and
  the boot reaches genuine explorer shell chrome with `285/292` checks passing. Review adjustment:
  the rootserver `RingChannel::raw` null-destination wall is gone; the B3 frontier has moved to the
  explicit E1000 interrupt-delivery proof, which now walls at `label=3 ip=0x0e014abd
  addr=0x1000f01fd88` after start while ISR/DPC evidence for that PCI device is still absent.
- B3 continued. Hosted driver IRQL state is now per-component shared-frame state instead of a
  PASSIVE-only CR8 rewrite. ReactOS CR8 helper reads are patched to load that byte, hosted spin-lock
  imports raise/lower it according to the NT contract, `KeReleaseSpinLockFromDpcLevel` no longer
  lowers IRQL, `KeGetCurrentIrql` is a real trampoline, and queued KDPC routines run at
  `DISPATCH_LEVEL`. The pump also records label-3 exception/code details for future hosted-driver
  walls. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-hosted-irql-20260806.log`. Result: boot
  reaches genuine explorer shell chrome with `286/292` checks passing; `E1000` reports
  `start=0x00000000`, `int_delivered=1`, `dpc=1`, `dpc_count=1`, `dpc_drops=0`, DMA common-buffer
  evidence, and generic PCI I/O-port evidence. The new generic gates
  `exec_generic_hw_interrupt_delivered` and `exec_generic_hw_dpc_delivered` pass for the real
  registry-selected E1000 path. Review adjustment: B3 is no longer blocked on E1000 ISR/DPC
  delivery. The remaining failures are the legacy direct NIC proof gates
  `exec_nic_has_msi_capability`/`exec_nic_raised_real_interrupt`/
  `exec_nic_irq_reached_isolated_host`, transport-accounting gates
  `exec_irp_transport_call_bound`/`exec_client_reply_bound`, and `exec_vm_pool_headroom`.
- B3 cleanup continued. The old direct NIC MSI/isolated-ISR proof was retired from the early
  hardware capstone. The remaining direct NIC checks still prove raw BAR mapping, live MMIO, TX DMA
  writeback, and VT-d confinement, while interrupt delivery now belongs only to the generic
  registry-selected hosted-driver/resource-manager gates that already exercise ReactOS `e1000.sys`
  through `IoConnectInterrupt`, ISR dispatch, and KDPC delivery. The obsolete
  `exec_nic_has_msi_capability`, `exec_nic_raised_real_interrupt`, and
  `exec_nic_irq_reached_isolated_host` gates and their hand-programmed MSI helper were removed.
  Review adjustment: the remaining cleanup targets are transport accounting, VM pool headroom, and
  dynamic per-devnode hosted resource/window allocation for multi-NIC and arbitrary driver scale.
- B3 cleanup continued. Transport accounting now uses a dedicated never-bound
  `REPLY_TRANSPORT_PROBE_SLOT` for the negative control, so the proof no longer depends on a spare
  dynamic hosted-driver instance slot. The FSD-class hosted-driver pool now matches the one 2 MiB
  page-table window that was actually mapped for each instance, reclaiming unused root-untyped
  capacity without changing the effective driver address space. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-fsd-pool-headroom-20260807.log`. Result:
  `exec_generic_hw_interrupt_delivered`, `exec_generic_hw_dpc_delivered`,
  `exec_irp_transport_call_bound`, `exec_client_reply_bound`, `exec_vm_pool_headroom`, and
  `exec_explorer_shell_chrome_painted` all pass; the boot reaches genuine explorer shell chrome with
  `289/289` checks passing. Review adjustment: B3 cleanup now centers on replacing remaining fixed
  hosted proof arenas/windows with per-devnode dynamic resource windows for multi-NIC and arbitrary
  boot-driver scale.

### 2026-08-07

- B3 cleanup continued. Hosted PnP resource publication now carries a vector of
  `HostedPnpPciResourceWindow` records keyed by PCI bus/dev/function, with separate per-window
  component MMIO and DMA VAs. The grant path first resolves the registry-selected devnode against the
  enumerated PCI bus, then matches the corresponding published window before assigning resource
  lists, mapping BAR/DMA frames, and registering resource-manager/DMA-manager ownership. The old
  `HOSTED_PNP_NIC_*` globals and the combined PCI-match/resource-assignment helper were removed, and
  hosted resource mapping now creates every page-table leaf required by a multi-2MiB MMIO or DMA
  grant. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-hosted-pci-windows-20260807.log`. Result:
  `E1000` receives PCI resources (`mmio_len=131072`, `io_len=64`, `dma_len=270336`), starts through
  the generic path, and keeps MMIO, I/O-port, DMA, ISR, and DPC evidence green; the boot reaches
  genuine explorer shell chrome with `289/289` checks passing. Review adjustment: this removes the
  NIC-named hosted resource context, but the publisher still exposes only the pre-claimed E1000
  hardware grant and root-bus proof resources still use fixed VAs. The next B3 cleanup should make
  resource publication originate from the registry-selected devnode set/resource broker for every
  eligible PCI function, then replace the fixed root-bus proof windows with the same allocator.
- B3 cleanup continued. Hosted PCI window publication now originates from the registry-selected
  boot/system PnP launch plans: the early hardware claim is only retained as broker grant material,
  the initial hosted PnP context publishes PCI enumeration without resource windows, and the final
  context exposes windows only for launch-plan devnodes that resolve to matching broker grants.
  Duplicate bus/dev/function windows are collapsed, missing grants and capacity exhaustion are
  reported explicitly, and the boot now gates this boundary with
  `exec_hosted_pci_windows_selected_from_registry`. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-plan-derived-pci-windows-20260807.log`.
  Result: `selected=1 published=1 missing-grants=0 cap-exhausted=0`, the ReactOS `E1000` path keeps
  MMIO, I/O-port, DMA, ISR, DPC, and interface publication evidence green, and the boot reaches
  genuine explorer shell chrome with `290/290` checks passing. Review adjustment: PCI publication is
  no longer tied to a pre-published E1000 identity; remaining B3 resource-window debt is the fixed
  root-bus proof VAs and the bounded hosted window/instance tables before arbitrary multi-driver
  scale can be considered complete.
- B3 cleanup continued. Root-bus proof resources now use the same published resource-window
  boundary as PCI. `nt-pnp` exposes a tested root-bus profile matcher, the executive builds root
  windows only for registry-selected launch-plan devnodes, and the old static
  `HOSTED_PNP_ROOT_DMA_*` frame globals plus `NIC_VADDR`/`DMA_VADDR`/`NIC_IOVA` reuse were removed
  from the root grant path. The root proof still has an executive seed alias for its synthetic MMIO
  register page, but that alias is allocated by root-window index and looked up through the active
  resource evidence before interrupt injection. Validation: `cargo fmt --all`, `cargo test -p
  nt-pnp`, `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-root-resource-windows-20260807.log`.
  Result: `pci-selected=1 pci-published=1 root-selected=1 root-published=1`, both
  `exec_hosted_pci_windows_selected_from_registry` and
  `exec_hosted_root_windows_selected_from_registry` pass, `DmaPnpPowerTest` and ReactOS `E1000`
  both receive resources through the generic hosted PnP path, and the boot reaches genuine explorer
  shell chrome with `291/291` checks passing. Review adjustment: the remaining B3 resource debt is
  no longer static hosted identity; it is bounded scaling and broker coverage. Next work should make
  hardware-grant discovery enumerate/claim every registry-selected eligible PCI function instead of
  carrying only the raw E1000 claim, then address fixed hosted instance/window caps where they become
  practical blockers.
- B3 cleanup continued. PCI grant discovery now walks the registry-selected boot/system PnP launch
  plans before resource-window publication, deduplicates selected bus/dev/function identities, keeps
  any existing real DMA/IOMMU grant, and can claim cap-only BAR/interrupt grants for selected PCI
  functions that do not require DMA. PCI resource windows and START validation now treat DMA as
  optional all-or-none state, so the broker no longer invents synthetic DMA or rejects legitimate
  BAR/interrupt-only devices. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-pci-grant-discovery-20260807.log`. Result:
  `exec_hosted_pci_grants_discovered_from_registry` passes with
  `selected=1 existing=1 claimed=0 missing-mmio=0 missing-int=0 claim-failures=0 cap-exhausted=0`,
  PCI/root window publication remains clean, ReactOS `E1000` and `DmaPnpPowerTest` still start
  through the generic hosted PnP path, and the boot reaches genuine explorer shell chrome with
  `292/292` checks passing. Review adjustment: the next B3 cleanup should move the E1000
  DMA/common-buffer/IOMMU setup itself out of the raw proof block into generic broker grant
  construction, then replace fixed hosted instance/window caps with growable or per-launch
  allocation.
- B3 cleanup continued. Existing PCI grant registration now uses the same broker constructor as
  registry-selected PCI grant discovery: the E1000 path resolves the enumerated PCI device by
  bus/dev/function, derives BAR base and page count from the device's memory BAR, removes the fixed
  `NIC_BAR_PAGES` constant, and records the existing DMA/IOMMU grant only when the DMA grant is
  internally consistent. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-brokered-existing-pci-grant-20260807.log`.
  Result: `exec_hosted_pci_existing_grant_brokered` passes with `count=1 failures=0`, PCI/root
  window publication remains registry-selected, ReactOS `E1000` and `DmaPnpPowerTest` still start
  through the generic hosted PnP path, and the boot reaches genuine explorer shell chrome with
  `293/293` checks passing. Review adjustment: the remaining B3 cleanup is moving DMA/common-buffer
  and IOMMU allocation itself behind the broker boundary, then replacing fixed hosted
  window/instance caps where they block arbitrary multi-driver scale.
- B3 cleanup continued. E1000 DMA/common-buffer grant allocation and IOMMU setup moved behind
  generic broker helpers: `allocate_hosted_pci_dma_grant` allocates the cap-backed common-buffer
  grant, `map_hosted_pci_dma_grant_iova` derives IO-space request/domain identity from the
  enumerated PCI device and maps the grant into the device IO space, and hosted PnP only receives
  the existing DMA grant after IOMMU mapping succeeds. The unused raw `alloc_slot_run` helper was
  removed. The raw direct TX proof still runs before VT-d as a hardware liveness proof, while the
  brokered boundary is now gated by `exec_hosted_pci_dma_grant_iommu_brokered`. Validation:
  `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof `.tmp/boot-brokered-pci-dma-grant-20260807.log`.
  Result: `exec_frame_get_paddr`, `exec_nic_tx_dma_writeback`,
  `exec_nic_iopt_hierarchy_built`, `exec_nic_dma_frame_io_mapped`,
  `exec_hosted_pci_dma_grant_iommu_brokered`, and `exec_nic_confined_dma` pass; registry-selected
  PCI/root window publication, ReactOS `E1000`, `DmaPnpPowerTest`, ISR/DPC evidence, and explorer
  shell chrome remain green with `294/294` checks passing. Review adjustment: B3 cleanup now moves
  to bounded hosted window/instance/allocation-record scaling and then removing the direct raw proof
  once generic PCI evidence fully replaces it.
- B3 cleanup continued. The fixed hosted PCI/root resource-window caps were removed from the
  publication path. `HostedPnpResourceVaAllocator` now hands out component MMIO/DMA VAs from the
  hosted-driver resource arena, root proof seed aliases from the actual executive seed scratch
  arena, and root DMA logical addresses independently; publication reports `pci-va-exhausted` or
  `root-va-exhausted` only when those real arenas run out. PCI grant discovery no longer rejects
  selected devices because of the old window cap. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target
  x86_64-unknown-none`, `./components/ntos-executive/build.sh`,
  `./rust-micro/scripts/build_kernel.sh extern-rootserver`, and
  `./rust-micro/scripts/run_specs.sh` proof
  `.tmp/boot-dynamic-hosted-resource-windows-20260807.log`. Result: hosted PCI grant discovery
  reports `selected=1 existing=1 claimed=0 missing-mmio=0 missing-int=0 claim-failures=0`,
  resource publication reports
  `pci-selected=1 pci-published=1 pci-missing-grants=0 pci-va-exhausted=0 root-selected=1
  root-published=1 root-missing-grants=0 root-va-exhausted=0`, ReactOS `E1000` and
  `DmaPnpPowerTest` both receive generic resources, the generic MMIO/interrupt/DMA/ISR/DPC gates
  stay green, and explorer shell chrome remains green with `294/294` checks passing. Review
  adjustment: remaining B3 scaling debt is now the hosted driver instance table, shared-frame DMA
  allocation-record capacity, and any other launch-state caps that prevent arbitrary driver count.
- B3 cleanup continued. The fixed hosted driver instance table was removed. Live driver state,
  executive alias cap lists, and FSD reply caps now grow on demand; W^X rights storage is per-loaded
  image; executive code/aux PT maps are checked; high per-instance VA arena coverage is installed on
  demand. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` proof
  `.tmp/boot-dynamic-driver-instances-pd-20260807.log`. Result: `Msfs` instance 0, `Npfs` instance 1,
  `IrpFsdTest` instance 2, `DmaPnpPowerTest` reuses instance 2, and ReactOS `E1000` instance 3; generic
  PCI/root hardware gates and FSD transport gates stay green; explorer shell chrome remains green
  with `294/294` checks passing. Review adjustment: remaining B3 launch scaling debt is shared-frame
  DMA allocation records and any other fixed launch-state caps; then remove direct raw NIC proof once
  generic PCI evidence fully replaces it.
- B3 cleanup continued. The hosted common-buffer allocation record list no longer has a fixed
  eight-record shared-page cap. Each hosted driver now maps the full shared handoff arena up to the
  ARG window, publishes the derived record capacity in shared metadata, and validates the capacity and
  high-water mark before replaying allocations into `nt-dma-manager`. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` proof
  `.tmp/boot-dynamic-dma-record-arena-20260807.log`. Result:
  `exec_hosted_pci_dma_grant_iommu_brokered`, `exec_generic_hw_mmio_interrupt_dma`,
  `exec_generic_pci_registry_selected`, `exec_generic_pci_support_driver_entry`,
  `exec_generic_pci_add_device_reached`, `exec_generic_pci_io_port_out32`, and explorer shell chrome
  stay green with `294/294` checks passing. Review adjustment: remaining B3 launch scaling debt is now
  hosted device/root-PDO binding tables, hosted registry identity slots, and any small shared queues
  that block real multi-device drivers; then remove direct raw NIC proof once generic PCI evidence
  fully replaces it.
- B3 cleanup continued. Hosted device bindings, root-PDO bindings, and hosted registry identity state
  are no longer fixed 16-slot arrays. The launch path now uses growable `Vec`-backed state, reuses
  holes on teardown, widens hosted registry identity IDs to `usize`, and preserves existing lookup and
  update semantics for AddDevice, PDO, and linkage-registry correlation. Validation: `cargo fmt --all`,
  `cargo check --manifest-path components/ntos-executive/Cargo.toml --target x86_64-unknown-none`,
  `./components/ntos-executive/build.sh`, `./rust-micro/scripts/build_kernel.sh extern-rootserver`,
  and `./rust-micro/scripts/run_specs.sh` proof
  `.tmp/boot-dynamic-hosted-bindings-20260807.log`. Result: `DmaPnpPowerTest` and ReactOS `E1000`
  generic hardware evidence stayed green, `exec_generic_hw_mmio_interrupt_dma`,
  `exec_generic_pci_registry_selected`, `exec_generic_pci_support_driver_entry`,
  `exec_generic_pci_add_device_reached`, `exec_generic_pci_io_port_out32`,
  `exec_fsd_on_shared_harness`, `exec_msgina_logon_dialog_painted`, and
  `exec_explorer_shell_chrome_painted` pass with `294/294` checks passing. Review adjustment:
  remaining B3 launch scaling debt is now driver registry handle slots, hosted interface
  registration slots, driver object extension slots if real drivers need more, and the small DPC queue
  policy; after those, retire the direct raw NIC proof.
