# Kernel Completion Plan

Last updated: 2026-08-06

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

1. Continue B3 by carrying selected `Enum` devnode descriptors/resources into hosted device-driver
   Start/AddDevice, then retire production callers of the legacy MMIO fixture helper.
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
