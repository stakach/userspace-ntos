# Kernel Completion Plan

Last updated: 2026-08-05

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

- `[ ]` B1: Unify `NtLoadDriver`/`NtUnloadDriver`, SCM driver start/stop, and boot/system driver
  launch on one service-key to driver-object path.
- `[ ]` B2: Order boot/system drivers by `Start`, group, and tag metadata instead of compiled-in
  driver lists.
- `[ ]` B3: Bind PnP devnodes to driver services from registry `Enum`/`Services` data and let
  drivers create device objects/interfaces through I/O Manager mechanisms.
- `[ ]` B4: Replace fixture-specific driver proof paths with generic driver lifecycle gates:
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

1. Create this plan and keep it current while working.
2. Start A1/A2 in `nt-config-manager`: typed service metadata and host tests.
3. Review the executive's current service/driver launch readers against the new metadata API.
4. Commit after the host-tested metadata slice is green.

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
