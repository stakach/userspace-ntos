# NT Driver Host — behavioural compatibility notes

Running notes on the Driver Host: loading + executing a WDM `.sys` driver in an
isolated user-space component and completing IRPs through the I/O Manager. See
`references/nt-driver-host-spec.md`.

## Driver-visible ABI (implemented, Milestone 1 — `nt-kernel-abi`)

- The `#[repr(C)]` structures a loaded driver sees inside the Driver Host, at the
  **exact WDK x86_64 field offsets** (from `references/windows-kits/10/Include/
  10.0.28000.0/km/wdm.h`), so an unmodified driver's machine code hits the right
  fields. `const _` layout asserts pin every offset at compile time:
  - `DRIVER_OBJECT` — 336 bytes; `DeviceObject`@8, `Flags`@16, `DriverName`@56,
    `DriverUnload`@104, **`MajorFunction[28]`@112** (the dispatch table a driver
    fills in `DriverEntry`).
  - `DEVICE_OBJECT` — 336 bytes, 16-aligned; `Flags`@48, `Characteristics`@52,
    `DeviceExtension`@64, `DeviceType`@72, `StackSize`@76 (tail opaque for v0.1).
  - `IRP` — 208 bytes, 16-aligned; `AssociatedIrp.SystemBuffer`@24, `IoStatus`@48,
    `CancelRoutine`@104, `UserBuffer`@112, `Tail.Overlay.CurrentStackLocation`@184.
  - `IO_STACK_LOCATION` — 72 bytes; `Parameters`@8 (with the `POINTER_ALIGNMENT`
    IOCTL layout: `IoControlCode`@24), `DeviceObject`@40, `CompletionRoutine`@56.
  - `UNICODE_STRING` (16), `IO_STATUS_BLOCK` (16), `LIST_ENTRY` (16).
- These are **local Driver Host projections**, not canonical kernel objects, and are
  deliberately **not** a cross-component ABI — cross-component messages carry ids.
- Pointer fields are `GuestAddr` (a `u64` wrapper meaning "address in the Driver
  Host's own space", never authority); `GuestPtr<T>` is the typed form for
  call-gate signatures. All layouts derive `bytemuck::Pod`/`Zeroable` so the runtime
  can zero-init + view parameter unions (`device_io_control()` / `read_write()`).
- `major` module: the IRP major-function codes; `MAJOR_FUNCTION_COUNT` = 28.

## PE loader (implemented, Milestone 2 — `nt-pe-loader`)

- A checked PE32+/x86_64 loader for Windows kernel images (`.sys`): parse → validate
  → list imports/relocations → map → relocate (spec §7.2, §20 M2). `no_std` + `alloc`,
  **no `unsafe`**. Every read goes through bounded `u16/u32/u64/bytes_at` helpers; a
  malformed image returns a structured `PeError`, **never panics or executes**.
- `PeFile::parse` validates DOS (`MZ`) → NT (`PE\0\0`) → COFF (`machine == AMD64`,
  bounded section count) → optional header (`PE32+` magic) → data directories, then
  the section table. Exposes `image_base`, `size_of_image`, `entry_point_rva`.
- `imports()` walks `IMAGE_IMPORT_DESCRIPTOR`s → one `ImportedDll` per module with its
  `ByName {name, hint}` / `ByOrdinal` functions **and each function's IAT slot RVA**
  (where the Driver Host will later patch the resolved trampoline).
- `relocations()` walks the base-reloc blocks; only `DIR64` (applied) + `ABSOLUTE`
  (padding) are accepted — any other type is `UnsupportedRelocation`.
- `map(load_base)` allocates `SizeOfImage`, copies headers + sections to their virtual
  addresses (BSS zero-filled), applies `DIR64` relocations for `load_base`, and exposes
  `entry_point()` + `patch_iat(slot_rva, addr)` for the import-patch step (§9).
- Rejected in v0.1 (per spec §7.2): x86/ARM64, non-PE32+, TLS callbacks, resources,
  packed images, signature enforcement, unsupported relocations.
- Tests: hand-crafted PE images (parse+map+entry, import listing with IAT slots, DIR64
  relocation on rebase, malformed-image rejection) + proptest fuzz (arbitrary + mutated
  bytes never panic) + a `cargo-fuzz` target (`fuzz/`, run manually). 116 workspace tests.

## Export registry + import report (implemented, Milestone 3 — `nt-compat-exports`, `driver-import-report`)

- `nt-compat-exports` is the driver-visible `ntoskrnl.exe` / `hal.dll` symbol table
  (spec §7.3). Each export has an `ExportStatus` — `Implemented` / `Partial` /
  `StubSuccess` / `StubFailure` / `Unsupported` / `TrapIfCalled` — and every
  `Partial` documents its deviations (enforced by a test). The `ExportRegistry`
  resolves `dll!name` (DLL name case-insensitive, symbol case-sensitive) to an
  `ImportOutcome`: `Available(status)` (loads), `Blocked` (unsupported — fail-fast),
  or `Missing`. `check()` produces an `ImportReport` with a `runnable()` verdict.
- v0.1 statuses: the device/symlink/IRP/Rtl/pool exports are `Implemented` (the
  runtime provides them in M4–M7); DbgPrint, the events, IRQL, and spinlocks are
  `Partial` (single-threaded / simulated / local-state); and the hardware / DMA /
  interrupt / device-stacking / `PsCreateSystemThread` / WDF exports are
  `Unsupported` — importing any of them blocks the load, so no driver gets fake
  hardware authority (spec §19.4). Trampoline addresses are bound later by the
  runtime (M5) via `set_trampoline`.
- `driver-import-report <driver.sys>` (spec §15, runs without seL4): parses the
  image with `nt-pe-loader`, resolves its imports against the registry, prints an
  `OK` / `UNSUPP` / `MISSING` line per import + a `runnable` / `BLOCKED` verdict,
  and exits non-zero when the driver cannot run under the v0.1 export set — so
  missing imports are reported **before** `DriverEntry`.
- `nt-driver-test-fixtures` emits synthetic PE32+ images (headers, sections,
  imports, relocations) so the loader/exports/tool are testable without a Windows
  toolchain. 125 workspace tests.

## Driver-local runtime (implemented, Milestone 4 — `nt-driver-runtime`)

- The local NT runtime inside one Driver Host (spec §7.4): a guest-memory arena,
  the projected objects a loaded driver sees, the driver pool, UTF-16 strings,
  IRQL/event/spinlock stubs, and pointer validation. `no_std` + `alloc`, no `unsafe`.
- **Arena** (`arena.rs`): a bump allocator over a byte buffer modelling the Driver
  Host address space; objects are addressed by `GuestAddr` (`base + offset`), and
  typed reads/writes are bounds-checked + **unaligned** (`pod_read_unaligned`), so
  the 16-aligned `DEVICE_OBJECT`/`IRP` projections are safe at arbitrary offsets.
- **Projections** (`DriverRuntime`): `create_driver_object` / `create_device_object`
  (+ `DeviceExtension` region) / `create_irp` (+ stack locations) build the M1
  layouts in the arena. The `ObjectTable` tracks each projection's guest address,
  kind, and the **canonical id** it stands for (set by the I/O Manager in M6), with a
  `retire()` that makes a deleted object's pointer stale.
- **Pointer validation** (spec §19.2/§19.3): `validate(addr, kind)` accepts only a
  live projection of the expected kind at exactly `addr`; `validate_driver_object`,
  `validate_writable(addr, len)` (output params), and `is_known_pointer` round it
  out. A valid-looking pointer grants access only to the local projection — never
  canonical authority. Stale (retired), foreign (outside-arena), and wrong-kind
  pointers are all rejected.
- **Pool** (`pool.rs`, spec §13): `ExAllocatePoolWithTag`/`ExFreePoolWithTag` over
  the arena, with `DoubleFree` / `UnknownPointer` traps and an `unload_report()` that
  lists leaked blocks (`addr`, `size`, tag) + live devices.
- **Strings** (`strings.rs`): allocate/read a `UNICODE_STRING` + UTF-16LE buffer.
- **IRQL / events** (`sync.rs`, spec §14): a simulated single-CPU `Irql`
  (raise/lower + invalid-transition counter) and a `PKEVENT`-keyed `EventTable`
  (init/set/clear/reset with previous-state), tracked runtime-side. 134 workspace
  tests.

## DriverEntry call gate (implemented, Milestone 5 — `nt-driver-host`)

- Orchestrates the v0.1 load path (spec §9): `DriverHost::load` parses the `.sys`
  with `nt-pe-loader`, resolves **every** import against the export set and fails
  with `BlockedImports` before any execution (§9 step 5), maps + relocates the
  image, patches each IAT slot to a bound export trampoline (§9 steps 7–8), and
  creates the `DRIVER_OBJECT` + UTF-16 `RegistryPath` projections in the runtime.
- `DriverHost::start` calls `DriverEntry` through a `DriverEntryGate` and captures
  the `MajorFunction` dispatch table + `DriverUnload` the driver installed; on a
  failure `NTSTATUS` it cleans up the partial projections (retires them) and marks
  the driver `Failed` (§9 failure path).
- **The call gate is abstracted** (spec §8.1): `MockGate<F>` runs a Rust closure so
  host tests exercise the gate + capture + cleanup logic without executing x64 code
  (this build host is aarch64); `Win64Gate` (cfg `x86_64`) transmutes the mapped
  entry point to an `extern "win64" fn(u64, u64) -> i32` and calls it — the real
  path, proven in QEMU (M9). The single `unsafe` block carries a `SAFETY:` note.
- Verified: a synthetic driver importing supported exports loads (3 trampolines
  bound + IAT patched), a mock `DriverEntry` installs CREATE/CLOSE/DEVICE_CONTROL +
  unload and the host captures them, an `IoConnectInterrupt` import blocks the load,
  and a failing `DriverEntry` retires the projections. 138 workspace tests.

## Device/symlink bridge (implemented, Milestone 6 — `nt-driver-abi`, `nt-driver-host` services)

- `nt-driver-abi`: the `DH_OP_*` SURT protocol (spec §7.5) — opcodes `0x3000..=0x30ff`
  (control/status, IRP dispatch/complete/cancel/buffer, device + symbolic-link
  creation, trace) + fixed-layout Pod request/reply structs (`DhCreateDeviceRequest`
  + inline UTF-16 name, `DhCreateDeviceReply` with the canonical ids,
  `DhSymbolicLinkRequest`, `DhDeleteDeviceRequest`, `DhStatusReply`) with size asserts.
- The driver-callable exports (spec §11), on `DriverServices` — the runtime + an
  `IoManagerBridge` a driver reaches (via trampolines on the kernel; called directly
  from the mock `DriverEntry` in host tests):
  - `io_create_device` validates the `DriverObject` + output pointer, reads the
    `DeviceName`, creates the local `DEVICE_OBJECT` projection, forwards a
    `BridgeCreateDevice` to the I/O Manager, stores the returned canonical `DeviceId`
    in the projection (`set_canonical_id`), and writes the `PDEVICE_OBJECT` out.
  - `io_create_symbolic_link` / `io_delete_symbolic_link` / `io_delete_device` /
    `rtl_init_unicode_string`.
- The `DriverEntryGate` now passes `DriverServices` (was raw `Arena`), so the driver
  can call these exports; `start(gate, bridge)` wires the bridge in. `NullBridge`
  serves drivers that create no devices.
- Verified end-to-end: a synthetic driver's `DriverEntry` creates `\Device\SurtTest0`
  + `\??\SurtTest0` through a bridge backed by the **real `nt-io-manager`**, and the
  I/O Manager then **opens the device by symlink** — plus a bogus `DriverObject`
  pointer is rejected and the canonical `DeviceId` lands in the local projection.
  140 workspace tests.

## IRP dispatch end-to-end (implemented, Milestone 7 — `nt-driver-host` dispatch)

- The other direction of the driver path (spec §10): the I/O Manager dispatches an
  IRP, the loaded driver's `MajorFunction[major]` runs, and the IRP completes.
- `DriverHost::dispatch_irp(gate, bridge, req, io_buffer)` (a `DH_OP_DISPATCH_IRP`):
  resolves the local `DEVICE_OBJECT` from the canonical `DeviceId`, checks the
  captured dispatch table, stages `io_buffer` into a `SystemBuffer`, builds the
  local `IRP` + `IO_STACK_LOCATION` (major/minor/device + `DeviceIoControl`
  parameters), calls `MajorFunction[major]` through the dispatch gate, and returns
  `Completed` / `Pending` / `Failed`. On completion the driver's `SystemBuffer`
  output is mirrored back (`METHOD_BUFFERED`, spec §12).
- The dispatch gate mirrors the entry gate: `MockDispatchGate<F>` runs a Rust
  closure (host tests); `Win64Gate::call_dispatch` transmutes the captured routine
  to an `extern "win64" fn(PDEVICE_OBJECT, PIRP)` (real path, QEMU/M9).
- Exports: `io_get_current_irp_stack_location` (reads `Irp.CurrentStackLocation`)
  and `io_complete_request` / `IofCompleteRequest`. Completion is tracked in the
  runtime and enforced **exactly once** (spec §10.2) — a second completion, an
  unknown IRP, or a non-IRP address all fail.
- Verified: `IRP_MJ_CREATE`/`CLOSE`/`DEVICE_CONTROL` reach the driver, the buffered
  echo of `"ping"` round-trips, double-completion + unknown-IRP completion are
  rejected, and — end to end over the **real `nt-io-manager`** — a client `open` by
  symlink reaches the driver's CREATE and `device_control` echoes `"ping"` back
  through the loaded driver (a `DriverHostBackend` bridging the I/O Manager's
  `DriverDispatchBackend` to `dispatch_irp`). 143 workspace tests.

## Pending + cancel (implemented, Milestone 8 — `nt-driver-host` dispatch)

- The async IRP cases (spec §10.2, §10.3, §17). A driver marks an IRP pending
  (`io_mark_irp_pending` → `PendingReturned`) and returns `STATUS_PENDING`;
  `dispatch_irp` returns `Pending` and records the IRP in the pending table
  (keeping it tracked).
- `complete_pending(irp_id, status, information)` models the driver's deferred
  DPC/worker calling `IoCompleteRequest`: it writes the `IoStatus`, completes the
  IRP (exactly-once), and queues a `DhCompletion`. `cancel_irp(irp_id)`
  (`DH_OP_CANCEL_IRP`) completes a still-pending IRP with `STATUS_CANCELLED`
  (v0.1 — cancel-routine invocation deferred). `poll_completion` drains ready
  completions for the I/O Manager's pump.
- **Exactly one final state** (spec §10.2/§10.3): completion and cancel both go
  through the runtime's exactly-once `complete_irp`, so whichever wins the race
  produces the single delivered completion and the loser is a no-op — verified in
  both orders.
- `fault()` fails every pending IRP with `STATUS_DEVICE_REMOVED` (so the I/O Manager
  can finalize them) and marks the driver `Faulted`; a faulted driver rejects new
  dispatch (spec §17). 148 workspace tests.
