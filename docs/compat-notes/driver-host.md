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
