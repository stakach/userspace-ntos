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
