# NT I/O Manager — behavioural compatibility notes

Running notes on how this I/O Manager matches (or deliberately diverges from) NT
behaviour. Companion to the Object Manager notes; see `references/nt-io-manager-spec.md`.

## Wire ABI (implemented, Milestone 1 — `nt-io-abi`)

- Two reserved SURT opcode ranges: client-facing `IO_OP_*` (`0x3000..=0x30ff`) and
  I/O Manager ↔ driver-peer `IODRV_OP_*` (`0x3100..=0x31ff`, split into a
  driver-direction `0x3100..` block and a peer-direction `0x3180..` block).
- `IRP_MJ_*` major-function codes use the public WDK values (0x00 CREATE … 0x1b PNP,
  `IO_MAJOR_FUNCTION_COUNT` = 0x1c). IOCTL `ctl_code`/`device_type`/`function`/
  `method`/`access` follow the `CTL_CODE` bit layout; `METHOD_BUFFERED` is the only
  method v0.1 will honour.
- I/O ids (`DriverId`/`DeviceId`/`FileId`/`IrpId`/`IoRequestId`) are
  generation-protected `u64`s with the **same 24-bit gen / 40-bit slot split** as the
  Object Manager's ids — a stale id never resolves. On the wire they are plain `u64`;
  the runtime store (M2) does the packing + validation.
- Request/reply structs are `#[repr(C)]` + `bytemuck::Pod` (safe byte<->struct, no
  `unsafe`). `Pod` forbids padding, so fields are ordered gap-free with explicit
  `_reserved` — this is our own client/server wire, **not** a Windows binary layout,
  so field order may differ from the spec's illustrative structs. Variable payloads
  (paths, buffers) live in separate SURT registered buffers referenced by
  id/offset/len; paths are UTF-16LE. Compile-time `size_of`/`align_of` asserts guard
  every struct.
- New `nt-status` codes for I/O: `INVALID_DEVICE_REQUEST`, `CANCELLED`,
  `DEVICE_NOT_CONNECTED`, `FILE_CLOSED`, `BUFFER_TOO_SMALL`, `END_OF_FILE`.

## Core records + stores (implemented, Milestone 2 — `nt-io-manager`)

- **`GenStore<I, T>`** (`store.rs`) is a generation-protected slot-map: `insert`
  returns a fresh id, `remove` bumps the slot's generation so any surviving id no
  longer resolves. Same 24/40 gen/slot scheme as the Object Manager; `IoId` is a
  small trait implemented for the `nt-io-abi` id types. No `unsafe`, no OM coupling.
- **`DriverRecord`** carries the `MajorFunctionTable` (per-major `DispatchTarget`:
  `Unsupported` / `Mock(MockDispatchId)` / `DriverPeer(DriverPeerId)` — never a raw
  function pointer, spec §10.2), a device list, a backend id, flags, and unload state.
- **`DeviceRecord`** carries `DeviceType` (`FILE_DEVICE_*`), characteristics, flags
  (`DO_BUFFERED_IO`/`DO_DIRECT_IO`), and single-device-stack fields (`top_of_stack ==
  id`, `attached_to == None` in v0.1).
- **`FileRecord`** + **`FileState`** machine (`Allocated → CreateIrpDispatched → Open
  → CleanupPending → CleanupComplete → ClosePending → Closed`). The spec's separate
  `cleanup_done`/`close_done` booleans are subsumed by the state enum, which keeps
  cleanup and close distinct (spec §12.2). Illegal transitions are rejected + tested.
- **`IrpRecord`** + **`IrpState`** machine (`Allocated → Initialized → Queued/
  Dispatched → Pending → CancelRequested/Completing → Completed/Cancelled/Failed →
  Freed`), the `IoStackLocation` + `IoParameters` per-major payloads (only the v0.1
  variants are functional), `CancelState`, and `IoBufferRef` (a validated registered-
  buffer reference — never a raw pointer). Exactly the allowed transitions pass; e.g.
  `Completed → Completed` is rejected (no double-completion).
- **`IoManager`** owns the four stores + record CRUD; `add_device` links the device
  into the driver's list and stamps `top_of_stack`. Higher-level create/open/read
  APIs (with Object Manager integration) arrive in M3+. A store proptest asserts
  live ids resolve, removed ids stay stale, and counts stay consistent over random
  insert/remove sequences.

## Object Manager integration (implemented, Milestone 3 — `object_port.rs`)

- **`ObjectManagerPort`** is the trait through which the I/O Manager reaches the
  Object Manager (spec §8): register/close a client, create Driver/Device objects,
  resolve a device path (following symlinks), create/delete symbolic links, the
  brokered **create-File-object-and-handle-for-a-client** (§8.4), reference a File
  by handle for a client (access-checked), reference a Device, and close a handle.
  The I/O Manager never owns identity/names/handles — it only keeps the returned
  `ObjectId`s/`HandleValue`s.
- **`MockObjectPort`** — an in-memory fake (assigns object ids + handles, tracks
  named devices/drivers, symlinks, and per-client handles, exact + symlink path
  resolution). Unblocks host tests of the dispatch/open/read/write paths (M4-M6).
- **`ObjectManagerLibraryPort`** (feature `object-manager`, deps `nt-object-manager`)
  — the real in-process adapter (library mode: I/O Manager + Object Manager share a
  node). It maps the trait onto the actual OM: `create_driver`/`create_device`/
  `create_file` + `open_handle` + `reference_by_handle`/`reference_by_id` +
  `create_symbolic_link`/`remove_named_object` + `lookup_path` (splitting a full NT
  path into parent-dir + leaf). Tested against a real bootstrapped `ObjectManager`:
  create `\Driver\Test` + `\Device\Test0`, link `\??\Test0`, open by both paths,
  brokered file+handle, reference back for the client.
- The brokered "create object + handle for a target client" (§8.4) is satisfied by
  composing OM `create_file` + `open_handle` in the adapter; no new OM opcode was
  needed for library mode. A service-mode executive path (over SURT) is deferred to
  the client-facing server milestone.

## Dispatch backend + mock driver (implemented, Milestone 4 — `dispatch.rs`, `mock_driver.rs`)

- **`DriverDispatchBackend`** is the pluggable seam between the I/O Manager and a
  driver (spec §15.1): `dispatch_irp(ctx, &IrpProjection) -> DispatchOutcome` +
  `cancel_irp(IrpId)`. The backend receives an **`IrpProjection`** — ids + the
  current stack location's parameters, never the canonical `IrpRecord` — plus a
  `DispatchContext` carrying the buffered-I/O staging buffer (`SystemBuffer`).
- **`DispatchOutcome`** = `Completed { status, information }` | `Pending` |
  `Failed { status }`, with `from_status` mapping an `NtStatus` (success→Completed,
  error→Failed).
- **`MockDriverBackend`** (spec §15.2) is the in-process test/bring-up backend,
  deterministic + configurable: create succeeds/fails (`set_create_status`), reads
  return fixed data (`with_read_data`, filling the system buffer), writes record the
  bytes (`written()`), IOCTLs echo their input or return a fixed status
  (`IoctlBehavior::Echo | Status`), any dispatch can be forced `Pending` then
  finished with `complete_pending(irp, status, info)`, `cancel_irp` marks a pending
  IRP cancelled, and `inject_error` fails everything. Cleanup/close/flush complete
  success; an unknown major returns `STATUS_INVALID_DEVICE_REQUEST`.
- Buffered echo models `METHOD_BUFFERED`: input occupies the system buffer and the
  output is those same bytes bounded by the output length. The router that maps a
  major function to a backend, and the actual buffer staging, are wired up in M5/M6.
- `NtStatus` now derives `Default` (= `STATUS_SUCCESS`).

## Open / create path (implemented, Milestone 5 — `open.rs`)

- `IoManager` is now generic over the Object Manager port `P` and owns a registry
  of dispatch backends (`Vec<Box<dyn DriverDispatchBackend>>`). `register_client`
  delegates to the port so a client's canonical handles live in the Object Manager.
- **`create_driver`** (spec §10.3) registers the driver's dispatch backend + a
  `\Driver\Name` object and routes the v0.1 majors to that backend via the
  `MajorFunctionTable`. **`create_device`** (`IoCreateDevice`, §11.3) creates the
  `Device` object (named under `\Device`, or unnamed) owned by a driver.
  **`create_symbolic_link`** (§11.4) delegates to the Object Manager.
- **`open`** (spec §12.3) is the create path: resolve the Device object through the
  Object Manager (symlink-following), allocate a `FileRecord`, broker the OM File
  object + a handle for the client (§8.4), build + dispatch an `IRP_MJ_CREATE` to
  the device's driver backend (routed via the driver's `MajorFunctionTable` — an
  `Unsupported` major → `STATUS_INVALID_DEVICE_REQUEST`, a `DriverPeer` target →
  `STATUS_NOT_IMPLEMENTED` until M8), and on synchronous success move the file to
  `Open`, free the IRP, and return the handle. On any failure (driver failure, bad
  create status, error) it **closes the handle, removes the FileRecord, and frees
  the IRP** — no reference or record leaks (verified against the real Object
  Manager: a failed open leaves `live_object_count` unchanged). v0.1 completes
  creates synchronously; a `Pending` create returns `STATUS_NOT_SUPPORTED` pending
  the completion engine.
- Verified: `\Device\Test0` and `\??\Test0` (symlink) both open through the mock
  driver, and end-to-end against a real bootstrapped `ObjectManager`.

## Read / write / device-control (implemented, Milestone 6 — `read_write.rs`, `device_control.rs`)

- Every data request references the client's File handle through the Object
  Manager, access-checked (`reference_open_file`): read requires `GENERIC_READ`,
  write `GENERIC_WRITE`, an IOCTL the access from its `CTL_CODE` bits. The
  FileRecord must be in the `Open` state, else `STATUS_FILE_CLOSED`; a bad handle
  is `STATUS_INVALID_HANDLE`, insufficient access `STATUS_ACCESS_DENIED`.
- The shared synchronous path (`build_and_dispatch_sync` + `complete_sync`) builds
  the IRP + stack location, attaches an `IoBufferRef`, dispatches to the driver
  backend, and on synchronous completion frees the IRP and returns
  `IoStatus.Information`. A failure fails + frees the IRP; a `Pending` outcome parks
  the IRP and returns `STATUS_PENDING` (the completion engine that finishes pending
  IRPs is a later milestone). Transfers are bounded (`validate_transfer`, 64 KiB).
- **Buffered model only** (`METHOD_BUFFERED`, spec §14.2). Read stages a zeroed
  `SystemBuffer` the driver fills; write stages a copy of the client data; an IOCTL
  stages one buffer sized `max(input, output)` holding the input, then copies the
  driver's output back. `METHOD_IN_DIRECT`/`OUT_DIRECT`/`NEITHER` →
  `STATUS_NOT_SUPPORTED`.
- The mock driver is a loopback for tests: a write records the bytes and makes them
  the data a subsequent read returns, and an IOCTL echoes its input — so
  round-trips are observable through the I/O result (no backend downcast). Verified
  end-to-end against a real bootstrapped `ObjectManager` (write→read loopback + an
  echoing IOCTL through real OM handle validation).
