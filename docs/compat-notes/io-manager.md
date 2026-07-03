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
