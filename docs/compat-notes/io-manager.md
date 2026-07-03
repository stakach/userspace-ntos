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
