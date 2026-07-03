# driver-host component

The NT I/O Manager dispatching IRPs to a **separate, isolated driver-peer
component** over SURT — the on-kernel form of the driver-peer protocol (spec §16).
Two isolated seL4 components (own CSpaces + VSpaces), brokered by the rootserver:

- **io-side** — runs an `IoManager` over an in-process Object Manager, with a
  driver whose backend is a `DriverPeerBackend<SurtPeerTransport>`. It executes the
  file path (open / write / read / IOCTL / cleanup / close) on its own I/O Manager;
  each IRP is marshalled to the peer over SURT.
- **peer** — an isolated, untrusted "driver": it consumes `IODRV_OP_DISPATCH_IRP`
  requests, decodes the `IrpDispatchRequest` from the shared data frame, simulates
  a driver by major function, and pushes a final completion. It needs no heap.

## Run

```sh
# from the repo root:
./scripts/run-driver-host.sh
```

Expected tail:

```
[ntos-dh] NT I/O Manager - dispatch to isolated driver peer over SURT
  PASS open
  PASS write
  PASS read
  PASS device_control
  PASS cleanup
  PASS close
[ntos-dh summary: 6 passed, 0 failed]
```

## How it works

- **Broker** (`src/main.rs`): the same cap-transfer machinery as
  `components/object-service` / `components/io-manager` — a SURT ring pair
  (submission `SurtSqe`, completion `SurtCqe`) + a shared data frame + two
  notifications, mapped RW into both isolated children.
- **`SurtPeerTransport`** (io-side, in `src/io_side.rs`) implements
  `DriverPeerTransport`: stage `[IrpDispatchRequest][buffer]` into the data frame,
  push an `IODRV_OP_DISPATCH_IRP` SQE, wake the peer, block for the dispatch CQE,
  copy the peer's output back, map to a `DispatchOutcome`. The `IoManager` +
  `DriverPeerBackend` are reused **unchanged**; only the transport is new.
- **`src/peer.rs`** decodes the wire `IrpDispatchRequest` directly (no heap) and
  simulates the driver: create OK, read returns `b"peerread"`, write/IOCTL succeed.

## Notes

- **Scope**: synchronous completion only. Pending / cancel / peer-fault handling
  are host-tested in `nt-io-manager` (M8a) but not exercised over the ring here.
- The `SurtSqe`/`SurtCqe` carry the IODRV protocol verbatim (`SurtSqe` = an
  `IODRV_OP_DISPATCH_IRP` + the request/buffer slice; `SurtCqe` = the dispatch
  response with `IODRV_CQE_FINAL`).
- Reuses the broker + 256 KiB bump allocator (only the io-side allocates; the peer
  is heap-free).
