# NT I/O Manager — architecture

The I/O Manager is the second executive component (after the Object Manager). It
owns canonical I/O state — driver / device / file / IRP records, dispatch routing,
completion, cancellation — and goes *through* the Object Manager for all object
identity, naming, handles, and references (it never bypasses it).

## Crates

```
nt-io-abi       fixed-layout wire ABI: opcodes, request/reply structs, IRP major
                + IOCTL constants, generation-protected id types, Driver Host
                projection records. no_std, no allocation, no seL4/OM dependency.
nt-io-manager   the core: generation-protected stores (driver/device/file/IRP),
                the file + IRP state machines, the ObjectManagerPort trait, the
                DriverDispatchBackend (mock + driver-peer), open/read/write/IOCTL/
                cleanup/close, and the completion + cancellation engine. no_std +
                alloc, single-threaded (&mut self), zero unsafe.
nt-io-server    transport-agnostic service dispatcher over the wire ABI.
nt-io-client    ergonomic client stub over a pluggable transport backend.
components/
  io-manager    the I/O Manager as isolated seL4 components over SURT (the server
                embeds an in-process Object Manager).
```

## Ownership split (spec §8.2)

```
object identity / name / type / handles / references  -> Object Manager
driver / device / file I/O records                    -> I/O Manager
IRP state                                             -> I/O Manager
driver execution / runtime state                      -> Driver Host (later)
```

The Object Manager objects for Driver / Device / File carry an opaque routing body
(`owner_component` + `owner_local_id`) that points back to the I/O Manager's
`DriverId` / `DeviceId` / `FileId`.

## Request lifecycle

```
client -> IoServer::dispatch -> IoManager
  open:  resolve Device object (OM, symlink-following)
         -> broker File object + handle for the client (OM)
         -> IRP_MJ_CREATE -> driver backend -> handle
  read/write/ioctl:  reference File handle (OM, access-checked)
         -> stage buffered SystemBuffer -> IRP -> backend -> completion
  cleanup/close:  IRP_MJ_CLEANUP/CLOSE -> release OM handle + drop FileRecord
```

Backends are pluggable via `DriverDispatchBackend`: a `MockDriverBackend`
(in-process, deterministic) or a `DriverPeerBackend` that marshals an
`IrpDispatchRequest` to an isolated, untrusted Driver Host peer over SURT. A
completion is delivered synchronously or, for a pending IRP, on the peer's reverse
ring (drained by `pump`). Every IRP has exactly one final completion; cancellation
races with completion are finalized exactly once. A peer fault fails its in-flight
IRPs and marks its devices delete-pending, leaving unrelated drivers untouched.

## Driver Host readiness (spec §20)

The wire projection records (`DriverObjectProjection` / `DeviceObjectProjection` /
`FileObjectProjection` / `IoStackLocationProjection` + `IrpDispatchRequest`) are
the stable, ids-only view a Driver Host peer receives. The `DriverHostRoutine`
plan enumerates the `Io*` support routines a future Driver Host runtime will
provide, their MVP status, and the export names for a future `nt-compat-exports`
crate — so the Driver Host can build on this I/O Manager without redesigning IRP
ownership.
