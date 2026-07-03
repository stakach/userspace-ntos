# io-manager component

The NT I/O Manager as **two fully-isolated seL4 components** — a client and a
server, each with its own CSpace + VSpace — talking over **SURT rings** wired up by
a broker (the rootserver). The server component **embeds an in-process Object
Manager** (library mode) plus a mock driver; the client drives the full file path
across an address-space boundary.

## Run

```sh
# from the repo root:
./scripts/run-io-manager.sh
```

Expected tail:

```
[ntos-io] NT I/O Manager - isolated client/server over SURT
  PASS ping
  PASS open
  PASS write
  PASS read
  PASS device_control
  PASS cleanup
  PASS close
[ntos-io summary: 7 passed, 0 failed]
```

## How it works

- **Broker** (`src/main.rs`): identical to `components/object-service` — creates two
  SURT ring frames (submission `SurtSqe`, completion `SurtCqe`), two data frames
  (request / reply payloads), two notifications and a result endpoint; `init_ring`s
  both rings; maps everything RW into **both** child VSpaces at fixed vaddrs; seeds
  each child's CNode; spawns the two isolated TCBs; prints the summary + sentinel.
- **Server** (`src/server.rs`): builds an `IoManager` over an in-process
  `ObjectManagerLibraryPort`, registers `\Driver\Test` + `\Device\Test0` + the
  `\??\Test0` symlink and a mock driver, then a `drain_blocking` loop runs the
  **unchanged** `nt_io_server::IoServer::dispatch` and pushes each `IoReply` as a
  `SurtCqe`.
- **Client** (`src/client.rs`): a `SurtBackend` implements `nt_io_client::Backend`
  (copy request into the request frame, push a `SurtSqe`, wake the server, block for
  the completion, map the `SurtCqe` back to an `IoReply`, copy any read/IOCTL output
  from the reply frame). It drives the **unchanged** `IoClient`: ping, open by
  symlink, write, read (loopback), echoing IOCTL, cleanup, close.

The SURT descriptors carry the I/O protocol verbatim: `SurtSqe`(opcode + a slice of
the request frame) is an I/O request; `SurtCqe`(status/flags/information/detail0/
detail1) is an `IoReply` field-for-field. So the M7a server dispatcher and client
stub are reused as-is; only the transport is new.

## Notes

- **Heap**: `src/allocator.rs` — a 256 KiB static-region bump allocator (bigger than
  `object-service`'s 128 KiB since the server holds both an I/O Manager and an
  Object Manager). Counter lives in the RW heap (image `.bss` is mapped read-only in
  spawned components), single-threaded, no reclamation.
- **Scope**: one client ↔ one server, single request in flight (synchronous RPC),
  a mock driver. A real Driver Host peer over SURT is the next milestone (M8).
- Reuses the `components/object-service` cap-transfer machinery + the published
  `surt-sel4` crate.
