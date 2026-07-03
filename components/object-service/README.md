# object-service component

The NT Object Manager as **two fully-isolated seL4 components** — a client and a
server, each with its own CSpace + VSpace — talking over **SURT rings** wired up by
a broker (the rootserver). This is the hardened form of the in-process
`object-manager` component (M7b): the OB protocol now crosses a real
address-space boundary.

## Run

```sh
# from the repo root:
./scripts/run-object-service.sh
```

Expected tail:

```
[ntos-svc] NT Object Manager - isolated client/server over SURT
  PASS ping
  PASS create_directory
  PASS lookup
  PASS open
  PASS create_symbolic_link
  PASS lookup_via_symlink
  PASS query_symbolic_link
  PASS close_handle
[ntos-svc summary: 8 passed, 0 failed]
```

## How it works

- **Broker** (`src/main.rs`, `_start`): creates two SURT ring frames (submission
  `SurtSqe`, completion `SurtCqe`), two data frames (request / reply payloads), two
  notifications and a result endpoint; `init_ring`s both rings; maps everything RW
  into **both** child VSpaces at fixed vaddrs; seeds each child's CNode; spawns the
  two isolated TCBs; waits for the client's verdict; prints the summary + sentinel.
- **Server** (`src/server.rs`): `Consumer<SurtSqe>` + `Producer<SurtCqe>`; a
  `drain_blocking` loop reads each request from the shared request frame and runs
  the **unchanged** `nt_object_server::Server::dispatch`, then pushes an `ObReply`
  as a `SurtCqe` and writes any variable result into the reply frame.
- **Client** (`src/client.rs`): a `SurtBackend` implements
  `nt_object_client::Backend` — copy the encoded request into the request frame,
  push a `SurtSqe`, wake the server, block for the matching completion, map the
  `SurtCqe` back to an `ObReply`. It drives the **unchanged** `ObjectClient`.

The SURT descriptors carry the OB protocol verbatim: `SurtSqe`(opcode + a slice of
the request frame) is an OB request; `SurtCqe`(status/information/detail0/detail1)
is an `ObReply` field-for-field. So the M7a server dispatcher and client stub are
reused as-is; only the transport is new.

## Notes

- **Heap**: `src/allocator.rs` — a bump allocator whose counter lives in the **RW
  heap** (each component's image `.bss` is mapped read-only), 128 KiB per component,
  single-threaded so no atomics, no reclamation. Enough for a bounded bring-up.
- **Scope**: one client ↔ one server, single request in flight (synchronous RPC).
  The ring API supports more; multi-client / pipelined is future work.
- **Reuses** the proven cap-transfer machinery from `rust-micro/vendor/surt-demo`
  (spawn isolated component, build VSpace/CNode, seed caps) and the published
  `surt-sel4` crate for the ring transport.
