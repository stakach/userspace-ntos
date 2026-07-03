# object-manager component

The NT Object Manager running as a **seL4 component** on the rust-micro kernel —
a standalone bare-metal root task the kernel boots. It provides a heap (a bump
global allocator), creates the Object Manager service (`nt-object-server`), and
drives it through the real client stub (`nt-object-client`), proving the whole NT
object stack runs on seL4.

## Run

```sh
# from the repo root:
./scripts/run-object-manager.sh
```

Builds the component (staging it as the kernel's rootserver), builds the kernel
via the `rust-micro` submodule in `extern-rootserver` mode, and boots QEMU.
Expected tail:

```
[ntos-om] NT Object Manager on rust-micro (in-process service dispatch)
  PASS server_bootstrap
  PASS ping
  PASS create_directory
  PASS lookup
  PASS open
  PASS create_symbolic_link
  PASS lookup_via_symlink
  PASS query_symbolic_link
  PASS close_handle
[ntos-om summary: 9 passed, 0 failed]
```

## Notes

- **Heap**: a 128 KiB static-region bump allocator (`src/allocator.rs`), atomic so
  the timer can't corrupt it mid-allocation, no reclamation — enough for a bounded
  bring-up. A real deployment wants a reclaiming allocator over a runtime-mapped
  heap.
- **Transport**: the client drives the service **in-process** here (the whole
  stack on one node). Splitting client and server into separate isolated
  components talking over a SURT ring / control endpoint (with capability
  transfer) is the next hardening step — the `vendor/surt-demo` cap-transfer
  scenario in rust-micro is the reference for that machinery.
- Built for the kernel's bare-metal target with `-Z build-std=core,alloc`
  (`compiler-builtins-mem` for memcpy/memset); own workspace, excluded from the
  host test workspace.
