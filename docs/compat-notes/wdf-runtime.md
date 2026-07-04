# KMDF / WDF runtime — compatibility notes

The first Kernel-Mode Driver Framework compatibility layer (spec: NT KMDF/WDF Runtime).
Target driver `KmdfBasicTest.sys` — KMDF **v1.15**, binds via `WDFLDR.SYS` (`WdfVersionBind`
fills the driver's `WdfFunctions` table + `WdfDriverGlobals`), then WDF calls go through
`WdfFunctions[index](WdfDriverGlobals, ...)`. FuncCount = 444 (`WdfFunctionTableNumEntries`).
Authoritative headers: `references/windows-kits/10/Include/wdf/kmdf/1.15/`.

## WDF object core (implemented, Milestone 1 — `nt-wdf-object`)

- `WdfHandle` = `[type:8 | generation:24 | slot:32]`, never zero for a live object; opaque
  to the driver. Generation-validated so a stale/reused slot is rejected (spec §8.2).
- `WdfObjectTable`: `create` (typed, optionally parented), `validate`/`object_type`/`parent`,
  `reference`/`dereference` (refcount, spec §7.4), `set_callbacks`, `set_context`/`get_context`
  (one typed context per object, spec §18), `delete`. Handle validation rejects
  Null/Stale/WrongType/Deleted.
- Parent/child tree: a driver owns devices, a device owns queues (spec §7.3). `delete` walks
  children **depth-first** and returns the ordered `PendingCallback` list (cleanup before
  destroy, each once) for the runtime to invoke **after** the table borrow is released — the
  Driver Host re-entrancy discipline. Destroy is deferred until the last reference drops.
- 5 unit tests: create/validate/wrong-type/stale, depth-first delete, cleanup→destroy order,
  deferred destroy, context storage.
