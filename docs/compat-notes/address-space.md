# NT Memory Manager address space + fault handling — compatibility notes

The demand-paging layer beneath the section objects (spec: NT Memory Manager Address Space +
Fault Handling). Address spaces with VAD trees + a page-fault resolver over the M23 Cache Manager.

## nt-address-space (implemented, Milestones 25.1-25.7)

- AddressSpace (§7.1): VA bounds, 4 KiB pages, 64 KiB allocation granularity, a VAD tree, commit
  accounting (charge on reserve, release on unmap, COMMITMENT_LIMIT enforcement §17).
- VA allocation (§9): `reserve_view` first-fit free-region search (granularity-aligned) or a
  caller base with overlap detection (CONFLICTING_ADDRESSES). Demand mode: pages start
  CommittedNotResident.
- Fault resolver (§12): `fault` (section-backed — materialises the page from the stream's cache
  via CcCopyRead), `fault_anonymous` (zero-fill), with access-violation (no VAD / NOACCESS) +
  protection (write to read-only) checks; write faults mark the page dirty (§12.4).
- Demand access: `read`/`write` fault pages in on touch (a reserved view is not resident until
  read). `unmap_view` writes dirty resident pages back through the cache (CcCopyWrite) + releases
  commit; `unmap_anonymous` drops private pages.
- MDL (§15): `mm_probe_and_lock_pages` (fault-in + verify access + lock), `mm_unlock_pages`.
- 7 unit tests: VA allocation + overlap, demand paging faults on touch, the mapped-edit acceptance
  through the fault path, anonymous zero-fill, access violations (unreserved/read-only/NOACCESS),
  commit-limit enforcement, MDL probe/lock/unlock.

## Demand paging in QEMU (implemented, Milestone 25 — `configuration-manager`)

The `configuration-manager` component now also proves demand paging bare-metal on seL4
(27/27 checks): over a MemFs-backed cache it reserves a section view (0 pages resident), reads
through the fault path (the page materialises → "abcdef", 1 page resident), raises an access
violation faulting an unreserved VA, then edits through the write-fault path, unmaps (dirty
writeback → CcCopyWrite) + flushes → the MemFs file reads "aXYZef", and commit is released.
