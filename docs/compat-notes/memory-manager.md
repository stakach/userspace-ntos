# NT Memory Manager section objects + mapped views — compatibility notes

The NT Memory Manager section layer (spec: NT Memory Manager Section Objects + Mapped Views).
Section objects mapped into address-space views, kept coherent with the M23 Cache Manager.

## nt-memory-manager (implemented, Milestones 24.1-24.6)

- Section objects (§8): `zw_create_section_file` (file-backed, coherent via the Cache Manager) +
  `zw_create_section_pagefile` (anonymous committed zeroed memory, §9.3). Protection validation +
  `SEC_IMAGE` rejection (§8.3).
- Views (§10): `zw_map_view_of_section_file` materialises bytes from the stream's `SharedCacheMap`
  (`CcCopyRead`, Approach B §12.1), `zw_map_view_of_section_anon` gives a zeroed view,
  `mm_map_view_in_system_space` (§16). `view_read`/`view_write` are the mapped "pointer"
  (a view-local buffer); the Driver Host projects it into a real VA.
- Dirty writeback (§11.3, §15): `zw_unmap_view_of_section_file` writes a dirty writable view back
  through the cache (`CcCopyWrite`); a following `CcFlushCache` reaches the file. Anonymous unmap
  writes back to the section's committed memory (shared across views).
- Protection model (§17): PAGE_NOACCESS/READONLY/READWRITE/WRITECOPY — read-only views reject
  writes, NOACCESS views reject reads.
- 5 unit tests incl. the §24 acceptance (map file → edit through the view → unmap → flush → file
  reflects the edit), system-space mapping, anonymous section sharing, protection/access checks,
  partial-view offset.

## Mapped sections in QEMU (implemented, Milestone 24 — `configuration-manager`)

The `configuration-manager` component now also proves mapped sections bare-metal on seL4
(24/24 checks) — the §24 acceptance flow end-to-end: ZwCreateFile+write "abcdef" on MemFs →
ZwCreateSection (PAGE_READWRITE, SEC_COMMIT) over the file → ZwMapViewOfSection (materialises
"abcdef" from the cache) → edit "XYZ" at offset 1 through the view → ZwUnmapViewOfSection
(writeback → cache dirty) → CcFlushCache → ZwReadFile returns "aXYZef". Plus an anonymous
(pagefile) section shared across two views.
