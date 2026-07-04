# MDL — compatibility notes

Memory Descriptor List support for DMA (spec: NT DMA/MDL/IOMMU, Milestone 14, §8).
Test driver `DmaPnpPowerTest.sys` uses `IoAllocateMdl` + `MmBuildMdlForNonPagedPool`
+ `MmGetSystemAddressForMdlSafe`, and a `METHOD_OUT_DIRECT` IOCTL for `IRP->MdlAddress`.

## MDL (implemented, Milestone 14.1 — `nt-mdl`)

- WDK `MDL` x64 layout: `Next`@0, `Size`@8, `MdlFlags`@10, `Process`@16,
  `MappedSystemVa`@24, `StartVa`@32, `ByteCount`@40, `ByteOffset`@44. Flag bits
  `MDL_MAPPED_TO_SYSTEM_VA`=0x0001, `MDL_SOURCE_IS_NONPAGED_POOL`=0x0004.
- `MmGetSystemAddressForMdlSafe` is an **inline macro** — with
  `MDL_SOURCE_IS_NONPAGED_POOL` set it returns `MappedSystemVa` directly, so a Driver
  Host that fills those fields in `MmBuildMdlForNonPagedPool` needs no
  `MmMapLockedPagesSpecifyCache` call.
- `MdlRegistry`: `allocate` (`IoAllocateMdl`, records va/byte_count/byte_offset),
  `build_for_nonpaged` (locks), `validate_slice` (locked + in-range), `add/remove_mapping`,
  `free` (`IoFreeMdl` — rejects `ActiveMappings`, spec §8.4). Stale IDs rejected. 4 tests.
