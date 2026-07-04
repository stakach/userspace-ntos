# DMA Manager — compatibility notes

The NT DMA Manager (spec: NT DMA/MDL/IOMMU, Milestone 14). Test driver
`DmaPnpPowerTest.sys`: `IoGetDmaAdapter` → `DMA_ADAPTER.DmaOperations`
(`AllocateCommonBuffer`@16, `FreeCommonBuffer`@24, `PutDmaAdapter`@8); a common
buffer with a fake logical address the simulated device decodes to invert its bytes.

## DMA ABI + Manager (implemented, Milestones 14.2/14.3 — `nt-dma-abi`, `nt-dma-manager`)

- `nt-dma-abi`: opcodes `DMA_OP_*` (0x8000..=0x80ff), direction constants,
  `#[repr(C)]` `DmaAllocCommonBufferReq` / `DmaMapTransferReq`. Opaque `u64` IDs. 3 tests.
- `nt-dma-manager`: `register_adapter` (`IoGetDmaAdapter`, 64 map registers, §9.5),
  `put_adapter`; `alloc_common_buffer` (`AllocateCommonBuffer` — owner + active +
  length ≤ adapter max + address-bit limit, assigns a **fake logical address** never a
  real host physical address, §10.4), `free_common_buffer` (owner + length validated,
  double-free rejected), `map_transfer` (clips to adapter max), `free_mapping`,
  `revoke_owner` (fault/remove cleanup, §15.3). `decode_logical` is the **IOMMU-facade
  lookup** (§19.2): resolves a device logical address to its backing Driver-Host
  address only within a live common buffer / active mapping — a device cannot reach
  unowned memory. 5 tests.

## Driver Host DMA integration (implemented, Milestones 14.4-14.9 — `driver-host-dma`)

`components/driver-host-dma` loads the real `DmaPnpPowerTest.sys` (W^X + NX) and drives
the full DMA lifecycle against in-process PnP + Power + DMA + MDL managers. **21/21 checks
pass in QEMU, no #GP.**

- `IoGetDmaAdapter` builds a `DMA_ADAPTER` {Version@0, Size@2, DmaOperations@8} + a
  `DMA_OPERATIONS` table {Size@0, PutDmaAdapter@8, AllocateCommonBuffer@16,
  FreeCommonBuffer@24}; unused slots are null (the driver null-checks). `register_adapter`
  reports 64 map registers.
- `AllocateCommonBuffer` returns a **page-aligned** common buffer (a dedicated static; real
  `AllocateCommonBuffer` is page-aligned) + writes the fake logical address; the sim DMA
  device (`run_dma_command`) reads the programmed DMA regs, decodes the logical address via
  the DMA Manager (IOMMU facade), inverts the common buffer, then interrupts → ISR → DPC
  completes the roundtrip IRP.
- MDL exports: `IoAllocateMdl` (stashes the registry ID in the MDL's `Next` field),
  `MmBuildMdlForNonPagedPool` (sets `MDL_SOURCE_IS_NONPAGED_POOL` + `MappedSystemVa`),
  `IoFreeMdl`, `MmMapLockedPagesSpecifyCache` (fallback), `ExAllocatePoolWithTag`.
  `MmGetSystemAddressForMdlSafe` is inline in the driver — reads the flags/`MappedSystemVa`.
- `METHOD_OUT_DIRECT` IOCTL: `dispatch_direct` builds an MDL over the output buffer + sets
  `IRP->MdlAddress`@8; the driver fills it via `MmGetSystemAddressForMdlSafe`.
- Checks: `dma_adapter_and_common_buffer`, `ioctl_get_id` (0x444d4131 "DMA1"), `dma_info`
  (64 map regs / 4096 common buffer / allocated), `mdl_self_test`, `common_buffer_roundtrip`,
  `direct_buffer_fill_via_mdl`, `dma_rejected_in_d3`, `dma_resumes_in_d0`, `remove_revokes_dma`.

### Lesson: the /GS cookie top-16-bits invariant

START faulted with `int 0x29` / `ecx=2` (FAST_FAIL_STACK_COOKIE_CHECK) at
`DmaPnpStartHardware`'s epilogue. Root cause was **not** stack corruption: the seeded
`__security_cookie` (`0x1234_...`) had non-zero top 16 bits, which MSVC's x64
`__security_check_cookie` rejects (`rol; test cx,0xffff`). `DmaPnpPowerTest.sys` is the
first fixture whose codegen emits that check. Fixed by centralizing the seed in
`nt-pe-loader::SECURITY_COOKIE_SEED` (top bits zero). See `nt-pe-loader`.
