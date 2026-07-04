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
