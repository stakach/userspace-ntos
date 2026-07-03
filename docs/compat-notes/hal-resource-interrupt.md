# NT HAL / Resource Manager / Interrupt — compatibility notes

The first hardware-shaped WDM driver path (spec: Milestone 11) — MMIO mapping,
register access, and interrupt connect/inject/disconnect, simulated first. See
`references/nt-hal-resource-interrupt-spec.md`. Test driver: `MmioInterruptTest.sys`
(github.com/stakach/ntdriver): maps a fake MMIO region at phys `0x10000000`, reads a
`0x4d4d494f` ("MMIO") ID register via inlined `READ_REGISTER_ULONG` (so the mapping
must be real Driver-Host memory), and connects an ISR on vector 5; a
`WAIT_FOR_INTERRUPT` IOCTL pends an IRP that an injected interrupt's ISR→DPC completes.

## HAL wire ABI (implemented, Milestone 11.1 — `nt-hal-abi`)

- `no_std`, no alloc, no seL4/Driver-Host dependency: pure `#[repr(C)]` wire types.
- Opcodes `HAL_OP_*` in the `0x5000..=0x50ff` range (spec §10); resource kinds,
  cache types, rights, interrupt mode/share constants.
- Structs: `HalResourceDescriptor` (56B; `interrupt_args`/`interrupt_fields` pack
  vector/irql/affinity/mode into `arg0`/`arg1`), `HalQueryDeviceResourcesReq`,
  `HalMapIoSpaceReq` (40B), `HalUnmapIoSpaceReq`, `HalConnectInterruptReq` (opaque
  ISR `*_token` fields — no raw pointers cross SURT, spec §6.2/§16.3),
  `HalDisconnectInterruptReq`, `HalInjectInterruptReq`. Static layout tests.
