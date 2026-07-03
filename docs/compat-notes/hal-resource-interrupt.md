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

## Resource Manager (implemented, Milestone 11.2 — `nt-resource-manager`)

- `ResourceManager` is the canonical assignment store (spec §7/§8/§9). `no_std` +
  `alloc`, works purely in physical addresses + opaque IDs — no driver code, no raw
  pointers (spec §16).
- `with_mmio_test_fixture(owner)` builds the `MmioInterruptTest` static fixture
  (memory phys `0x1000_0000` len `0x1000` RW non-cached; exclusive level-sensitive
  interrupt vector 5).
- `map_io_space` succeeds only if `[phys, phys+len)` lies within a memory resource
  **assigned to that owner**, not revoked, with read rights (spec §6.1) — else
  `NotAssigned`/`OutOfRange`/`WrongOwner`/`Revoked`/`AccessDenied`. `unmap_io_space`
  invalidates by `mapping_id`; a re-unmap (stale ID) fails.
- `connect_interrupt` is exclusive (second connect → `AlreadyConnected`), ownership-
  checked; `disconnect_interrupt` invalidates the ID. `inject_vector`/
  `inject_interrupt` resolve a connected interrupt to its Driver-Host callback
  tokens (dropped after disconnect). `revoke_host` cleans up all mappings +
  interrupts for a faulted host (spec §15.1). 6 unit tests (§18.1/§18.4).

## Register access + simulated device (implemented, Milestone 11.3)

- `nt-register-access::RegisterBank` (spec §5.5, §8.6): a bounded byte buffer with
  width-specific (`u8`/`u16`/`u32`) little-endian read/write, checking bounds +
  alignment + per-range read-only permissions before each access. `poke_u32`
  bypasses read-only (device-side mutation); `as_mut_ptr` exposes the backing store
  for the Driver Host to hand a driver directly (register macros are inlined).
- `nt-sim-device::SimDevice` (spec §5.8, §12): the fake MMIO device — ID
  (`0x4d4d494f`, read-only) / control / status (bit0 = interrupt pending) / ack /
  irq-count. `raise_interrupt` asserts the line; `acknowledge` clears it + bumps the
  count. `mmio_ptr` is the `MmMapIoSpace` result the driver dereferences directly.
  5 unit tests (width/bounds/alignment/read-only; ID + interrupt line).

## MmioInterruptTest.sys in QEMU (implemented, Milestones 11.5-11.7 — `driver-host-mmio`)

The `driver-host-mmio` seL4 component hosts the Resource Manager + simulated device
**in-process** (the "simulated register backend direct call" of spec §19; register
macros are inlined so the mapping must be real Driver-Host memory) and runs the real
`MmioInterruptTest.sys`. Verified in QEMU (17/17):

- `DriverEntry` → `IoCreateDevice` → `MmMapIoSpace(0x10000000)` (validated against
  the fixture, returns the sim register-bank pointer) → `READ_REGISTER_ULONG(ID)` =
  `0x4d4d494f` (direct dereference) → `IoConnectInterrupt(vector 5)` (ownership-
  validated, ISR tokens registered).
- IOCTLs: `GET_ID` / `READ_REG32` read the ID register; `WAIT_FOR_INTERRUPT` pends
  the IRP.
- Injection: the test asserts the device line, resolves the connected ISR through
  the Resource Manager, runs it at the device IRQL (no runtime borrow held), then
  drains the DPC it queued — which completes the pending IRP. `GET_INTERRUPT_COUNT`
  = 1; `DISCONNECT_INTERRUPT` releases it (further injection dropped). No callback
  ran at the wrong IRQL.

Compat exports added (in the component): `MmMapIoSpace`, `MmUnmapIoSpace`,
`IoConnectInterrupt`, `IoDisconnectInterrupt`, `KeInitializeSpinLock`,
`KeAcquireSpinLockRaiseToDpc`, `KeReleaseSpinLock` (+ the existing DPC/completion
path). `nt-kernel-exec` gained `acquire_spin`/`release_spin`/`initialize_spin`.
Register access (`READ/WRITE_REGISTER_ULONG`) is inlined in the driver — no export.
