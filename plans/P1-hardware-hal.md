# P1 — Real Hardware (HAL / IRQ / DMA / Timer / Port)

**Goal:** replace the simulated hardware model with **real** access under QEMU so
real ReactOS drivers can drive real devices: MMIO via seL4 frame caps, interrupts
via seL4 IRQ handler caps, a real LAPIC clock, x86 port I/O via IO‑port caps, and
real DMA (contiguous buffers + physical addresses + MDLs).

**Why:** everything above (storage, FS, registry) needs real device I/O. Today
`nt-sim-device` + fake MMIO stand in; drivers "work" against a model, not metal.

## Status: not started

## Background to reuse
- `docs/architecture/sel4_irq_bridge.md`, `hal-resource-interrupt.md`,
  `wdf-hardware.md` — existing designs.
- `nt-hal-abi` + `hal-svc`, `nt-resource-manager`, `nt-cm-resources`,
  `nt-dma-manager`/`nt-dma-abi`/`nt-mdl`, `nt-wdf-interrupt`, `nt-wdf-dma`.
- rust-micro exposes IRQ handler caps + notification binding (from sel4test
  INTERRUPT family) and device untyped/frames.

## Tasks
- [ ] **Real MMIO:** the executive/HAL retypes device untyped → frame caps for a
      device BAR and maps them into the owning driver host's VSpace (uncached).
      `MmMapIoSpace` in a host resolves to a real mapped BAR. Replace `nt-sim-device`
      on the real path (keep it for unit tests).
- [ ] **Real interrupts:** HAL gets the device's IRQ handler cap, binds it to a
      notification, and forwards to the driver host's ISR/DPC over the reflector
      (or a dedicated IRQ ring). `IoConnectInterrupt` / `WdfInterruptCreate`
      deliver a real QEMU device interrupt. Ack path back to the kernel.
- [ ] **Real timer/clock:** LAPIC timer as the system clock; `KeQueryPerformance
      Counter` / interrupt time / `KeQuerySystemTime`; one-shot + periodic timers
      for `KeSetTimer`/WDF timers. (rust-micro already uses LAPIC as its clock.)
- [ ] **Real port I/O:** seL4 x86 IO‑port caps → `READ_PORT_*`/`WRITE_PORT_*`
      (needed for legacy IDE/PIC/8042).
- [ ] **Real DMA:** contiguous "common buffer" allocation with a real physical
      address; MDLs describing real pages; scatter/gather list build. Cache
      coherence assumptions documented (QEMU is coherent; note real-HW caveats).
- [ ] **Resource assignment from real hardware:** PnP/HAL enumerate a real device's
      BARs + IRQ (PCI config space) and hand a `CM_RESOURCE_LIST` to the driver at
      START — real values, not fixtures.

## Test drivers (build in `stakach/ntdriver` as needed)
- Reuse `mmio_interrupt_test_driver`, `kmdf_dma_interrupt_test_driver`,
  `power_pnp_mmio_test_driver` — but pointed at a **real** QEMU device (e.g. an
  `edu` PCI test device, or a virtio device) instead of the simulated bank.
- If no suitable simple QEMU device exists, add a minimal one to the QEMU cmdline
  (e.g. `-device edu`) and a matching KMDF driver in `ntdriver`.

## Exit criteria
- A real KMDF (or WDM) driver in an **isolated host** maps a real QEMU device's
  MMIO, programs it, and receives a **real interrupt** delivered through the seL4
  IRQ → HAL → reflector → ISR/DPC path — verified end-to-end in QEMU, with the
  driver still crash-contained by the supervisor.

## E2E test
`e2e-real-mmio-irq`: executive spawns HAL + an isolated driver host for the QEMU
test device; the driver writes an MMIO command, the device raises an IRQ, the
host's ISR runs and completes; a DMA common-buffer round-trip moves bytes.

## Notes / findings
_(append as work proceeds)_
