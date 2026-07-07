# P1 — Real Hardware (HAL / IRQ / DMA / Timer / Port)

**Goal:** replace the simulated hardware model with **real** access under QEMU so
real ReactOS drivers can drive real devices: MMIO via seL4 frame caps, interrupts
via seL4 IRQ handler caps, a real LAPIC clock, x86 port I/O via IO‑port caps, and
real DMA (contiguous buffers + physical addresses + MDLs).

**Why:** everything above (storage, FS, registry) needs real device I/O. Today
`nt-sim-device` + fake MMIO stand in; drivers "work" against a model, not metal.

## Status: in progress — real MMIO (3984164) + real IRQ (0e96454) landed

## Background to reuse
- `docs/architecture/sel4_irq_bridge.md`, `hal-resource-interrupt.md`,
  `wdf-hardware.md` — existing designs.
- `nt-hal-abi` + `hal-svc`, `nt-resource-manager`, `nt-cm-resources`,
  `nt-dma-manager`/`nt-dma-abi`/`nt-mdl`, `nt-wdf-interrupt`, `nt-wdf-dma`.
- rust-micro exposes IRQ handler caps + notification binding (from sel4test
  INTERRUPT family) and device untyped/frames.

## Tasks
- [x] **Real MMIO — first proof (3984164):** the executive retypes a real device
      untyped (HPET, 0xFED00000 — kernel exposes IOAPIC/HPET/LAPIC MMIO as device
      untypeds) into a device frame + maps it (kernel makes device frames uncached),
      and reads the real HPET GCAP_ID register = 0x8086A201 (VENDOR_ID 0x8086). This
      is the `claim_device_page()` mechanism; next, hand a BAR window to an isolated
      driver host + wire `MmMapIoSpace`, and enumerate real BARs via PCI (still TODO).
- [x] **Real interrupts — first proof (0e96454):** the executive programs HPET
      timer 0 for a one-shot routed to an IOAPIC pin (23), issues an
      `X86IRQIssueIRQHandlerIOAPIC` cap (which programs IOAPIC RTE[pin] →
      vector+PIC1_VECTOR_BASE), binds a **badged** notification, arms the timer, and
      receives the **real interrupt** (badge 0x40 via non-blocking `SysNBRecv`).
      Findings: `ioapic_issue_irq_handler()` hand-builds the 7-word + extra-cap
      invocation (label 64; mr3=pin in r15; mr4..6 at IPC words 5-7; dest CNode at
      word 122; depth 64). **IRQ now reaches an isolated driver host (f67753a):** the
      executive binds the IRQ-handler cap to a badged notification and transfers ONLY
      a cap to that notification to a separate isolated ISR component (`spawn_isr` /
      `isr.rs`, its own VSpace/CSpace, least-privilege); the ISR thread wakes on the
      real interrupt and signals back (badge 0x80). The executive must *block* (not
      spin) to yield to the priority-100 host — it runs at priority 255. **Still
      TODO:** the Ack path (`IRQHandler::Ack`) for repeat/level IRQs, forward the ISR
      wake into a DPC/ring, and `IoConnectInterrupt`/`WdfInterruptCreate` on a real
      *device* (not timer) IRQ.
- [ ] **Real timer/clock:** LAPIC timer as the system clock; `KeQueryPerformance
      Counter` / interrupt time / `KeQuerySystemTime`; one-shot + periodic timers
      for `KeSetTimer`/WDF timers. (rust-micro already uses LAPIC as its clock.)
- [x] **Real port I/O (112c3d1):** the executive mints an x86 IOPort cap from the
      singleton IOPortControl (slot 7) and does real `in`/`out` (In32 via SysCall →
      value in reply mr0; Out32 via SysSend). Used to drive PCI config space; the
      same path serves `READ_PORT_*`/`WRITE_PORT_*` for legacy IDE/PIC/8042.
- [ ] **Real DMA:** contiguous "common buffer" allocation with a real physical
      address; MDLs describing real pages; scatter/gather list build. Cache
      coherence assumptions documented (QEMU is coherent; note real-HW caveats).
- [~] **Resource assignment from real hardware — enumeration done (112c3d1):**
      `pci_read32()` walks bus 0 and reads real vendor/device/class/BARs/IRQ. Found 7
      devices incl. an Intel e1000e NIC (MMIO BAR0=0x81060000, IRQ 11) and two ICH9
      AHCI controllers (class 0x010601, ABAR/BAR5=0x81084000, IRQ 10). **Still TODO:**
      turn a captured (BAR, IRQ) into device-frame + IRQ-handler caps for an isolated
      host and hand it a real `CM_RESOURCE_LIST` at START (combine with the MMIO + IRQ
      increments — the mechanisms all exist now).

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
