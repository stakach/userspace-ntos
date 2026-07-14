//! # `nt-pnp` — the PnP resource-assignment POLICY (device enumeration → `CM_RESOURCE_LIST`)
//!
//! This is the *policy* half of capability-secure PnP (see `project_driver_model.md`,
//! effort 2). In NT, the PnP Manager enumerates the bus, binds a function driver to each
//! device, and *assigns resources* — handing the driver a `CM_RESOURCE_LIST` at
//! `IRP_MN_START_DEVICE`. In a capability microkernel that resource assignment IS a
//! capability grant: "PnP assigns the device its BAR + IRQ + DMA" ≡ "a trusted broker
//! MINTS exactly the frame caps (the MMIO BAR), the IRQ notification, and the DMA frame
//! caps the resource list describes and delegates them into the driver's CNode." Least
//! privilege by construction — the driver gets caps to ITS device and nothing else.
//!
//! This crate is the *broker's brain*: it
//!   1. **enumerates** PCI config space (vendor/device/class, each BAR's base + SIZE via the
//!      canonical write-all-ones probe, the IRQ line) into a device list,
//!   2. **binds** an enumerated device to a driver class (by class code / vendor+device), and
//!   3. **assigns resources** — builds the `CM_RESOURCE_LIST` (via `nt-cm-resources`) that
//!      names the exact MMIO BAR + interrupt the executive then mints caps for.
//!
//! It is *pure logic*: config access is injected via closures (a reader + a writer) so the
//! whole engine is host-testable against a mock config space. The seL4 executive supplies
//! closures over its real `pci_read32`/`pci_write32` (which drive the 0xCF8/0xCFC ports via
//! an I/O-port cap) and mints the caps the returned resource list describes — that cap
//! MECHANISM stays in the trusted root (same policy/mechanism split as `nt-process`).

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

pub use nt_cm_resources::{
    InterruptDescriptor, MemoryDescriptor, CM_RESOURCE_INTERRUPT_LATCHED,
    CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE, CM_RESOURCE_MEMORY_READ_WRITE,
    CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE, MEMORY_INTERRUPT_LIST_SIZE,
};

/// PCI configuration-space register offsets (byte offsets, dword-aligned).
pub const PCI_CFG_VENDOR_DEVICE: u8 = 0x00;
pub const PCI_CFG_COMMAND_STATUS: u8 = 0x04;
pub const PCI_CFG_CLASS_REV: u8 = 0x08;
/// BAR0..BAR5 live at 0x10, 0x14, … 0x24.
pub const PCI_CFG_BAR0: u8 = 0x10;
/// Interrupt line (low byte) + interrupt pin (second byte) at 0x3C.
pub const PCI_CFG_INTERRUPT: u8 = 0x3C;

/// The number of standard type-0 BARs.
pub const PCI_NUM_BARS: usize = 6;

/// BAR low-bit decode (PCI spec §6.2.5.1).
const BAR_IO_SPACE: u32 = 0x1; // bit0: 1 = I/O space, 0 = memory space
const BAR_TYPE_MASK: u32 = 0x6; // bits[2:1]: memory BAR type
const BAR_TYPE_64BIT: u32 = 0x4; // bits[2:1] == 10b => 64-bit memory BAR
const BAR_MEM_ADDR_MASK: u32 = 0xFFFF_FFF0; // memory BAR base = value & ~0xF
const BAR_IO_ADDR_MASK: u32 = 0xFFFF_FFFC; // I/O BAR base = value & ~0x3

/// PCI device class codes (the high byte of the class-code dword).
pub const PCI_CLASS_STORAGE: u8 = 0x01;
pub const PCI_CLASS_NETWORK: u8 = 0x02;
pub const PCI_CLASS_DISPLAY: u8 = 0x03;

/// One decoded Base Address Register.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Bar {
    /// The BAR index (0..6).
    pub index: u8,
    /// True = I/O-space BAR, false = memory-space BAR.
    pub is_io: bool,
    /// True = 64-bit memory BAR (consumes this BAR + the next one).
    pub is_64bit: bool,
    /// The decoded base address (flag bits masked off).
    pub base: u64,
    /// The region SIZE in bytes, computed by the write-all-ones probe. `0` = BAR unimplemented.
    pub size: u64,
}

impl Bar {
    /// Whether this BAR is present (implemented — non-zero size).
    pub fn is_present(&self) -> bool {
        self.size != 0
    }
}

/// One enumerated PCI function.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciDevice {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor: u16,
    pub device: u16,
    /// The 24-bit class code `(base_class << 16) | (sub_class << 8) | prog_if`.
    pub class: u32,
    /// The PCI interrupt line (IRQ) from config 0x3C low byte.
    pub irq_line: u8,
    /// The PCI interrupt pin (0 = none/MSI-only, 1 = INTA .. 4 = INTD).
    pub irq_pin: u8,
    /// The decoded BARs (only *present* BARs are pushed).
    pub bars: Vec<Bar>,
}

impl PciDevice {
    /// The high byte of the class code — the PCI *base class* (e.g. `PCI_CLASS_NETWORK`).
    pub fn base_class(&self) -> u8 {
        (self.class >> 16) as u8
    }

    /// The first *present memory* BAR — the device's primary MMIO register file (a NIC's BAR0).
    pub fn first_memory_bar(&self) -> Option<&Bar> {
        self.bars.iter().find(|b| !b.is_io && b.is_present())
    }
}

/// Decode a BAR and probe its size. `read(off)` reads a config dword; `write(off, v)` writes one.
/// Follows the canonical PCI algorithm: save the BAR, write all-ones, read back the mask, restore
/// the BAR, then `size = (~mask & addr_mask) + 1`. Returns the decoded [`Bar`] (size 0 if the BAR
/// is unimplemented — reads back 0 after the all-ones write).
fn probe_bar<R, W>(index: u8, read: &R, write: &W) -> Bar
where
    R: Fn(u8) -> u32,
    W: Fn(u8, u32),
{
    let off = PCI_CFG_BAR0 + index * 4;
    let orig = read(off);
    let is_io = orig & BAR_IO_SPACE != 0;
    let is_64bit = !is_io && (orig & BAR_TYPE_MASK) == BAR_TYPE_64BIT;
    let addr_mask = if is_io { BAR_IO_ADDR_MASK } else { BAR_MEM_ADDR_MASK };
    // Write all-ones and read back the decoded address mask, then restore.
    write(off, 0xFFFF_FFFF);
    let probed = read(off) & addr_mask;
    write(off, orig);
    let size = if probed == 0 {
        0
    } else {
        // `probed` already has the flag bits masked off, so the size is `~probed + 1` (the value
        // of the lowest set bit of the decoded mask). Negation stays in u32 so a 32-bit BAR of
        // size 0x2_0000 gives ~0xFFFE_0000 + 1 = 0x2_0000.
        (!probed) as u64 + 1
    };
    let base = if is_io {
        (orig & BAR_IO_ADDR_MASK) as u64
    } else {
        (orig & BAR_MEM_ADDR_MASK) as u64
    };
    Bar { index, is_io, is_64bit, base, size }
}

/// Enumerate one PCI function at `(bus, dev, func)` given a config reader + writer scoped to that
/// function (`read(off)` / `write(off, v)` operate on the caller-selected BDF). Returns `None` if
/// the function is absent (vendor == 0xFFFF). The size-probe MUTATES each BAR (all-ones write) and
/// restores it — the caller's `write` must reach real config space.
pub fn enumerate_function<R, W>(bus: u8, dev: u8, func: u8, read: R, write: W) -> Option<PciDevice>
where
    R: Fn(u8) -> u32,
    W: Fn(u8, u32),
{
    let vd = read(PCI_CFG_VENDOR_DEVICE);
    let vendor = (vd & 0xFFFF) as u16;
    if vendor == 0xFFFF {
        return None;
    }
    let device = (vd >> 16) as u16;
    let class = read(PCI_CFG_CLASS_REV) >> 8;
    let intr = read(PCI_CFG_INTERRUPT);
    let irq_line = (intr & 0xFF) as u8;
    let irq_pin = ((intr >> 8) & 0xFF) as u8;
    let mut bars = Vec::new();
    let mut i = 0u8;
    while (i as usize) < PCI_NUM_BARS {
        let bar = probe_bar(i, &read, &write);
        // A 64-bit memory BAR consumes the next BAR slot for its high dword; skip it.
        let step = if bar.is_64bit { 2 } else { 1 };
        if bar.is_present() {
            bars.push(bar);
        }
        i += step;
    }
    Some(PciDevice { bus, dev, func, vendor, device, class, irq_line, irq_pin, bars })
}

/// Enumerate every present function on `bus` (0..32 devices × 0..8 functions). `read(dev,func,off)`
/// / `write(dev,func,off,v)` access config space for the given device/function on this bus. This is
/// the PnP Manager's bus walk — the same one the executive did inline before `nt-pnp` existed.
pub fn enumerate_bus<R, W>(bus: u8, read: R, write: W) -> Vec<PciDevice>
where
    R: Fn(u8, u8, u8) -> u32,
    W: Fn(u8, u8, u8, u32),
{
    let mut out = Vec::new();
    for dev in 0..32u8 {
        for func in 0..8u8 {
            let d = enumerate_function(
                bus,
                dev,
                func,
                |off| read(dev, func, off),
                |off, v| write(dev, func, off, v),
            );
            match d {
                Some(d) => out.push(d),
                None => {
                    if func == 0 {
                        break; // no function 0 => the device is absent
                    }
                }
            }
        }
    }
    out
}

/// A driver class the PnP Manager can bind a device to. In the real system this comes from the
/// `Enum`/`Services` registry (already read from the SYSTEM hive); a simple class match is enough
/// for the first device (the NIC). Binding by registry `HardwareID` → service is a follow-on.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DriverClass {
    /// A network function driver (e.g. the e1000 NIC host).
    Network,
    /// A mass-storage function driver (AHCI/SATA).
    Storage,
    /// A display/GPU function driver.
    Display,
}

/// Bind an enumerated device to a driver class by its PCI base class. Returns `None` for a class
/// with no bound driver. (The registry-`HardwareID`-keyed binding is a documented follow-on; this
/// class match is the same "network controller → NIC host" rule the executive used inline.)
pub fn bind_driver(device: &PciDevice) -> Option<DriverClass> {
    match device.base_class() {
        PCI_CLASS_NETWORK => Some(DriverClass::Network),
        PCI_CLASS_STORAGE => Some(DriverClass::Storage),
        PCI_CLASS_DISPLAY => Some(DriverClass::Display),
        _ => None,
    }
}

/// Find the first enumerated device the PnP Manager would bind to `class`.
pub fn find_device_for_class(devices: &[PciDevice], class: DriverClass) -> Option<&PciDevice> {
    devices.iter().find(|d| bind_driver(d) == Some(class))
}

/// The resource assignment PnP produces for a device: which MMIO window + interrupt (+ optional
/// DMA common-buffer) the driver is granted. This is the abstract grant the executive turns into
/// minted caps; [`assignment_to_cm_list`] encodes it as the `CM_RESOURCE_LIST` the driver reads.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResourceAssignment {
    /// The device MMIO physical base (the BAR base).
    pub mmio_phys: u64,
    /// The MMIO window length (rounded up to whole pages by the broker when minting frame caps).
    pub mmio_len: u64,
    /// The interrupt vector/level assigned to the device (translated form).
    pub int_vector: u32,
    /// True = latched (edge/MSI), false = level-sensitive.
    pub int_latched: bool,
    /// The interrupt affinity mask (CPU set).
    pub int_affinity: u64,
    /// The DMA common-buffer length in bytes (`0` = no DMA resource).
    pub dma_len: u64,
}

/// Assign resources to a device bound to `class`, from its enumerated BARs + IRQ. `int_vector` is
/// the translated interrupt vector the executive has arranged for this device (e.g. the MSI vector
/// it programmed); `dma_len` is the common-buffer size the driver needs (0 for none). Returns
/// `None` if the device exposes no memory BAR (nothing to grant). This is the arbitration step —
/// trivial for a single device with one MMIO BAR.
pub fn assign_resources(
    device: &PciDevice,
    int_vector: u32,
    int_latched: bool,
    int_affinity: u64,
    dma_len: u64,
) -> Option<ResourceAssignment> {
    let bar = device.first_memory_bar()?;
    Some(ResourceAssignment {
        mmio_phys: bar.base,
        mmio_len: bar.size,
        int_vector,
        int_latched,
        int_affinity,
        dma_len,
    })
}

/// Encode a [`ResourceAssignment`] as the `CM_RESOURCE_LIST` (memory + interrupt) a WDK driver
/// reads at `IRP_MN_START_DEVICE`. `mmio_va` is the *driver-visible* address of the MMIO window
/// (where the executive maps the minted BAR frames in the driver's VSpace) — the driver dereferences
/// the descriptor's `Memory.Start`, so it must be the VA the caps are mapped at, not the physaddr.
/// Writes into `buf` (>= [`MEMORY_INTERRUPT_LIST_SIZE`]); returns the byte length written.
pub fn assignment_to_cm_list(
    buf: &mut [u8],
    bus_number: u32,
    assign: &ResourceAssignment,
    mmio_va: u64,
    mmio_len: u32,
) -> Option<usize> {
    nt_cm_resources::build_memory_interrupt_list(
        buf,
        bus_number,
        MemoryDescriptor {
            start: mmio_va,
            length: mmio_len,
            flags: CM_RESOURCE_MEMORY_READ_WRITE,
            share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
        },
        InterruptDescriptor {
            level: assign.int_vector,
            vector: assign.int_vector,
            affinity: assign.int_affinity,
            flags: if assign.int_latched {
                CM_RESOURCE_INTERRUPT_LATCHED
            } else {
                CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE
            },
            share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::cell::RefCell;

    /// A mock PCI config space: a map of `(dev, func, off) -> dword`, with the size-probe protocol
    /// implemented (an all-ones write to a BAR latches the size mask; reading back returns it; any
    /// other write restores the stored value). Enough to drive the enumerator end-to-end.
    struct MockConfig {
        /// (dev, func, off) -> stored dword.
        regs: RefCell<vec::Vec<((u8, u8, u8), u32)>>,
        /// (dev, func, bar_off) -> size mask returned after an all-ones write.
        bar_masks: vec::Vec<((u8, u8, u8), u32)>,
    }

    impl MockConfig {
        fn get(&self, dev: u8, func: u8, off: u8) -> u32 {
            self.regs
                .borrow()
                .iter()
                .find(|(k, _)| *k == (dev, func, off))
                .map(|(_, v)| *v)
                .unwrap_or(0xFFFF_FFFF)
        }
        fn set(&self, dev: u8, func: u8, off: u8, v: u32) {
            let mut r = self.regs.borrow_mut();
            if let Some(e) = r.iter_mut().find(|(k, _)| *k == (dev, func, off)) {
                e.1 = v;
            } else {
                r.push(((dev, func, off), v));
            }
        }
        fn read(&self, dev: u8, func: u8, off: u8) -> u32 {
            self.get(dev, func, off)
        }
        fn write(&self, dev: u8, func: u8, off: u8, v: u32) {
            // Emulate the BAR size probe: an all-ones write to a probed BAR latches the size mask.
            if v == 0xFFFF_FFFF {
                if let Some((_, mask)) = self.bar_masks.iter().find(|(k, _)| *k == (dev, func, off)) {
                    self.set(dev, func, off, *mask);
                    return;
                }
            }
            self.set(dev, func, off, v);
        }
    }

    /// Build a mock with a single NIC at 00:03.0: Intel e1000 (8086:100E), class 0x020000
    /// (network/ethernet), BAR0 = 32-bit memory @ 0xFEBC_0000 size 128 KiB, IRQ line 11 pin INTA.
    fn nic_mock() -> MockConfig {
        let regs = vec![
            ((3, 0, PCI_CFG_VENDOR_DEVICE), 0x100E_8086),
            ((3, 0, PCI_CFG_CLASS_REV), 0x0200_0000), // class 0x020000 in the high 24 bits
            ((3, 0, PCI_CFG_BAR0), 0xFEBC_0000),      // 32-bit mem BAR base
            ((3, 0, PCI_CFG_INTERRUPT), 0x0000_010B), // pin=INTA(1) line=11(0x0B)
        ];
        MockConfig {
            regs: RefCell::new(regs),
            // 128 KiB memory BAR => mask 0xFFFE_0000 (size = ~mask+1 = 0x2_0000).
            bar_masks: vec![((3, 0, PCI_CFG_BAR0), 0xFFFE_0000)],
        }
    }

    #[test]
    fn enumerates_nic_with_bar_size_and_irq() {
        let m = nic_mock();
        let devs = enumerate_bus(
            0,
            |d, f, o| m.read(d, f, o),
            |d, f, o, v| m.write(d, f, o, v),
        );
        assert_eq!(devs.len(), 1);
        let nic = &devs[0];
        assert_eq!(nic.vendor, 0x8086);
        assert_eq!(nic.device, 0x100E);
        assert_eq!(nic.base_class(), PCI_CLASS_NETWORK);
        assert_eq!(nic.irq_line, 11);
        assert_eq!(nic.irq_pin, 1);
        let bar = nic.first_memory_bar().unwrap();
        assert!(!bar.is_io);
        assert_eq!(bar.base, 0xFEBC_0000);
        assert_eq!(bar.size, 0x2_0000); // 128 KiB from the write-all-ones probe
    }

    #[test]
    fn probe_restores_the_bar_after_sizing() {
        let m = nic_mock();
        let _ = enumerate_function(0, 3, 0, |o| m.read(3, 0, o), |o, v| m.write(3, 0, o, v));
        // The BAR must be restored to its original value after the size probe.
        assert_eq!(m.get(3, 0, PCI_CFG_BAR0), 0xFEBC_0000);
    }

    #[test]
    fn binds_network_class_to_nic_driver() {
        let m = nic_mock();
        let devs = enumerate_bus(0, |d, f, o| m.read(d, f, o), |d, f, o, v| m.write(d, f, o, v));
        assert_eq!(bind_driver(&devs[0]), Some(DriverClass::Network));
        let nic = find_device_for_class(&devs, DriverClass::Network).unwrap();
        assert_eq!(nic.device, 0x100E);
        assert!(find_device_for_class(&devs, DriverClass::Storage).is_none());
    }

    #[test]
    fn absent_device_terminates_scan() {
        // Empty config space => every read is 0xFFFF => no devices.
        let m = MockConfig { regs: RefCell::new(vec![]), bar_masks: vec![] };
        let devs = enumerate_bus(0, |d, f, o| m.read(d, f, o), |d, f, o, v| m.write(d, f, o, v));
        assert!(devs.is_empty());
    }

    #[test]
    fn assigns_resources_and_builds_cm_list() {
        let m = nic_mock();
        let devs = enumerate_bus(0, |d, f, o| m.read(d, f, o), |d, f, o, v| m.write(d, f, o, v));
        let nic = find_device_for_class(&devs, DriverClass::Network).unwrap();
        let assign = assign_resources(nic, 5, true, 1, 0x1000).unwrap();
        assert_eq!(assign.mmio_phys, 0xFEBC_0000);
        assert_eq!(assign.mmio_len, 0x2_0000);
        assert_eq!(assign.int_vector, 5);
        assert!(assign.int_latched);
        assert_eq!(assign.dma_len, 0x1000);

        // The driver-visible resource list names the driver's MMIO VA + the assigned vector.
        let mut buf = [0u8; MEMORY_INTERRUPT_LIST_SIZE];
        let mmio_va = 0x0000_0100_105F_0000u64;
        let n = assignment_to_cm_list(&mut buf, 0, &assign, mmio_va, 0x4000).unwrap();
        assert_eq!(n, MEMORY_INTERRUPT_LIST_SIZE);
        let (mem, int) = nt_cm_resources::decode_memory_interrupt_list(&buf).unwrap();
        assert_eq!(mem.start, mmio_va);
        assert_eq!(mem.length, 0x4000);
        assert_eq!(int.vector, 5);
        assert_eq!(int.flags, CM_RESOURCE_INTERRUPT_LATCHED);
        assert_eq!(int.affinity, 1);
    }

    #[test]
    fn assign_none_without_memory_bar() {
        // A device with only an I/O BAR has no MMIO window to grant.
        let regs = vec![
            ((5, 0, PCI_CFG_VENDOR_DEVICE), 0xBEEF_1234),
            ((5, 0, PCI_CFG_CLASS_REV), 0x0200_0000),
            ((5, 0, PCI_CFG_BAR0), 0xC001), // I/O BAR (bit0 set)
            ((5, 0, PCI_CFG_INTERRUPT), 0x0000_0105),
        ];
        let m = MockConfig {
            regs: RefCell::new(regs),
            bar_masks: vec![((5, 0, PCI_CFG_BAR0), 0xFFFF_FF01)], // 256-byte I/O BAR
        };
        let dev = enumerate_function(0, 5, 0, |o| m.read(5, 0, o), |o, v| m.write(5, 0, o, v)).unwrap();
        assert!(dev.first_memory_bar().is_none());
        assert!(assign_resources(&dev, 5, true, 1, 0).is_none());
    }
}
