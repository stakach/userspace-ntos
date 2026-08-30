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
//!   2. **resolves** registry `Enum`/service devnodes to enumerated bus functions, and
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

mod pci_inventory;

pub use pci_inventory::{
    CommittedPciInventoryUpdate, PciInventory, PciInventoryError, PciLocation, PciResourceChange,
    PreparedPciCensus, PreparedPciInventoryUpdate,
};

use alloc::vec::Vec;

pub use nt_cm_resources::{
    CmResourceDescriptor, InterruptDescriptor, IoAddressRequirement, IoInterruptRequirement,
    IoResourceRequirement, MemoryDescriptor, PortDescriptor, CM_RESOURCE_INTERRUPT_LATCHED,
    CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE, CM_RESOURCE_MEMORY_BAR, CM_RESOURCE_MEMORY_PREFETCHABLE,
    CM_RESOURCE_MEMORY_READ_WRITE, CM_RESOURCE_PORT_16_BIT_DECODE, CM_RESOURCE_PORT_BAR,
    CM_RESOURCE_PORT_IO, CM_RESOURCE_PORT_POSITIVE_DECODE, CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
    CM_RESOURCE_SHARE_SHARED, INTERFACE_TYPE_PCI_BUS, INTERFACE_TYPE_PNP_BUS,
    IO_RESOURCE_ALTERNATIVE, IO_RESOURCE_PREFERRED, IO_RESOURCE_REQUIRED,
    MEMORY_INTERRUPT_LIST_SIZE, MEMORY_LIST_SIZE, MEMORY_PORT_INTERRUPT_LIST_SIZE,
    MEMORY_PORT_LIST_SIZE, PORT_INTERRUPT_LIST_SIZE, PORT_LIST_SIZE,
};

/// PCI configuration-space register offsets (byte offsets, dword-aligned).
pub const PCI_CFG_VENDOR_DEVICE: u8 = 0x00;
pub const PCI_CFG_COMMAND_STATUS: u8 = 0x04;
pub const PCI_CFG_CLASS_REV: u8 = 0x08;
/// Cache-line/latency/header/BIST dword. Header type is byte 0x0e (bits 16..23).
pub const PCI_CFG_HEADER: u8 = 0x0C;
/// BAR0..BAR5 live at 0x10, 0x14, … 0x24.
pub const PCI_CFG_BAR0: u8 = 0x10;
/// Primary/secondary/subordinate bus numbers for a PCI-to-PCI bridge.
pub const PCI_CFG_BUS_NUMBERS: u8 = 0x18;
/// Interrupt line (low byte) + interrupt pin (second byte) at 0x3C.
pub const PCI_CFG_INTERRUPT: u8 = 0x3C;

/// The number of standard type-0 BARs.
pub const PCI_NUM_BARS: usize = 6;

/// BAR low-bit decode (PCI spec §6.2.5.1).
const BAR_IO_SPACE: u32 = 0x1; // bit0: 1 = I/O space, 0 = memory space
const BAR_TYPE_MASK: u32 = 0x6; // bits[2:1]: memory BAR type
const BAR_TYPE_20BIT: u32 = 0x2; // bits[2:1] == 01b => below-1MiB memory BAR
const BAR_TYPE_64BIT: u32 = 0x4; // bits[2:1] == 10b => 64-bit memory BAR
const BAR_PREFETCHABLE: u32 = 0x8;
const BAR_MEM_ADDR_MASK: u32 = 0xFFFF_FFF0; // memory BAR base = value & ~0xF
const BAR_IO_ADDR_MASK: u32 = 0xFFFF_FFFC; // I/O BAR base = value & ~0x3
const PCI_COMMAND_IO_SPACE: u16 = 0x0001;
const PCI_COMMAND_MEMORY_SPACE: u16 = 0x0002;
const PCI_HEADER_TYPE_MASK: u8 = 0x7f;
const PCI_HEADER_TYPE_DEVICE: u8 = 0;
const PCI_HEADER_TYPE_BRIDGE: u8 = 1;
const PCI_HEADER_TYPE_CARDBUS: u8 = 2;

/// PCI device class codes (the high byte of the class-code dword).
pub const PCI_CLASS_STORAGE: u8 = 0x01;
pub const PCI_CLASS_NETWORK: u8 = 0x02;
pub const PCI_CLASS_DISPLAY: u8 = 0x03;
pub const PCI_CLASS_BRIDGE: u8 = 0x06;
pub const PCI_SUBCLASS_PCI_TO_PCI: u8 = 0x04;

/// One decoded Base Address Register.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Bar {
    /// The BAR index (0..6).
    pub index: u8,
    /// True = I/O-space BAR, false = memory-space BAR.
    pub is_io: bool,
    /// True = 64-bit memory BAR (consumes this BAR + the next one).
    pub is_64bit: bool,
    /// True when a memory BAR advertises prefetchable memory.
    pub prefetchable: bool,
    /// The decoded base address (flag bits masked off).
    pub base: u64,
    /// The region SIZE in bytes, computed by the write-all-ones probe. `0` = BAR unimplemented.
    pub size: u64,
    /// Highest address the BAR's native decode width can represent.
    pub maximum_address: u64,
}

impl Bar {
    /// Whether this BAR is present (implemented — non-zero size).
    pub fn is_present(&self) -> bool {
        self.size != 0
    }

    /// Whether this BAR is both implemented and assigned a usable base address.
    pub fn is_assigned(&self) -> bool {
        self.is_present() && self.base != 0
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

    /// The first assigned memory BAR — the device's primary MMIO register file (a NIC's BAR0).
    pub fn first_memory_bar(&self) -> Option<&Bar> {
        self.bars.iter().find(|b| !b.is_io && b.is_assigned())
    }

    /// The first assigned I/O-space BAR.
    pub fn first_io_bar(&self) -> Option<&Bar> {
        self.bars.iter().find(|b| b.is_io && b.is_assigned())
    }

    /// Native `PCI_SLOT_NUMBER.AsULONG` (`DeviceNumber:5`, then `FunctionNumber:3`).
    pub fn slot_number(&self) -> u32 {
        self.dev as u32 | ((self.func as u32) << 5)
    }
}

/// Read-only PCI function snapshot used to detect topology changes without disabling decode or
/// writing BAR sizing values into an already-started device.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PciFunctionSnapshot {
    pub bus: u8,
    pub dev: u8,
    pub func: u8,
    pub vendor: u16,
    pub device: u16,
    pub class: u32,
    pub irq_line: u8,
    pub irq_pin: u8,
    pub header_type: u8,
    pub bar_count: u8,
    pub raw_bars: [u32; PCI_NUM_BARS],
}

impl PciFunctionSnapshot {
    pub fn location(&self) -> PciLocation {
        PciLocation::new(self.bus, self.dev, self.func)
    }

    pub fn base_class(&self) -> u8 {
        (self.class >> 16) as u8
    }

    pub fn subclass(&self) -> u8 {
        (self.class >> 8) as u8
    }

    pub fn is_pci_bridge(&self) -> bool {
        self.base_class() == PCI_CLASS_BRIDGE && self.subclass() == PCI_SUBCLASS_PCI_TO_PCI
    }

    pub fn same_hardware_identity(&self, device: &PciDevice) -> bool {
        self.location() == PciLocation::from(device)
            && self.vendor == device.vendor
            && self.device == device.device
            && self.class == device.class
    }
}

impl From<&PciFunctionSnapshot> for PciLocation {
    fn from(snapshot: &PciFunctionSnapshot) -> Self {
        snapshot.location()
    }
}

/// Decode a BAR and probe its size. `read(off)` reads a config dword; `write(off, v)` writes one.
/// Follows the canonical PCI algorithm: save the BAR, write all-ones, read back the mask, restore
/// the BAR, then `size = (~mask & addr_mask) + 1`. Returns the decoded [`Bar`] (size 0 if the BAR
/// is unimplemented — reads back 0 after the all-ones write).
fn probe_bar<R, W>(index: u8, paired_slot_available: bool, read: &R, write: &W) -> Bar
where
    R: Fn(u8) -> u32,
    W: Fn(u8, u32),
{
    let off = PCI_CFG_BAR0 + index * 4;
    let orig = read(off);
    let is_io = orig & BAR_IO_SPACE != 0;
    let memory_type = orig & BAR_TYPE_MASK;
    let is_64bit = !is_io && memory_type == BAR_TYPE_64BIT;
    let prefetchable = !is_io && orig & BAR_PREFETCHABLE != 0;
    let addr_mask = if is_io {
        BAR_IO_ADDR_MASK
    } else {
        BAR_MEM_ADDR_MASK
    };
    if is_64bit && !paired_slot_available {
        return Bar {
            index,
            is_io,
            is_64bit,
            prefetchable,
            base: 0,
            size: 0,
            maximum_address: u64::MAX,
        };
    }
    let orig_high = if is_64bit { read(off + 4) } else { 0 };
    // A 64-bit BAR must be probed and restored as one register pair.
    write(off, 0xFFFF_FFFF);
    if is_64bit {
        write(off + 4, 0xFFFF_FFFF);
    }
    let probed_low = read(off) & addr_mask;
    let probed_high = if is_64bit { read(off + 4) } else { 0 };
    if is_64bit {
        write(off + 4, orig_high);
    }
    write(off, orig);

    let (base, size_mask, maximum_address) = if is_io {
        (
            (orig & BAR_IO_ADDR_MASK) as u64,
            probed_low as u64,
            u32::MAX as u64,
        )
    } else if memory_type == BAR_TYPE_64BIT {
        (
            ((orig_high as u64) << 32) | (orig & BAR_MEM_ADDR_MASK) as u64,
            ((probed_high as u64) << 32) | probed_low as u64,
            u64::MAX,
        )
    } else if memory_type == 0 || memory_type == BAR_TYPE_20BIT {
        (
            (orig & BAR_MEM_ADDR_MASK) as u64,
            probed_low as u64,
            if memory_type == BAR_TYPE_20BIT {
                0x000F_FFFF
            } else {
                u32::MAX as u64
            },
        )
    } else {
        // 0b11 is reserved by PCI and cannot become an authoritative resource constraint.
        (0, 0, 0)
    };
    let size = if size_mask == 0 {
        0
    } else if is_64bit {
        (!size_mask).wrapping_add(1)
    } else {
        (!(size_mask as u32)).wrapping_add(1) as u64
    };
    Bar {
        index,
        is_io,
        is_64bit,
        prefetchable,
        base,
        size,
        maximum_address,
    }
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
    let header_type = ((read(PCI_CFG_HEADER) >> 16) & 0xff) as u8 & PCI_HEADER_TYPE_MASK;
    let bar_count = match header_type {
        PCI_HEADER_TYPE_DEVICE => 6u8,
        PCI_HEADER_TYPE_BRIDGE => 2u8,
        PCI_HEADER_TYPE_CARDBUS => 1u8,
        _ => 0u8,
    };
    let intr = read(PCI_CFG_INTERRUPT);
    let irq_line = (intr & 0xFF) as u8;
    let irq_pin = ((intr >> 8) & 0xFF) as u8;
    let mut bars = Vec::new();
    let command = read(PCI_CFG_COMMAND_STATUS) as u16;
    if bar_count != 0 {
        // Preserve command bits while writing zero to the W1C status half. Decode must be disabled
        // while a BAR contains the all-ones sizing value.
        write(
            PCI_CFG_COMMAND_STATUS,
            (command & !(PCI_COMMAND_IO_SPACE | PCI_COMMAND_MEMORY_SPACE)) as u32,
        );
    }
    let mut i = 0u8;
    while i < bar_count {
        let bar = probe_bar(i, i + 1 < bar_count, &read, &write);
        // A 64-bit memory BAR consumes the next BAR slot for its high dword; skip it.
        let step = if bar.is_64bit { 2 } else { 1 };
        if bar.is_present() {
            bars.push(bar);
        }
        i += step;
    }
    if bar_count != 0 {
        write(PCI_CFG_COMMAND_STATUS, command as u32);
    }
    Some(PciDevice {
        bus,
        dev,
        func,
        vendor,
        device,
        class,
        irq_line,
        irq_pin,
        bars,
    })
}

/// Read one PCI function without mutating config space. BAR dwords are captured exactly as
/// programmed; their sizes are intentionally not probed.
pub fn snapshot_function<R>(bus: u8, dev: u8, func: u8, read: R) -> Option<PciFunctionSnapshot>
where
    R: Fn(u8) -> u32,
{
    let vendor_device = read(PCI_CFG_VENDOR_DEVICE);
    let vendor = vendor_device as u16;
    if vendor == u16::MAX {
        return None;
    }
    let class = read(PCI_CFG_CLASS_REV) >> 8;
    let header_type = ((read(PCI_CFG_HEADER) >> 16) & 0xff) as u8 & PCI_HEADER_TYPE_MASK;
    let bar_count = match header_type {
        PCI_HEADER_TYPE_DEVICE => 6,
        PCI_HEADER_TYPE_BRIDGE => 2,
        PCI_HEADER_TYPE_CARDBUS => 1,
        _ => 0,
    };
    let interrupt = read(PCI_CFG_INTERRUPT);
    let mut raw_bars = [0; PCI_NUM_BARS];
    for index in 0..bar_count {
        raw_bars[index as usize] = read(PCI_CFG_BAR0 + index * 4);
    }
    Some(PciFunctionSnapshot {
        bus,
        dev,
        func,
        vendor,
        device: (vendor_device >> 16) as u16,
        class,
        irq_line: interrupt as u8,
        irq_pin: (interrupt >> 8) as u8,
        header_type,
        bar_count,
        raw_bars,
    })
}

pub fn snapshot_bus<R>(bus: u8, read: R) -> Vec<PciFunctionSnapshot>
where
    R: Fn(u8, u8, u8) -> u32,
{
    let mut snapshots = Vec::new();
    for dev in 0..32u8 {
        for func in 0..8u8 {
            match snapshot_function(bus, dev, func, |offset| read(dev, func, offset)) {
                Some(snapshot) => snapshots.push(snapshot),
                None if func == 0 => break,
                None => {}
            }
        }
    }
    snapshots
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

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PciTopologyError {
    InvalidBridgeWindow {
        bridge: PciLocation,
        primary: u8,
        secondary: u8,
        subordinate: u8,
    },
    DuplicateSecondaryBus {
        bridge: PciLocation,
        secondary: u8,
    },
}

/// Enumerate a complete configured PCI hierarchy starting at `root_bus`.
///
/// Every discovered PCI-to-PCI bridge must publish a coherent primary/secondary/subordinate
/// window. Each secondary bus has exactly one parent bridge. The walk rejects malformed or cyclic
/// topology instead of silently publishing only part of the bus tree.
pub fn enumerate_hierarchy<R, W>(
    root_bus: u8,
    read: R,
    write: W,
) -> Result<Vec<PciDevice>, PciTopologyError>
where
    R: Fn(u8, u8, u8, u8) -> u32,
    W: Fn(u8, u8, u8, u8, u32),
{
    let mut scheduled = [false; 256];
    let mut buses = Vec::new();
    let mut devices = Vec::new();
    scheduled[root_bus as usize] = true;
    buses.push(root_bus);

    let mut bus_index = 0;
    while bus_index < buses.len() {
        let bus = buses[bus_index];
        bus_index += 1;
        let bus_devices = enumerate_bus(
            bus,
            |device, function, offset| read(bus, device, function, offset),
            |device, function, offset, value| write(bus, device, function, offset, value),
        );
        for device in &bus_devices {
            let subclass = ((device.class >> 8) & 0xff) as u8;
            if device.base_class() != PCI_CLASS_BRIDGE || subclass != PCI_SUBCLASS_PCI_TO_PCI {
                continue;
            }
            let bridge = PciLocation::from(device);
            let numbers = read(device.bus, device.dev, device.func, PCI_CFG_BUS_NUMBERS);
            let primary = numbers as u8;
            let secondary = (numbers >> 8) as u8;
            let subordinate = (numbers >> 16) as u8;
            if primary != bus || secondary == 0 || secondary > subordinate {
                return Err(PciTopologyError::InvalidBridgeWindow {
                    bridge,
                    primary,
                    secondary,
                    subordinate,
                });
            }
            if scheduled[secondary as usize] {
                return Err(PciTopologyError::DuplicateSecondaryBus { bridge, secondary });
            }
            scheduled[secondary as usize] = true;
            buses.push(secondary);
        }
        devices.extend(bus_devices);
    }
    Ok(devices)
}

/// Read-only counterpart to [`enumerate_hierarchy`]. This is the only hierarchy walk suitable for
/// detecting hotplug while existing function drivers remain active.
pub fn snapshot_hierarchy<R>(
    root_bus: u8,
    read: R,
) -> Result<Vec<PciFunctionSnapshot>, PciTopologyError>
where
    R: Fn(u8, u8, u8, u8) -> u32,
{
    let mut scheduled = [false; 256];
    let mut buses = Vec::new();
    let mut snapshots = Vec::new();
    scheduled[root_bus as usize] = true;
    buses.push(root_bus);

    let mut bus_index = 0;
    while bus_index < buses.len() {
        let bus = buses[bus_index];
        bus_index += 1;
        let bus_snapshots = snapshot_bus(bus, |device, function, offset| {
            read(bus, device, function, offset)
        });
        for snapshot in &bus_snapshots {
            if !snapshot.is_pci_bridge() {
                continue;
            }
            let bridge = snapshot.location();
            let numbers = read(
                snapshot.bus,
                snapshot.dev,
                snapshot.func,
                PCI_CFG_BUS_NUMBERS,
            );
            let primary = numbers as u8;
            let secondary = (numbers >> 8) as u8;
            let subordinate = (numbers >> 16) as u8;
            if primary != bus || secondary == 0 || secondary > subordinate {
                return Err(PciTopologyError::InvalidBridgeWindow {
                    bridge,
                    primary,
                    secondary,
                    subordinate,
                });
            }
            if scheduled[secondary as usize] {
                return Err(PciTopologyError::DuplicateSecondaryBus { bridge, secondary });
            }
            scheduled[secondary as usize] = true;
            buses.push(secondary);
        }
        snapshots.extend(bus_snapshots);
    }
    Ok(snapshots)
}

/// A parsed PCI registry ID constraint, such as `PCI\VEN_8086&DEV_100E` or `PCI\CC_020000`.
///
/// Windows stores these strings under `Enum\PCI\...\HardwareID` and `CompatibleIDs`, ordered from
/// most to least specific. The PnP manager uses them to match an enumerated bus function to the
/// service selected by INF/registry state.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PciIdPattern {
    pub vendor: Option<u16>,
    pub device: Option<u16>,
    /// Class code parsed from `CC_...`. `class_digits` records whether the ID constrains the full
    /// 24-bit class/progif (`6`), base+subclass (`4`), or only base class (`2`).
    pub class: Option<u32>,
    pub class_digits: u8,
}

fn eq_ascii_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

fn starts_with_pci_prefix(id: &str) -> bool {
    let bytes = id.as_bytes();
    bytes.len() >= 4
        && eq_ascii_ignore_case(&bytes[..3], b"PCI")
        && matches!(bytes[3], b'\\' | b'/' | b'#')
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_hex_fixed(bytes: &[u8], pos: usize, digits: usize) -> Option<u32> {
    if pos + digits > bytes.len() {
        return None;
    }
    let mut value = 0u32;
    for &b in &bytes[pos..pos + digits] {
        value = (value << 4) | hex_nibble(b)? as u32;
    }
    Some(value)
}

fn find_hex_field(bytes: &[u8], prefix: &[u8], digits: usize) -> Option<u32> {
    let needed = prefix.len() + digits;
    if bytes.len() < needed {
        return None;
    }
    let end = bytes.len() - needed;
    let mut pos = 0usize;
    while pos <= end {
        if eq_ascii_ignore_case(&bytes[pos..pos + prefix.len()], prefix) {
            return parse_hex_fixed(bytes, pos + prefix.len(), digits);
        }
        pos += 1;
    }
    None
}

fn find_class_field(bytes: &[u8]) -> (Option<u32>, u8) {
    let mut cc_pos = None;
    let mut pos = 0usize;
    while pos + 3 <= bytes.len() {
        if eq_ascii_ignore_case(&bytes[pos..pos + 3], b"CC_") {
            cc_pos = Some(pos);
            break;
        }
        pos += 1;
    }
    let Some(cc_pos) = cc_pos else {
        return (None, 0);
    };
    let value_pos = cc_pos + 3;
    if let Some(value) = parse_hex_fixed(bytes, value_pos, 6) {
        (Some(value), 6)
    } else if let Some(value) = parse_hex_fixed(bytes, value_pos, 4) {
        (Some(value), 4)
    } else if let Some(value) = parse_hex_fixed(bytes, value_pos, 2) {
        (Some(value), 2)
    } else {
        (None, 0)
    }
}

/// Parse a PCI hardware/compatible/device-instance ID into match constraints.
///
/// This accepts the common NT forms:
/// `PCI\VEN_vvvv&DEV_dddd...`, `PCI\VEN_vvvv`, `PCI\VEN_vvvv&CC_ccccpp`,
/// `PCI\CC_ccccpp`, and the equivalent critical-device-database `PCI#...` prefix.
pub fn parse_pci_id_pattern(id: &str) -> Option<PciIdPattern> {
    if !starts_with_pci_prefix(id) {
        return None;
    }
    let bytes = id.as_bytes();
    let vendor = find_hex_field(bytes, b"VEN_", 4).map(|v| v as u16);
    let device = find_hex_field(bytes, b"DEV_", 4).map(|v| v as u16);
    let (class, class_digits) = find_class_field(bytes);
    if vendor.is_none() && device.is_none() && class.is_none() {
        return None;
    }
    Some(PciIdPattern {
        vendor,
        device,
        class,
        class_digits,
    })
}

impl PciIdPattern {
    /// Whether this registry ID constraint matches the enumerated PCI function.
    pub fn matches(&self, device: &PciDevice) -> bool {
        if self.vendor.is_some_and(|vendor| vendor != device.vendor) {
            return false;
        }
        if self.device.is_some_and(|dev| dev != device.device) {
            return false;
        }
        if let Some(class) = self.class {
            match self.class_digits {
                6 => {
                    if device.class != class {
                        return false;
                    }
                }
                4 => {
                    if (device.class >> 8) != class {
                        return false;
                    }
                }
                2 => {
                    if (device.class >> 16) != class {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }
}

fn find_device_for_id_pattern<'a>(devices: &'a [PciDevice], id: &str) -> Option<&'a PciDevice> {
    let pattern = parse_pci_id_pattern(id)?;
    devices.iter().find(|device| pattern.matches(device))
}

fn parse_hex_u8_token(token: &str) -> Option<u8> {
    let bytes = token.as_bytes();
    if bytes.is_empty() || bytes.len() > 2 {
        return None;
    }
    let mut value = 0u8;
    for &byte in bytes {
        value = (value << 4) | hex_nibble(byte)?;
    }
    Some(value)
}

fn pci_instance_location(instance_id: &str) -> Option<(u8, u8, u8)> {
    if !starts_with_pci_prefix(instance_id) {
        return None;
    }
    let instance = instance_id
        .rsplit(|ch| ch == '\\' || ch == '/' || ch == '#')
        .next()?;
    let mut bus_token = None;
    let mut request_token = None;
    for token in instance.split('&') {
        bus_token = request_token;
        request_token = Some(token);
    }
    let bus = parse_hex_u8_token(bus_token?)?;
    let request = parse_hex_u8_token(request_token?)?;
    let dev = (request >> 3) & 0x1f;
    let func = request & 0x07;
    Some((bus, dev, func))
}

/// Resolve a registry-imported PCI devnode to the enumerated PCI function it represents.
///
/// A complete `Enum\PCI` instance path can carry the bus and device/function in its final segment.
/// That location is the most specific identity when repeated identical functions exist. If it is
/// present, the match is exact and still checked against the instance's vendor/device/class
/// constraints. Devnodes without a usable location fall back to NT's normal ID ranking: hardware
/// IDs, then the instance path as an ID pattern, then compatible IDs from most to least specific.
pub fn find_pci_device_for_devnode<'a, H, C>(
    devices: &'a [PciDevice],
    instance_id: &str,
    hardware_ids: &[H],
    compatible_ids: &[C],
) -> Option<&'a PciDevice>
where
    H: AsRef<str>,
    C: AsRef<str>,
{
    if let Some((bus, dev, func)) = pci_instance_location(instance_id) {
        let device = devices
            .iter()
            .find(|device| device.bus == bus && device.dev == dev && device.func == func)?;
        if parse_pci_id_pattern(instance_id).is_some_and(|pattern| !pattern.matches(device)) {
            return None;
        }
        return Some(device);
    }

    for id in hardware_ids {
        if let Some(device) = find_device_for_id_pattern(devices, id.as_ref()) {
            return Some(device);
        }
    }
    if let Some(device) = find_device_for_id_pattern(devices, instance_id) {
        return Some(device);
    }
    for id in compatible_ids {
        if let Some(device) = find_device_for_id_pattern(devices, id.as_ref()) {
            return Some(device);
        }
    }
    None
}

/// Selects the bus-relative or translated side of one PnP resource assignment.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ResourceView {
    Raw,
    Translated,
}

/// The complete ordered resource assignment PnP produces for a device.
///
/// The raw and translated vectors have identical descriptor kinds at every index. Keeping both
/// sides explicit prevents the executive from reconstructing bus resources from translated values
/// after platform arbitration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceAssignment {
    raw: Vec<CmResourceDescriptor>,
    translated: Vec<CmResourceDescriptor>,
    /// The DMA common-buffer length in bytes (`0` = no DMA resource).
    pub dma_len: u64,
}

impl ResourceAssignment {
    fn new(
        raw: Vec<CmResourceDescriptor>,
        translated: Vec<CmResourceDescriptor>,
        dma_len: u64,
    ) -> Result<Self, ResourceRequirementsError> {
        if raw.is_empty() || raw.len() != translated.len() {
            return Err(ResourceRequirementsError::MissingInterruptTranslation);
        }
        for (raw, translated) in raw.iter().zip(&translated) {
            let valid_pair = match (*raw, *translated) {
                (CmResourceDescriptor::Memory(raw), CmResourceDescriptor::Memory(translated)) => {
                    raw.length != 0 && raw.length == translated.length
                }
                (CmResourceDescriptor::Port(raw), CmResourceDescriptor::Port(translated)) => {
                    raw.length != 0 && raw.length == translated.length
                }
                (CmResourceDescriptor::Interrupt(_), CmResourceDescriptor::Interrupt(_)) => true,
                _ => false,
            };
            if !valid_pair {
                return Err(ResourceRequirementsError::MissingInterruptTranslation);
            }
        }
        Ok(Self {
            raw,
            translated,
            dma_len,
        })
    }

    pub fn resources(&self, view: ResourceView) -> &[CmResourceDescriptor] {
        match view {
            ResourceView::Raw => &self.raw,
            ResourceView::Translated => &self.translated,
        }
    }

    pub fn memory_resources(
        &self,
        view: ResourceView,
    ) -> impl Iterator<Item = MemoryDescriptor> + '_ {
        self.resources(view)
            .iter()
            .filter_map(|resource| match resource {
                CmResourceDescriptor::Memory(memory) => Some(*memory),
                _ => None,
            })
    }

    pub fn port_resources(&self, view: ResourceView) -> impl Iterator<Item = PortDescriptor> + '_ {
        self.resources(view)
            .iter()
            .filter_map(|resource| match resource {
                CmResourceDescriptor::Port(port) => Some(*port),
                _ => None,
            })
    }

    pub fn interrupt_resource(&self, view: ResourceView) -> Option<InterruptDescriptor> {
        self.resources(view)
            .iter()
            .find_map(|resource| match resource {
                CmResourceDescriptor::Interrupt(interrupt) => Some(*interrupt),
                _ => None,
            })
    }
}

/// Select only the platform resources admitted by one function stack's filtered native list.
///
/// Raw and translated descriptors retain their exact pairing. The returned assignment therefore
/// names precisely the resources that may be published in START and minted into the driver
/// domain; unrequested platform candidates are not carried through as implicit grants.
pub fn select_resource_assignment(
    available: &ResourceAssignment,
    filtered_requirements: &[u8],
    interface_type: i32,
    bus_number: u32,
    slot_number: u32,
) -> Result<ResourceAssignment, ResourceRequirementsError> {
    let selected = nt_cm_resources::select_io_resource_assignment(
        filtered_requirements,
        interface_type,
        bus_number,
        slot_number,
        available.resources(ResourceView::Raw),
    )
    .map_err(ResourceRequirementsError::InvalidFilteredRequirements)?
    .ok_or(ResourceRequirementsError::UnsatisfiedFilteredRequirements)?;
    if selected.is_empty() {
        return Err(ResourceRequirementsError::UnsatisfiedFilteredRequirements);
    }
    let mut raw = Vec::new();
    let mut translated = Vec::new();
    raw.try_reserve_exact(selected.len())
        .map_err(|_| ResourceRequirementsError::OutOfMemory)?;
    translated
        .try_reserve_exact(selected.len())
        .map_err(|_| ResourceRequirementsError::OutOfMemory)?;
    for index in selected {
        let raw_descriptor = available
            .resources(ResourceView::Raw)
            .get(index)
            .copied()
            .ok_or(ResourceRequirementsError::UnsatisfiedFilteredRequirements)?;
        let translated_descriptor = available
            .resources(ResourceView::Translated)
            .get(index)
            .copied()
            .ok_or(ResourceRequirementsError::UnsatisfiedFilteredRequirements)?;
        raw.push(raw_descriptor);
        translated.push(translated_descriptor);
    }
    ResourceAssignment::new(raw, translated, available.dma_len)
}

/// A root-bus resource profile describes synthetic hardware enumerated by the native root bus.
/// The registry devnode still selects the service; this profile only describes the resource shape
/// the broker can mint for a root-enumerated device ID.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RootBusResourceProfile {
    pub device_id: &'static str,
    pub mmio_phys: u64,
    pub mmio_len: u64,
    pub interrupt_vector: u32,
    pub interrupt_latched: bool,
}

/// The DMA PnP proof device's root-bus register bank. The test driver reads a 4 KiB MMIO range
/// starting at this translated physical address and then acquires interrupt + common-buffer DMA
/// resources through the normal WDM calls.
pub const ROOT_DMA_TEST_RESOURCE_PROFILE: RootBusResourceProfile = RootBusResourceProfile {
    device_id: r"ROOT\USERSPACE_NTOS_DMA",
    mmio_phys: 0x1000_0000,
    mmio_len: 0x1000,
    interrupt_vector: 5,
    interrupt_latched: false,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceRequirementsError {
    UnassignedBar,
    UnsupportedBarLength,
    AddressOverflow,
    OutOfMemory,
    MissingInterruptTranslation,
    InvalidInterruptPin,
    InvalidFilteredRequirements(nt_cm_resources::IoResourceAssignmentError),
    UnsatisfiedFilteredRequirements,
    EncodeCm(nt_cm_resources::CmResourceListError),
    Encode(nt_cm_resources::IoResourceRequirementsError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PciBootResources {
    pub raw: Vec<u8>,
    pub translated: Vec<u8>,
}

/// One interrupt route selected by the platform interrupt provider after requirements filtering.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PciInterruptAssignment {
    /// Bus-relative interrupt level selected by the platform router.
    pub bus_level: u32,
    /// System vector after platform translation.
    pub vector: u32,
    pub latched: bool,
    pub affinity: u64,
}

/// Firmware/platform-owned INTx link routing for functions on one PCI bus.
///
/// Direct children use the standard PCI swizzle `(slot + pin - 1) mod 4`. The table contents are
/// supplied by the platform provider; this type does not embed a machine or device identity.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PciIntxRoutingTable {
    pub bus: u8,
    pub link_vectors: [Option<u32>; 4],
}

impl PciIntxRoutingTable {
    pub const fn new(bus: u8, link_vectors: [Option<u32>; 4]) -> Self {
        Self { bus, link_vectors }
    }

    pub fn route(&self, device: &PciDevice) -> Option<u32> {
        if device.bus != self.bus || !(1..=4).contains(&device.irq_pin) {
            return None;
        }
        let link = (device.dev as usize + device.irq_pin as usize - 1) & 3;
        self.link_vectors[link]
    }
}

fn memory_bar_flags(bar: &Bar) -> u16 {
    CM_RESOURCE_MEMORY_READ_WRITE
        | CM_RESOURCE_MEMORY_BAR
        | if bar.prefetchable {
            CM_RESOURCE_MEMORY_PREFETCHABLE
        } else {
            0
        }
}

fn port_bar_flags() -> u16 {
    CM_RESOURCE_PORT_IO
        | CM_RESOURCE_PORT_16_BIT_DECODE
        | CM_RESOURCE_PORT_POSITIVE_DECODE
        | CM_RESOURCE_PORT_BAR
}

/// Build the bus-relative and translated boot-resource snapshots for one PCI function.
///
/// BAR addresses use identity translation on the current x86 platform. Interrupt routing is kept
/// distinct: the raw list contains the PCI line with all-processor affinity, while the translated
/// list contains the vector and affinity selected by the interrupt broker.
pub fn pci_boot_resources(
    device: &PciDevice,
    translated_interrupt: Option<PciInterruptAssignment>,
) -> Result<Option<PciBootResources>, ResourceRequirementsError> {
    if device.irq_pin > 4 {
        return Err(ResourceRequirementsError::InvalidInterruptPin);
    }
    let has_raw_interrupt = device.irq_pin != 0 && !matches!(device.irq_line, 0 | u8::MAX);
    if (device.irq_pin == 0 && translated_interrupt.is_some())
        || has_raw_interrupt != translated_interrupt.is_some()
    {
        return Err(ResourceRequirementsError::MissingInterruptTranslation);
    }
    let descriptor_count = device
        .bars
        .iter()
        .filter(|bar| bar.is_present())
        .count()
        .saturating_add(has_raw_interrupt as usize);
    if descriptor_count == 0 {
        return Ok(None);
    }
    let mut raw_descriptors = Vec::new();
    let mut translated_descriptors = Vec::new();
    raw_descriptors
        .try_reserve_exact(descriptor_count)
        .map_err(|_| ResourceRequirementsError::OutOfMemory)?;
    translated_descriptors
        .try_reserve_exact(descriptor_count)
        .map_err(|_| ResourceRequirementsError::OutOfMemory)?;
    for bar in device.bars.iter().filter(|bar| bar.is_present()) {
        if !bar.is_assigned() {
            return Err(ResourceRequirementsError::UnassignedBar);
        }
        let length =
            u32::try_from(bar.size).map_err(|_| ResourceRequirementsError::UnsupportedBarLength)?;
        let descriptor = if bar.is_io {
            CmResourceDescriptor::Port(PortDescriptor {
                start: bar.base,
                length,
                flags: port_bar_flags(),
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            })
        } else {
            CmResourceDescriptor::Memory(MemoryDescriptor {
                start: bar.base,
                length,
                flags: memory_bar_flags(bar),
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            })
        };
        raw_descriptors.push(descriptor);
        translated_descriptors.push(descriptor);
    }
    if has_raw_interrupt {
        raw_descriptors.push(CmResourceDescriptor::Interrupt(InterruptDescriptor {
            level: device.irq_line as u32,
            vector: device.irq_line as u32,
            affinity: u64::MAX,
            flags: CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE,
            share: CM_RESOURCE_SHARE_SHARED,
        }));
        let translated = translated_interrupt.unwrap();
        translated_descriptors.push(CmResourceDescriptor::Interrupt(InterruptDescriptor {
            level: translated.vector,
            vector: translated.vector,
            affinity: translated.affinity,
            flags: if translated.latched {
                CM_RESOURCE_INTERRUPT_LATCHED
            } else {
                CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE
            },
            share: CM_RESOURCE_SHARE_SHARED,
        }));
    }
    let size = nt_cm_resources::cm_resource_list_size(descriptor_count)
        .ok_or(ResourceRequirementsError::AddressOverflow)?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(size)
        .map_err(|_| ResourceRequirementsError::OutOfMemory)?;
    raw.resize(size, 0);
    nt_cm_resources::build_cm_resource_list(
        &mut raw,
        INTERFACE_TYPE_PCI_BUS,
        device.bus as u32,
        &raw_descriptors,
    )
    .map_err(ResourceRequirementsError::EncodeCm)?;
    let mut translated = Vec::new();
    translated
        .try_reserve_exact(size)
        .map_err(|_| ResourceRequirementsError::OutOfMemory)?;
    translated.resize(size, 0);
    nt_cm_resources::build_cm_resource_list(
        &mut translated,
        INTERFACE_TYPE_PCI_BUS,
        device.bus as u32,
        &translated_descriptors,
    )
    .map_err(ResourceRequirementsError::EncodeCm)?;
    Ok(Some(PciBootResources { raw, translated }))
}

fn encode_resource_requirements(
    interface_type: i32,
    bus_number: u32,
    slot_number: u32,
    descriptors: &[IoResourceRequirement],
) -> Result<Option<Vec<u8>>, ResourceRequirementsError> {
    if descriptors.is_empty() {
        return Ok(None);
    }
    let size = nt_cm_resources::io_resource_requirements_list_size(descriptors.len())
        .ok_or(ResourceRequirementsError::AddressOverflow)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| ResourceRequirementsError::OutOfMemory)?;
    bytes.resize(size, 0);
    nt_cm_resources::build_io_resource_requirements_list(
        &mut bytes,
        interface_type,
        bus_number,
        slot_number,
        descriptors,
    )
    .map_err(ResourceRequirementsError::Encode)?;
    Ok(Some(bytes))
}

fn fixed_address_requirement(bar: &Bar) -> Result<IoAddressRequirement, ResourceRequirementsError> {
    if !bar.is_assigned() {
        return Err(ResourceRequirementsError::UnassignedBar);
    }
    let length =
        u32::try_from(bar.size).map_err(|_| ResourceRequirementsError::UnsupportedBarLength)?;
    let maximum = bar
        .base
        .checked_add(bar.size - 1)
        .ok_or(ResourceRequirementsError::AddressOverflow)?;
    if bar.is_io && maximum > u16::MAX as u64 {
        return Err(ResourceRequirementsError::UnsupportedBarLength);
    }
    Ok(IoAddressRequirement {
        option: IO_RESOURCE_REQUIRED,
        share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
        flags: if bar.is_io {
            CM_RESOURCE_PORT_IO
                | CM_RESOURCE_PORT_16_BIT_DECODE
                | CM_RESOURCE_PORT_POSITIVE_DECODE
                | CM_RESOURCE_PORT_BAR
        } else {
            memory_bar_flags(bar)
        },
        length,
        // This implementation advertises only the placement the capability broker can mint.
        alignment: 1,
        minimum: bar.base,
        maximum,
    })
}

/// Build the exact bus-owned requirements for one enumerated PCI function.
///
/// Every implemented BAR is represented. Until the resource arbiter can reprogram BARs and mint a
/// replacement capability set, the only advertised placement is the current one. An interrupt pin
/// remains a shared, level-sensitive bus-routing requirement over the native PCI vector range.
pub fn pci_resource_requirements(
    device: &PciDevice,
) -> Result<Option<Vec<u8>>, ResourceRequirementsError> {
    pci_resource_requirements_filtered(device, device.irq_pin != 0)
}

/// Apply the function-stack interrupt filter to the bus-owned PCI requirements. BAR requirements
/// remain immutable; only the interrupt requirement may be removed by a stack that does not
/// register an interrupt service routine.
pub fn pci_resource_requirements_filtered(
    device: &PciDevice,
    include_interrupt: bool,
) -> Result<Option<Vec<u8>>, ResourceRequirementsError> {
    if device.irq_pin > 4 {
        return Err(ResourceRequirementsError::InvalidInterruptPin);
    }
    if include_interrupt && device.irq_pin == 0 {
        return Err(ResourceRequirementsError::MissingInterruptTranslation);
    }
    let mut descriptors = Vec::new();
    descriptors
        .try_reserve(device.bars.len().saturating_add(1))
        .map_err(|_| ResourceRequirementsError::OutOfMemory)?;
    for bar in device.bars.iter().filter(|bar| bar.is_present()) {
        let address = fixed_address_requirement(bar)?;
        descriptors.push(if bar.is_io {
            IoResourceRequirement::Port(address)
        } else {
            IoResourceRequirement::Memory(address)
        });
    }
    if include_interrupt {
        descriptors.push(IoResourceRequirement::Interrupt(IoInterruptRequirement {
            option: IO_RESOURCE_REQUIRED,
            share: CM_RESOURCE_SHARE_SHARED,
            flags: CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE,
            minimum_vector: 0,
            maximum_vector: 0xff,
            affinity_policy: 0,
            priority_policy: 0,
            targeted_processors: 0,
        }));
    }
    encode_resource_requirements(
        INTERFACE_TYPE_PCI_BUS,
        device.bus as u32,
        device.slot_number(),
        &descriptors,
    )
}

/// Build the immutable requirements published by a broker-backed root-bus profile.
pub fn root_bus_resource_requirements(
    profile: &RootBusResourceProfile,
) -> Result<Vec<u8>, ResourceRequirementsError> {
    if profile.mmio_phys == 0 || profile.mmio_len == 0 || profile.interrupt_vector == 0 {
        return Err(ResourceRequirementsError::UnassignedBar);
    }
    let length = u32::try_from(profile.mmio_len)
        .map_err(|_| ResourceRequirementsError::UnsupportedBarLength)?;
    let maximum = profile
        .mmio_phys
        .checked_add(profile.mmio_len - 1)
        .ok_or(ResourceRequirementsError::AddressOverflow)?;
    let descriptors = [
        IoResourceRequirement::Memory(IoAddressRequirement {
            option: IO_RESOURCE_REQUIRED,
            share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            flags: CM_RESOURCE_MEMORY_READ_WRITE,
            length,
            alignment: 1,
            minimum: profile.mmio_phys,
            maximum,
        }),
        IoResourceRequirement::Interrupt(IoInterruptRequirement {
            option: IO_RESOURCE_REQUIRED,
            share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            flags: if profile.interrupt_latched {
                CM_RESOURCE_INTERRUPT_LATCHED
            } else {
                CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE
            },
            minimum_vector: profile.interrupt_vector,
            maximum_vector: profile.interrupt_vector,
            affinity_policy: 0,
            priority_policy: 0,
            targeted_processors: 0,
        }),
    ];
    encode_resource_requirements(INTERFACE_TYPE_PNP_BUS, 0, 0, &descriptors)?
        .ok_or(ResourceRequirementsError::UnassignedBar)
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RootBusResourceCatalogError {
    EmptyDeviceId,
    EmptyResource,
    DuplicateDeviceId,
    OutOfMemory,
}

/// Growable broker catalog for root-bus resource profiles.
///
/// Registry devnodes still select devices by instance/hardware/compatible IDs. This catalog only
/// records which root-enumerated resource profiles the trusted broker is currently prepared to mint.
#[derive(Clone, Debug, Default)]
pub struct RootBusResourceCatalog {
    profiles: Vec<RootBusResourceProfile>,
}

impl RootBusResourceCatalog {
    pub fn new() -> Self {
        Self {
            profiles: Vec::new(),
        }
    }

    pub fn profiles(&self) -> &[RootBusResourceProfile] {
        &self.profiles
    }

    pub fn register(
        &mut self,
        profile: RootBusResourceProfile,
    ) -> Result<(), RootBusResourceCatalogError> {
        if profile.device_id.is_empty() {
            return Err(RootBusResourceCatalogError::EmptyDeviceId);
        }
        if profile.mmio_phys == 0 || profile.mmio_len == 0 || profile.interrupt_vector == 0 {
            return Err(RootBusResourceCatalogError::EmptyResource);
        }
        if self
            .profiles
            .iter()
            .any(|existing| existing.device_id.eq_ignore_ascii_case(profile.device_id))
        {
            return Err(RootBusResourceCatalogError::DuplicateDeviceId);
        }
        self.profiles
            .try_reserve(1)
            .map_err(|_| RootBusResourceCatalogError::OutOfMemory)?;
        self.profiles.push(profile);
        Ok(())
    }

    pub fn find_for_devnode<H, C>(
        &self,
        instance_id: &str,
        hardware_ids: &[H],
        compatible_ids: &[C],
    ) -> Option<RootBusResourceProfile>
    where
        H: AsRef<str>,
        C: AsRef<str>,
    {
        self.profiles.iter().copied().find(|profile| {
            devnode_matches_root_bus_profile(instance_id, hardware_ids, compatible_ids, profile)
        })
    }
}

fn devnode_device_id(instance_id: &str) -> &str {
    match instance_id.rfind('\\') {
        Some(pos) => &instance_id[..pos],
        None => instance_id,
    }
}

fn id_matches_profile(id: &str, profile: &RootBusResourceProfile) -> bool {
    id.eq_ignore_ascii_case(profile.device_id)
}

/// Return true when a registry devnode instance path or ID list names a root-bus resource profile.
pub fn devnode_matches_root_bus_profile<H, C>(
    instance_id: &str,
    hardware_ids: &[H],
    compatible_ids: &[C],
    profile: &RootBusResourceProfile,
) -> bool
where
    H: AsRef<str>,
    C: AsRef<str>,
{
    id_matches_profile(devnode_device_id(instance_id), profile)
        || hardware_ids
            .iter()
            .any(|id| id_matches_profile(id.as_ref(), profile))
        || compatible_ids
            .iter()
            .any(|id| id_matches_profile(id.as_ref(), profile))
}

/// Assign resources to a root-bus devnode when its instance path or registry IDs match a known
/// broker-backed profile. This is the root-bus counterpart to PCI BAR assignment: the returned
/// abstract resource list still has to be minted by the executive before `START_DEVICE`.
pub fn assign_root_bus_resources<H, C>(
    instance_id: &str,
    hardware_ids: &[H],
    compatible_ids: &[C],
    profile: &RootBusResourceProfile,
    int_vector: u32,
    int_latched: bool,
    int_affinity: u64,
    dma_len: u64,
) -> Option<ResourceAssignment>
where
    H: AsRef<str>,
    C: AsRef<str>,
{
    if !devnode_matches_root_bus_profile(instance_id, hardware_ids, compatible_ids, profile)
        || profile.mmio_phys == 0
        || profile.mmio_len == 0
        || int_vector != profile.interrupt_vector
        || int_latched != profile.interrupt_latched
    {
        return None;
    }
    let length = u32::try_from(profile.mmio_len).ok()?;
    let memory = CmResourceDescriptor::Memory(MemoryDescriptor {
        start: profile.mmio_phys,
        length,
        flags: CM_RESOURCE_MEMORY_READ_WRITE,
        share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
    });
    let raw_interrupt = CmResourceDescriptor::Interrupt(InterruptDescriptor {
        level: int_vector,
        vector: int_vector,
        affinity: u64::MAX,
        flags: if int_latched {
            CM_RESOURCE_INTERRUPT_LATCHED
        } else {
            CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE
        },
        share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
    });
    let translated_interrupt = CmResourceDescriptor::Interrupt(InterruptDescriptor {
        level: int_vector,
        vector: int_vector,
        affinity: int_affinity,
        flags: if int_latched {
            CM_RESOURCE_INTERRUPT_LATCHED
        } else {
            CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE
        },
        share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
    });
    ResourceAssignment::new(
        alloc::vec![memory, raw_interrupt],
        alloc::vec![memory, translated_interrupt],
        dma_len,
    )
    .ok()
}

/// Assign resources to a device from its enumerated BARs and optional IRQ. `int_vector` is the
/// translated interrupt vector the executive has
/// arranged for this device; `0` means the bus assigned no interrupt. `dma_len` is the common-buffer
/// size the driver needs (`0` for none). Returns `None` if the device exposes no memory or port
/// resource.
pub fn assign_resources(
    device: &PciDevice,
    interrupt: Option<PciInterruptAssignment>,
    dma_len: u64,
) -> Result<Option<ResourceAssignment>, ResourceRequirementsError> {
    if device.irq_pin > 4 || (device.irq_pin == 0 && interrupt.is_some()) {
        return Err(ResourceRequirementsError::InvalidInterruptPin);
    }
    if device
        .bars
        .iter()
        .any(|bar| bar.is_present() && !bar.is_assigned())
    {
        return Err(ResourceRequirementsError::UnassignedBar);
    }
    let address_count = device.bars.iter().filter(|bar| bar.is_present()).count();
    if address_count == 0 {
        return Ok(None);
    }
    let count = address_count.saturating_add(interrupt.is_some() as usize);
    let mut raw = Vec::new();
    let mut translated = Vec::new();
    raw.try_reserve_exact(count)
        .map_err(|_| ResourceRequirementsError::OutOfMemory)?;
    translated
        .try_reserve_exact(count)
        .map_err(|_| ResourceRequirementsError::OutOfMemory)?;
    for bar in device.bars.iter().filter(|bar| bar.is_present()) {
        let length =
            u32::try_from(bar.size).map_err(|_| ResourceRequirementsError::UnsupportedBarLength)?;
        let descriptor = if bar.is_io {
            let end = bar
                .base
                .checked_add(bar.size - 1)
                .ok_or(ResourceRequirementsError::AddressOverflow)?;
            if end > u16::MAX as u64 {
                return Err(ResourceRequirementsError::UnsupportedBarLength);
            }
            CmResourceDescriptor::Port(PortDescriptor {
                start: bar.base,
                length,
                flags: port_bar_flags(),
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            })
        } else {
            CmResourceDescriptor::Memory(MemoryDescriptor {
                start: bar.base,
                length,
                flags: memory_bar_flags(bar),
                share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
            })
        };
        raw.push(descriptor);
        translated.push(descriptor);
    }
    if let Some(interrupt) = interrupt {
        raw.push(CmResourceDescriptor::Interrupt(InterruptDescriptor {
            level: interrupt.bus_level,
            vector: interrupt.bus_level,
            affinity: u64::MAX,
            flags: CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE,
            share: CM_RESOURCE_SHARE_SHARED,
        }));
        translated.push(CmResourceDescriptor::Interrupt(InterruptDescriptor {
            level: interrupt.vector,
            vector: interrupt.vector,
            affinity: interrupt.affinity,
            flags: if interrupt.latched {
                CM_RESOURCE_INTERRUPT_LATCHED
            } else {
                CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE
            },
            share: CM_RESOURCE_SHARE_SHARED,
        }));
    }
    ResourceAssignment::new(raw, translated, dma_len).map(Some)
}

/// The largest `CM_RESOURCE_LIST` this crate currently emits for one device.
pub const ASSIGNMENT_CM_LIST_MAX_SIZE: usize = 20 + (PCI_NUM_BARS + 1) * 20;

/// Encode a [`ResourceAssignment`] as the `CM_RESOURCE_LIST` a WDK driver reads at
/// `IRP_MN_START_DEVICE`. The selected side preserves the bus descriptor order exactly.
pub fn assignment_to_cm_list(
    buf: &mut [u8],
    interface_type: i32,
    bus_number: u32,
    assign: &ResourceAssignment,
    view: ResourceView,
) -> Result<usize, nt_cm_resources::CmResourceListError> {
    nt_cm_resources::build_cm_resource_list(buf, interface_type, bus_number, assign.resources(view))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use core::cell::RefCell;

    fn interrupt(vector: u32, latched: bool, affinity: u64) -> Option<PciInterruptAssignment> {
        Some(PciInterruptAssignment {
            bus_level: vector,
            vector,
            latched,
            affinity,
        })
    }

    /// A mock PCI config space: a map of `(dev, func, off) -> dword`, with the size-probe protocol
    /// implemented (an all-ones write to a BAR latches the size mask; reading back returns it; any
    /// other write restores the stored value). Enough to drive the enumerator end-to-end.
    struct MockConfig {
        /// (dev, func, off) -> stored dword.
        regs: RefCell<vec::Vec<((u8, u8, u8), u32)>>,
        /// (dev, func, bar_off) -> size mask returned after an all-ones write.
        bar_masks: vec::Vec<((u8, u8, u8), u32)>,
    }

    struct MockTopology {
        regs: RefCell<vec::Vec<((u8, u8, u8, u8), u32)>>,
    }

    impl MockTopology {
        fn get(&self, bus: u8, dev: u8, func: u8, off: u8) -> u32 {
            self.regs
                .borrow()
                .iter()
                .find(|(key, _)| *key == (bus, dev, func, off))
                .map(|(_, value)| *value)
                .unwrap_or_else(|| {
                    if off == PCI_CFG_HEADER || off == PCI_CFG_COMMAND_STATUS {
                        0
                    } else {
                        0xffff_ffff
                    }
                })
        }

        fn set(&self, bus: u8, dev: u8, func: u8, off: u8, value: u32) {
            let mut regs = self.regs.borrow_mut();
            if let Some(entry) = regs
                .iter_mut()
                .find(|(key, _)| *key == (bus, dev, func, off))
            {
                entry.1 = value;
            } else {
                regs.push(((bus, dev, func, off), value));
            }
        }

        fn write(&self, bus: u8, dev: u8, func: u8, off: u8, value: u32) {
            if value == 0xffff_ffff
                && (PCI_CFG_BAR0..PCI_CFG_BAR0 + (PCI_NUM_BARS as u8) * 4).contains(&off)
                && (off - PCI_CFG_BAR0) % 4 == 0
            {
                self.set(bus, dev, func, off, 0);
            } else {
                self.set(bus, dev, func, off, value);
            }
        }
    }

    impl MockConfig {
        fn get(&self, dev: u8, func: u8, off: u8) -> u32 {
            self.regs
                .borrow()
                .iter()
                .find(|(k, _)| *k == (dev, func, off))
                .map(|(_, v)| *v)
                .unwrap_or_else(|| {
                    if off == PCI_CFG_HEADER || off == PCI_CFG_COMMAND_STATUS {
                        0
                    } else {
                        0xFFFF_FFFF
                    }
                })
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
                if let Some((_, mask)) = self.bar_masks.iter().find(|(k, _)| *k == (dev, func, off))
                {
                    self.set(dev, func, off, *mask);
                    return;
                }
                if (PCI_CFG_BAR0..PCI_CFG_BAR0 + (PCI_NUM_BARS as u8) * 4).contains(&off)
                    && (off - PCI_CFG_BAR0) % 4 == 0
                {
                    self.set(dev, func, off, 0);
                    return;
                }
            }
            self.set(dev, func, off, v);
        }
    }

    /// Build a mock with a single NIC at 00:03.0: Intel e1000 (8086:100E), class 0x020000
    /// (network/ethernet), BAR0 = 32-bit memory @ 0xFEBC_0000 size 128 KiB, BAR1 = I/O ports
    /// @ 0xC000 size 64 bytes, IRQ line 11 pin INTA.
    fn nic_mock() -> MockConfig {
        let regs = vec![
            ((3, 0, PCI_CFG_VENDOR_DEVICE), 0x100E_8086),
            ((3, 0, PCI_CFG_COMMAND_STATUS), 0xABCD_0007),
            ((3, 0, PCI_CFG_CLASS_REV), 0x0200_0000), // class 0x020000 in the high 24 bits
            ((3, 0, PCI_CFG_BAR0), 0xFEBC_0000),      // 32-bit mem BAR base
            ((3, 0, PCI_CFG_BAR0 + 4), 0xC001),       // I/O BAR base
            ((3, 0, PCI_CFG_INTERRUPT), 0x0000_010B), // pin=INTA(1) line=11(0x0B)
        ];
        MockConfig {
            regs: RefCell::new(regs),
            bar_masks: vec![
                // 128 KiB memory BAR => mask 0xFFFE_0000 (size = ~mask+1 = 0x2_0000).
                ((3, 0, PCI_CFG_BAR0), 0xFFFE_0000),
                // 64-byte I/O BAR => mask 0xFFFF_FFC1 after I/O flag bits.
                ((3, 0, PCI_CFG_BAR0 + 4), 0xFFFF_FFC1),
            ],
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
        let port = nic.first_io_bar().unwrap();
        assert!(port.is_io);
        assert_eq!(port.base, 0xC000);
        assert_eq!(port.size, 0x40);
    }

    #[test]
    fn hierarchy_walk_follows_configured_bridge_secondary_bus() {
        let topology = MockTopology {
            regs: RefCell::new(vec![
                ((0, 1, 0, PCI_CFG_VENDOR_DEVICE), 0x1111_8086),
                ((0, 1, 0, PCI_CFG_CLASS_REV), 0x0604_0000),
                (
                    (0, 1, 0, PCI_CFG_HEADER),
                    (PCI_HEADER_TYPE_BRIDGE as u32) << 16,
                ),
                ((0, 1, 0, PCI_CFG_BUS_NUMBERS), 0x0002_0200),
                ((0, 1, 0, PCI_CFG_INTERRUPT), 0),
                ((2, 4, 0, PCI_CFG_VENDOR_DEVICE), 0x100e_8086),
                ((2, 4, 0, PCI_CFG_CLASS_REV), 0x0200_0000),
                ((2, 4, 0, PCI_CFG_INTERRUPT), 0x0000_010b),
            ]),
        };

        let devices = enumerate_hierarchy(
            0,
            |bus, dev, func, off| topology.get(bus, dev, func, off),
            |bus, dev, func, off, value| topology.write(bus, dev, func, off, value),
        )
        .unwrap();
        assert_eq!(devices.len(), 2);
        assert_eq!(PciLocation::from(&devices[0]), PciLocation::new(0, 1, 0));
        assert_eq!(PciLocation::from(&devices[1]), PciLocation::new(2, 4, 0));
    }

    #[test]
    fn hierarchy_walk_rejects_duplicate_secondary_bus_ownership() {
        let topology = MockTopology {
            regs: RefCell::new(vec![
                ((0, 1, 0, PCI_CFG_VENDOR_DEVICE), 0x1111_8086),
                ((0, 1, 0, PCI_CFG_CLASS_REV), 0x0604_0000),
                (
                    (0, 1, 0, PCI_CFG_HEADER),
                    (PCI_HEADER_TYPE_BRIDGE as u32) << 16,
                ),
                ((0, 1, 0, PCI_CFG_BUS_NUMBERS), 0x0002_0200),
                ((0, 1, 0, PCI_CFG_INTERRUPT), 0),
                ((0, 2, 0, PCI_CFG_VENDOR_DEVICE), 0x2222_8086),
                ((0, 2, 0, PCI_CFG_CLASS_REV), 0x0604_0000),
                (
                    (0, 2, 0, PCI_CFG_HEADER),
                    (PCI_HEADER_TYPE_BRIDGE as u32) << 16,
                ),
                ((0, 2, 0, PCI_CFG_BUS_NUMBERS), 0x0002_0200),
                ((0, 2, 0, PCI_CFG_INTERRUPT), 0),
            ]),
        };

        assert_eq!(
            enumerate_hierarchy(
                0,
                |bus, dev, func, off| topology.get(bus, dev, func, off),
                |bus, dev, func, off, value| topology.write(bus, dev, func, off, value),
            ),
            Err(PciTopologyError::DuplicateSecondaryBus {
                bridge: PciLocation::new(0, 2, 0),
                secondary: 2,
            })
        );
    }

    #[test]
    fn probe_restores_the_bar_after_sizing() {
        let m = nic_mock();
        let _ = enumerate_function(0, 3, 0, |o| m.read(3, 0, o), |o, v| m.write(3, 0, o, v));
        // The BAR must be restored to its original value after the size probe.
        assert_eq!(m.get(3, 0, PCI_CFG_BAR0), 0xFEBC_0000);
        // Only command bits are restored. The status half is written as zero so W1C status bits
        // cannot be cleared by the sizing transaction.
        assert_eq!(m.get(3, 0, PCI_CFG_COMMAND_STATUS), 0x0000_0007);
    }

    #[test]
    fn bridge_header_probes_only_its_two_bar_slots() {
        let regs = vec![
            ((8, 0, PCI_CFG_VENDOR_DEVICE), 0x5678_1234),
            ((8, 0, PCI_CFG_CLASS_REV), 0x0604_0000),
            (
                (8, 0, PCI_CFG_HEADER),
                (PCI_HEADER_TYPE_BRIDGE as u32) << 16,
            ),
            ((8, 0, PCI_CFG_BAR0), 0x9000_0000),
            ((8, 0, PCI_CFG_BAR0 + 8), 0xA000_0000),
            ((8, 0, PCI_CFG_INTERRUPT), 0),
        ];
        let m = MockConfig {
            regs: RefCell::new(regs),
            bar_masks: vec![
                ((8, 0, PCI_CFG_BAR0), 0xFFFF_F000),
                // This is a bridge-bus-number register, not BAR2. A six-BAR probe would publish it.
                ((8, 0, PCI_CFG_BAR0 + 8), 0xFFFF_F000),
            ],
        };
        let device =
            enumerate_function(0, 8, 0, |o| m.read(8, 0, o), |o, v| m.write(8, 0, o, v)).unwrap();
        assert_eq!(device.bars.len(), 1);
        assert_eq!(device.bars[0].index, 0);
        assert_eq!(m.get(8, 0, PCI_CFG_BAR0 + 8), 0xA000_0000);
    }

    #[test]
    fn unpaired_64_bit_bar_does_not_probe_expansion_rom() {
        let bar5 = PCI_CFG_BAR0 + 5 * 4;
        let expansion_rom = bar5 + 4;
        let regs = vec![
            ((9, 0, PCI_CFG_VENDOR_DEVICE), 0x5678_1234),
            ((9, 0, PCI_CFG_CLASS_REV), 0x0200_0000),
            ((9, 0, bar5), 0xD000_0004),
            ((9, 0, expansion_rom), 0xE000_0001),
            ((9, 0, PCI_CFG_INTERRUPT), 0),
        ];
        let m = MockConfig {
            regs: RefCell::new(regs),
            bar_masks: vec![
                ((9, 0, bar5), 0xFFFF_F004),
                ((9, 0, expansion_rom), 0xFFFF_F800),
            ],
        };
        let device =
            enumerate_function(0, 9, 0, |o| m.read(9, 0, o), |o, v| m.write(9, 0, o, v)).unwrap();
        assert!(device.bars.iter().all(|bar| bar.index != 5));
        assert_eq!(m.get(9, 0, expansion_rom), 0xE000_0001);
    }

    #[test]
    fn probes_and_restores_complete_prefetchable_64_bit_bar() {
        let regs = vec![
            ((6, 0, PCI_CFG_VENDOR_DEVICE), 0x5678_1234),
            ((6, 0, PCI_CFG_CLASS_REV), 0x0200_0000),
            ((6, 0, PCI_CFG_BAR0), 0x4000_000c),
            ((6, 0, PCI_CFG_BAR0 + 4), 0x0000_0001),
            ((6, 0, PCI_CFG_INTERRUPT), 0),
        ];
        let m = MockConfig {
            regs: RefCell::new(regs),
            bar_masks: vec![
                ((6, 0, PCI_CFG_BAR0), 0xffe0_000c),
                ((6, 0, PCI_CFG_BAR0 + 4), 0xffff_ffff),
            ],
        };
        let device =
            enumerate_function(0, 6, 0, |o| m.read(6, 0, o), |o, v| m.write(6, 0, o, v)).unwrap();
        assert_eq!(device.bars.len(), 1);
        let bar = device.first_memory_bar().unwrap();
        assert!(bar.is_64bit);
        assert!(bar.prefetchable);
        assert_eq!(bar.base, 0x1_4000_0000);
        assert_eq!(bar.size, 0x20_0000);
        assert_eq!(bar.maximum_address, u64::MAX);
        assert_eq!(m.get(6, 0, PCI_CFG_BAR0), 0x4000_000c);
        assert_eq!(m.get(6, 0, PCI_CFG_BAR0 + 4), 1);
    }

    #[test]
    fn pci_bus_publishes_all_bar_and_interrupt_requirements() {
        let m = nic_mock();
        let device =
            enumerate_function(0, 3, 0, |o| m.read(3, 0, o), |o, v| m.write(3, 0, o, v)).unwrap();
        let bytes = pci_resource_requirements(&device).unwrap().unwrap();
        assert_eq!(bytes.len(), 40 + 3 * 32);
        assert_eq!(u32::from_le_bytes(bytes[0..4].try_into().unwrap()), 136);
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 5);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(bytes[36..40].try_into().unwrap()), 3);

        assert_eq!(bytes[40], IO_RESOURCE_REQUIRED);
        assert_eq!(bytes[41], nt_cm_resources::CM_RESOURCE_TYPE_MEMORY);
        assert_eq!(
            u32::from_le_bytes(bytes[48..52].try_into().unwrap()),
            0x2_0000
        );
        assert_eq!(
            u64::from_le_bytes(bytes[56..64].try_into().unwrap()),
            0xfebc_0000
        );
        assert_eq!(
            u64::from_le_bytes(bytes[64..72].try_into().unwrap()),
            0xfebd_ffff
        );

        assert_eq!(bytes[73], nt_cm_resources::CM_RESOURCE_TYPE_PORT);
        assert_eq!(
            u64::from_le_bytes(bytes[88..96].try_into().unwrap()),
            0xc000
        );
        assert_eq!(
            u64::from_le_bytes(bytes[96..104].try_into().unwrap()),
            0xc03f
        );

        assert_eq!(bytes[105], nt_cm_resources::CM_RESOURCE_TYPE_INTERRUPT);
        assert_eq!(bytes[106], CM_RESOURCE_SHARE_SHARED);
        assert_eq!(u32::from_le_bytes(bytes[112..116].try_into().unwrap()), 0);
        assert_eq!(
            u32::from_le_bytes(bytes[116..120].try_into().unwrap()),
            0xff
        );
    }

    #[test]
    fn pci_boot_resources_preserve_bar_order_flags_and_interrupt_translation() {
        let m = nic_mock();
        let device =
            enumerate_function(0, 3, 0, |o| m.read(3, 0, o), |o, v| m.write(3, 0, o, v)).unwrap();
        let resources = pci_boot_resources(&device, interrupt(5, true, 0x3))
            .unwrap()
            .unwrap();

        assert_eq!(resources.raw.len(), 80);
        assert_eq!(resources.translated.len(), 80);
        for bytes in [&resources.raw, &resources.translated] {
            assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 5);
            assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 0);
            assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), 3);
            assert_eq!(bytes[20], nt_cm_resources::CM_RESOURCE_TYPE_MEMORY);
            assert_eq!(bytes[40], nt_cm_resources::CM_RESOURCE_TYPE_PORT);
            assert_eq!(bytes[60], nt_cm_resources::CM_RESOURCE_TYPE_INTERRUPT);
            assert_eq!(
                u16::from_le_bytes(bytes[22..24].try_into().unwrap()),
                CM_RESOURCE_MEMORY_READ_WRITE | CM_RESOURCE_MEMORY_BAR
            );
            assert_eq!(
                u16::from_le_bytes(bytes[42..44].try_into().unwrap()),
                port_bar_flags()
            );
            assert_eq!(bytes[61], CM_RESOURCE_SHARE_SHARED);
        }
        assert_eq!(
            u32::from_le_bytes(resources.raw[64..68].try_into().unwrap()),
            11
        );
        assert_eq!(
            u32::from_le_bytes(resources.raw[68..72].try_into().unwrap()),
            11
        );
        assert_eq!(
            u64::from_le_bytes(resources.raw[72..80].try_into().unwrap()),
            u64::MAX
        );
        assert_eq!(
            u16::from_le_bytes(resources.raw[62..64].try_into().unwrap()),
            CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE
        );
        assert_eq!(
            u32::from_le_bytes(resources.translated[64..68].try_into().unwrap()),
            5
        );
        assert_eq!(
            u32::from_le_bytes(resources.translated[68..72].try_into().unwrap()),
            5
        );
        assert_eq!(
            u64::from_le_bytes(resources.translated[72..80].try_into().unwrap()),
            0x3
        );
        assert_eq!(
            u16::from_le_bytes(resources.translated[62..64].try_into().unwrap()),
            CM_RESOURCE_INTERRUPT_LATCHED
        );
    }

    #[test]
    fn root_profile_publishes_fixed_bus_requirements() {
        let bytes = root_bus_resource_requirements(&ROOT_DMA_TEST_RESOURCE_PROFILE).unwrap();
        assert_eq!(bytes.len(), 104);
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 15);
        assert_eq!(u32::from_le_bytes(bytes[36..40].try_into().unwrap()), 2);
        assert_eq!(bytes[41], nt_cm_resources::CM_RESOURCE_TYPE_MEMORY);
        assert_eq!(
            u64::from_le_bytes(bytes[56..64].try_into().unwrap()),
            0x1000_0000
        );
        assert_eq!(bytes[73], nt_cm_resources::CM_RESOURCE_TYPE_INTERRUPT);
        assert_eq!(u32::from_le_bytes(bytes[80..84].try_into().unwrap()), 5);
        assert_eq!(u32::from_le_bytes(bytes[84..88].try_into().unwrap()), 5);
    }

    #[test]
    fn parses_pci_registry_id_patterns() {
        assert_eq!(
            parse_pci_id_pattern(r"PCI\VEN_8086&DEV_100E&SUBSYS_00008086&REV_02"),
            Some(PciIdPattern {
                vendor: Some(0x8086),
                device: Some(0x100E),
                class: None,
                class_digits: 0,
            })
        );
        assert_eq!(
            parse_pci_id_pattern(r"pci\ven_8086&cc_020000"),
            Some(PciIdPattern {
                vendor: Some(0x8086),
                device: None,
                class: Some(0x020000),
                class_digits: 6,
            })
        );
        assert_eq!(
            parse_pci_id_pattern(r"PCI#CC_0200"),
            Some(PciIdPattern {
                vendor: None,
                device: None,
                class: Some(0x0200),
                class_digits: 4,
            })
        );
        assert!(parse_pci_id_pattern(r"ROOT\USERSPLACE_NTOS_INTERFACE_TEST").is_none());
    }

    #[test]
    fn matches_pci_devnode_by_hardware_id_before_broad_compatible_id() {
        let devices = vec![
            PciDevice {
                bus: 0,
                dev: 0,
                func: 0,
                vendor: 0x8086,
                device: 0x29C0,
                class: 0x060000,
                irq_line: 0,
                irq_pin: 0,
                bars: vec![],
            },
            PciDevice {
                bus: 0,
                dev: 3,
                func: 0,
                vendor: 0x8086,
                device: 0x100E,
                class: 0x020000,
                irq_line: 11,
                irq_pin: 1,
                bars: vec![Bar {
                    index: 0,
                    is_io: false,
                    is_64bit: false,
                    prefetchable: false,
                    base: 0xFEBC_0000,
                    size: 0x2_0000,
                    maximum_address: u32::MAX as u64,
                }],
            },
        ];
        let dev = find_pci_device_for_devnode(
            &devices,
            r"PCI\VEN_8086&DEV_100E\3&11583659&0&18",
            &[r"PCI\VEN_8086&DEV_100E"],
            &[r"PCI\VEN_8086"],
        )
        .unwrap();
        assert_eq!(dev.dev, 3);
        assert_eq!(dev.device, 0x100E);
    }

    #[test]
    fn matches_pci_devnode_from_instance_path_when_id_lists_are_empty() {
        let m = nic_mock();
        let devs = enumerate_bus(
            0,
            |d, f, o| m.read(d, f, o),
            |d, f, o, v| m.write(d, f, o, v),
        );
        let dev = find_pci_device_for_devnode(
            &devs,
            r"PCI\VEN_8086&DEV_100E\3&11583659&0&18",
            &[] as &[&str],
            &[] as &[&str],
        )
        .unwrap();
        assert_eq!(dev.vendor, 0x8086);
        assert_eq!(dev.device, 0x100E);
    }

    #[test]
    fn matches_repeated_pci_devices_by_instance_location() {
        let devices = vec![
            PciDevice {
                bus: 0,
                dev: 3,
                func: 0,
                vendor: 0x8086,
                device: 0x100E,
                class: 0x020000,
                irq_line: 11,
                irq_pin: 1,
                bars: vec![Bar {
                    index: 0,
                    is_io: false,
                    is_64bit: false,
                    prefetchable: false,
                    base: 0xFEBC_0000,
                    size: 0x2_0000,
                    maximum_address: u32::MAX as u64,
                }],
            },
            PciDevice {
                bus: 0,
                dev: 4,
                func: 0,
                vendor: 0x8086,
                device: 0x100E,
                class: 0x020000,
                irq_line: 10,
                irq_pin: 1,
                bars: vec![Bar {
                    index: 0,
                    is_io: false,
                    is_64bit: false,
                    prefetchable: false,
                    base: 0xFEBA_0000,
                    size: 0x2_0000,
                    maximum_address: u32::MAX as u64,
                }],
            },
        ];

        let first = find_pci_device_for_devnode(
            &devices,
            r"PCI\VEN_8086&DEV_100E\3&11583659&0&18",
            &[r"PCI\VEN_8086&DEV_100E"],
            &[r"PCI\CC_020000"],
        )
        .unwrap();
        let second = find_pci_device_for_devnode(
            &devices,
            r"PCI\VEN_8086&DEV_100E\3&11583659&0&20",
            &[r"PCI\VEN_8086&DEV_100E"],
            &[r"PCI\CC_020000"],
        )
        .unwrap();

        assert_eq!(first.dev, 3);
        assert_eq!(first.first_memory_bar().unwrap().base, 0xFEBC_0000);
        assert_eq!(second.dev, 4);
        assert_eq!(second.first_memory_bar().unwrap().base, 0xFEBA_0000);
    }

    #[test]
    fn exact_pci_instance_location_does_not_fall_back_to_generic_id() {
        let m = nic_mock();
        let devs = enumerate_bus(
            0,
            |d, f, o| m.read(d, f, o),
            |d, f, o, v| m.write(d, f, o, v),
        );
        let dev = find_pci_device_for_devnode(
            &devs,
            r"PCI\VEN_8086&DEV_100E\3&11583659&0&20",
            &[r"PCI\VEN_8086&DEV_100E"],
            &[r"PCI\CC_020000"],
        );
        assert!(dev.is_none());
    }

    #[test]
    fn matches_pci_devnode_by_compatible_class_id() {
        let m = nic_mock();
        let devs = enumerate_bus(
            0,
            |d, f, o| m.read(d, f, o),
            |d, f, o, v| m.write(d, f, o, v),
        );
        let dev = find_pci_device_for_devnode(
            &devs,
            r"PCI\VEN_DEAD&DEV_BEEF\0000",
            &[] as &[&str],
            &[r"PCI\CC_020000"],
        )
        .unwrap();
        assert_eq!(dev.class, 0x020000);

        let dev = find_pci_device_for_devnode(
            &devs,
            r"PCI\VEN_DEAD&DEV_BEEF\0000",
            &[] as &[&str],
            &[r"PCI\CC_0200"],
        )
        .unwrap();
        assert_eq!(dev.class, 0x020000);
    }

    #[test]
    fn absent_device_terminates_scan() {
        // Empty config space => every read is 0xFFFF => no devices.
        let m = MockConfig {
            regs: RefCell::new(vec![]),
            bar_masks: vec![],
        };
        let devs = enumerate_bus(
            0,
            |d, f, o| m.read(d, f, o),
            |d, f, o, v| m.write(d, f, o, v),
        );
        assert!(devs.is_empty());
    }

    #[test]
    fn assigns_resources_and_builds_cm_list() {
        let m = nic_mock();
        let devs = enumerate_bus(
            0,
            |d, f, o| m.read(d, f, o),
            |d, f, o, v| m.write(d, f, o, v),
        );
        let nic = find_pci_device_for_devnode(
            &devs,
            r"PCI\VEN_8086&DEV_100E\3&11583659&0&18",
            &[r"PCI\VEN_8086&DEV_100E"],
            &[r"PCI\CC_020000"],
        )
        .unwrap();
        let assign = assign_resources(nic, interrupt(5, true, 1), 0x1000)
            .unwrap()
            .unwrap();
        let memory = assign
            .memory_resources(ResourceView::Translated)
            .next()
            .unwrap();
        let port = assign
            .port_resources(ResourceView::Translated)
            .next()
            .unwrap();
        let interrupt = assign.interrupt_resource(ResourceView::Translated).unwrap();
        assert_eq!(memory.start, 0xFEBC_0000);
        assert_eq!(memory.length, 0x2_0000);
        assert_eq!(port.start, 0xC000);
        assert_eq!(port.length, 0x40);
        assert_eq!(
            port.flags,
            CM_RESOURCE_PORT_IO
                | CM_RESOURCE_PORT_16_BIT_DECODE
                | CM_RESOURCE_PORT_POSITIVE_DECODE
                | CM_RESOURCE_PORT_BAR
        );
        assert_eq!(interrupt.vector, 5);
        assert_eq!(interrupt.flags, CM_RESOURCE_INTERRUPT_LATCHED);
        assert_eq!(assign.dma_len, 0x1000);

        // The resource list names the caller-supplied translated memory address, the port BAR, and
        // the translated vector.
        let mut buf = [0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
        let memory_start = 0xFEBC_0000u64;
        let n = assignment_to_cm_list(
            &mut buf,
            INTERFACE_TYPE_PCI_BUS,
            0,
            &assign,
            ResourceView::Translated,
        )
        .unwrap();
        assert_eq!(n, MEMORY_PORT_INTERRUPT_LIST_SIZE);
        let (mem, port, int) = nt_cm_resources::decode_memory_port_interrupt_list(&buf).unwrap();
        assert_eq!(mem.start, memory_start);
        assert_eq!(mem.length, 0x2_0000);
        assert_eq!(port.start, 0xC000);
        assert_eq!(port.length, 0x40);
        assert_eq!(
            port.flags,
            assign
                .port_resources(ResourceView::Translated)
                .next()
                .unwrap()
                .flags
        );
        assert_eq!(port.share, CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE);
        assert_eq!(int.share, CM_RESOURCE_SHARE_SHARED);
        assert_eq!(int.vector, 5);
        assert_eq!(int.flags, CM_RESOURCE_INTERRUPT_LATCHED);
        assert_eq!(int.affinity, 1);
    }

    #[test]
    fn assigns_io_only_pci_resources_and_builds_cm_list() {
        let regs = vec![
            ((4, 0, PCI_CFG_VENDOR_DEVICE), 0x0019_1011),
            ((4, 0, PCI_CFG_CLASS_REV), 0x0200_0000),
            ((4, 0, PCI_CFG_BAR0), 0x6001),
            ((4, 0, PCI_CFG_BAR0 + 4), 0),
            ((4, 0, PCI_CFG_INTERRUPT), 0x0000_010A),
        ];
        let m = MockConfig {
            regs: RefCell::new(regs),
            bar_masks: vec![((4, 0, PCI_CFG_BAR0), 0xFFFF_FF81)],
        };
        let dev =
            enumerate_function(0, 4, 0, |o| m.read(4, 0, o), |o, v| m.write(4, 0, o, v)).unwrap();
        assert!(dev.first_memory_bar().is_none());
        let assign = assign_resources(&dev, interrupt(10, false, 1), 0x1000)
            .unwrap()
            .unwrap();
        assert_eq!(assign.memory_resources(ResourceView::Translated).count(), 0);
        let assigned_port = assign
            .port_resources(ResourceView::Translated)
            .next()
            .unwrap();
        assert_eq!(assigned_port.start, 0x6000);
        assert_eq!(assigned_port.length, 0x80);
        assert_eq!(
            assigned_port.flags,
            CM_RESOURCE_PORT_IO
                | CM_RESOURCE_PORT_16_BIT_DECODE
                | CM_RESOURCE_PORT_POSITIVE_DECODE
                | CM_RESOURCE_PORT_BAR
        );
        let assigned_interrupt = assign.interrupt_resource(ResourceView::Translated).unwrap();
        assert_eq!(assigned_interrupt.vector, 10);
        assert_eq!(
            assigned_interrupt.flags,
            CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE
        );
        assert_eq!(assign.dma_len, 0x1000);

        let mut buf = [0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
        let n = assignment_to_cm_list(
            &mut buf,
            INTERFACE_TYPE_PCI_BUS,
            0,
            &assign,
            ResourceView::Translated,
        )
        .unwrap();
        assert_eq!(n, PORT_INTERRUPT_LIST_SIZE);
        let (port, int) = nt_cm_resources::decode_port_interrupt_list(&buf).unwrap();
        assert_eq!(port.start, 0x6000);
        assert_eq!(port.length, 0x80);
        assert_eq!(port.flags, assigned_port.flags);
        assert_eq!(int.vector, 10);
        assert_eq!(int.flags, CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE);
        assert_eq!(int.affinity, 1);
    }

    #[test]
    fn assignment_preserves_multiple_bars_and_rejects_unassigned_resources() {
        let base = PciDevice {
            bus: 0,
            dev: 7,
            func: 0,
            vendor: 0x1234,
            device: 0x5678,
            class: 0x020000,
            irq_line: 10,
            irq_pin: 1,
            bars: vec![],
        };
        let memory = Bar {
            index: 0,
            is_io: false,
            is_64bit: false,
            prefetchable: false,
            base: 0x8000_0000,
            size: 0x1000,
            maximum_address: u32::MAX as u64,
        };
        let port = Bar {
            index: 2,
            is_io: true,
            is_64bit: false,
            prefetchable: false,
            base: 0x300,
            size: 0x20,
            maximum_address: u32::MAX as u64,
        };

        let mut unassigned = base.clone();
        unassigned.bars.push(Bar { base: 0, ..memory });
        assert_eq!(
            assign_resources(&unassigned, interrupt(10, false, 1), 0),
            Err(ResourceRequirementsError::UnassignedBar)
        );

        let mut two_memory = base.clone();
        two_memory.bars.push(memory);
        two_memory.bars.push(Bar {
            index: 1,
            base: 0x8001_0000,
            ..memory
        });
        let two_memory = assign_resources(&two_memory, interrupt(10, false, 1), 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            two_memory
                .memory_resources(ResourceView::Translated)
                .map(|memory| memory.start)
                .collect::<Vec<_>>(),
            alloc::vec![0x8000_0000, 0x8001_0000]
        );

        let mut two_ports = base;
        two_ports.bars.push(port);
        two_ports.bars.push(Bar {
            index: 3,
            base: 0x340,
            ..port
        });
        let two_ports = assign_resources(&two_ports, interrupt(10, false, 1), 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            two_ports
                .port_resources(ResourceView::Translated)
                .map(|port| port.start)
                .collect::<Vec<_>>(),
            alloc::vec![0x300, 0x340]
        );
        let mut bytes = [0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
        let written = assignment_to_cm_list(
            &mut bytes,
            INTERFACE_TYPE_PCI_BUS,
            0,
            &two_ports,
            ResourceView::Translated,
        )
        .unwrap();
        assert_eq!(written, 80);
        assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), 3);
        assert_eq!(bytes[20], nt_cm_resources::CM_RESOURCE_TYPE_PORT);
        assert_eq!(bytes[40], nt_cm_resources::CM_RESOURCE_TYPE_PORT);
        assert_eq!(bytes[60], nt_cm_resources::CM_RESOURCE_TYPE_INTERRUPT);
    }

    #[test]
    fn filtered_requirements_remove_unrequested_platform_grants() {
        let device = PciDevice {
            bus: 2,
            dev: 4,
            func: 1,
            vendor: 0x8086,
            device: 0x100e,
            class: 0x020000,
            irq_line: 11,
            irq_pin: 1,
            bars: vec![Bar {
                index: 0,
                is_io: false,
                is_64bit: false,
                prefetchable: false,
                base: 0x8000_0000,
                size: 0x20_000,
                maximum_address: u32::MAX as u64,
            }],
        };
        let available = assign_resources(&device, interrupt(11, false, 1), 0x4000)
            .unwrap()
            .unwrap();
        let filtered = pci_resource_requirements_filtered(&device, false)
            .unwrap()
            .unwrap();
        let selected = select_resource_assignment(
            &available,
            &filtered,
            INTERFACE_TYPE_PCI_BUS,
            device.bus as u32,
            device.slot_number(),
        )
        .unwrap();

        assert_eq!(selected.memory_resources(ResourceView::Raw).count(), 1);
        assert_eq!(selected.interrupt_resource(ResourceView::Raw), None);
        assert_eq!(selected.dma_len, 0x4000);
        assert_eq!(
            select_resource_assignment(
                &available,
                &filtered,
                INTERFACE_TYPE_PCI_BUS,
                device.bus as u32 + 1,
                device.slot_number(),
            ),
            Err(ResourceRequirementsError::InvalidFilteredRequirements(
                nt_cm_resources::IoResourceAssignmentError::InvalidIdentity,
            ))
        );
    }

    #[test]
    fn platform_routes_line_less_display_without_inventing_dispi_resources() {
        let regs = vec![
            ((1, 0, PCI_CFG_VENDOR_DEVICE), 0x1111_1234),
            ((1, 0, PCI_CFG_CLASS_REV), 0x0300_0000),
            ((1, 0, PCI_CFG_BAR0), 0xE000_0000),
            ((1, 0, PCI_CFG_INTERRUPT), 0x0000_01FF),
        ];
        let m = MockConfig {
            regs: RefCell::new(regs),
            bar_masks: vec![((1, 0, PCI_CFG_BAR0), 0xFF00_0000)],
        };
        let dev =
            enumerate_function(0, 1, 0, |o| m.read(1, 0, o), |o, v| m.write(1, 0, o, v)).unwrap();
        let routes = PciIntxRoutingTable::new(0, [Some(16), Some(17), Some(18), Some(19)]);
        let vector = routes.route(&dev).unwrap();
        assert_eq!(vector, 17);
        let assign = assign_resources(&dev, interrupt(vector, false, 1), 0)
            .unwrap()
            .unwrap();
        let memory = assign
            .memory_resources(ResourceView::Translated)
            .next()
            .unwrap();
        assert_eq!(memory.start, 0xE000_0000);
        assert_eq!(memory.length, 0x0100_0000);
        assert_eq!(assign.port_resources(ResourceView::Translated).count(), 0);
        assert_eq!(
            assign
                .interrupt_resource(ResourceView::Translated)
                .unwrap()
                .vector,
            17
        );
        assert_eq!(assign.dma_len, 0);

        let boot = pci_boot_resources(&dev, None).unwrap().unwrap();
        for bytes in [&boot.raw, &boot.translated] {
            assert_eq!(bytes.len(), MEMORY_LIST_SIZE);
            assert_eq!(u32::from_le_bytes(bytes[16..20].try_into().unwrap()), 1);
            assert_eq!(bytes[20], nt_cm_resources::CM_RESOURCE_TYPE_MEMORY);
        }

        let mut buf = [0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
        let n = assignment_to_cm_list(
            &mut buf,
            INTERFACE_TYPE_PCI_BUS,
            0,
            &assign,
            ResourceView::Translated,
        )
        .unwrap();
        assert_eq!(n, MEMORY_INTERRUPT_LIST_SIZE);
        assert_eq!(u32::from_le_bytes(buf[16..20].try_into().unwrap()), 2);
        assert_eq!(buf[20], nt_cm_resources::CM_RESOURCE_TYPE_MEMORY);
        assert_eq!(buf[40], nt_cm_resources::CM_RESOURCE_TYPE_INTERRUPT);
        assert_eq!(u32::from_le_bytes(buf[44..48].try_into().unwrap()), 17);
        let requirements = pci_resource_requirements(&dev).unwrap().unwrap();
        assert_eq!(
            u32::from_le_bytes(requirements[36..40].try_into().unwrap()),
            2
        );
        assert!(!requirements
            .windows(8)
            .any(|window| window == 0x01ceu64.to_le_bytes()));
        let filtered = pci_resource_requirements_filtered(&dev, true)
            .unwrap()
            .unwrap();
        assert_eq!(u32::from_le_bytes(filtered[36..40].try_into().unwrap()), 2);
        assert_eq!(filtered[41], nt_cm_resources::CM_RESOURCE_TYPE_MEMORY);
        assert_eq!(filtered[73], nt_cm_resources::CM_RESOURCE_TYPE_INTERRUPT);
    }

    #[test]
    fn root_bus_dma_profile_matches_registry_ids() {
        let empty: [&str; 0] = [];
        assert!(devnode_matches_root_bus_profile(
            r"ROOT\USERSPACE_NTOS_DMA\0001",
            &empty,
            &empty,
            &ROOT_DMA_TEST_RESOURCE_PROFILE,
        ));
        assert!(devnode_matches_root_bus_profile(
            r"ROOT\OTHER\0001",
            &[r"ROOT\USERSPACE_NTOS_DMA"],
            &empty,
            &ROOT_DMA_TEST_RESOURCE_PROFILE,
        ));
        assert!(devnode_matches_root_bus_profile(
            r"ROOT\OTHER\0001",
            &empty,
            &[r"ROOT\USERSPACE_NTOS_DMA"],
            &ROOT_DMA_TEST_RESOURCE_PROFILE,
        ));
        let assignment = assign_root_bus_resources(
            r"ROOT\USERSPACE_NTOS_DMA\0001",
            &[r"ROOT\USERSPACE_NTOS_DMA"],
            &empty,
            &ROOT_DMA_TEST_RESOURCE_PROFILE,
            5,
            false,
            1,
            0x1000,
        )
        .expect("root-bus DMA resources");
        let memory = assignment
            .memory_resources(ResourceView::Translated)
            .next()
            .unwrap();
        assert_eq!(memory.start, 0x1000_0000);
        assert_eq!(memory.length, 0x1000);
        assert_eq!(memory.flags, CM_RESOURCE_MEMORY_READ_WRITE);
        assert_eq!(
            assignment.port_resources(ResourceView::Translated).count(),
            0
        );
        let interrupt = assignment
            .interrupt_resource(ResourceView::Translated)
            .unwrap();
        assert_eq!(interrupt.vector, 5);
        assert_eq!(interrupt.flags, CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE);
        assert_eq!(interrupt.affinity, 1);
        assert_eq!(interrupt.share, CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE);
        assert_eq!(assignment.dma_len, 0x1000);
    }

    #[test]
    fn root_bus_profile_rejects_unmatched_devnode() {
        let empty: [&str; 0] = [];
        assert!(!devnode_matches_root_bus_profile(
            r"PCI\VEN_8086&DEV_100E\3&11583659&0&18",
            &[r"PCI\VEN_8086&DEV_100E"],
            &empty,
            &ROOT_DMA_TEST_RESOURCE_PROFILE,
        ));
        assert!(assign_root_bus_resources(
            r"PCI\VEN_8086&DEV_100E\3&11583659&0&18",
            &[r"PCI\VEN_8086&DEV_100E"],
            &empty,
            &ROOT_DMA_TEST_RESOURCE_PROFILE,
            5,
            false,
            1,
            0x1000,
        )
        .is_none());
    }

    #[test]
    fn root_bus_catalog_selects_from_multiple_profiles() {
        let empty: [&str; 0] = [];
        let second = RootBusResourceProfile {
            device_id: r"ROOT\USERSPACE_NTOS_SECOND",
            mmio_phys: 0x1001_0000,
            mmio_len: 0x2000,
            interrupt_vector: 7,
            interrupt_latched: false,
        };
        let mut catalog = RootBusResourceCatalog::new();
        catalog.register(ROOT_DMA_TEST_RESOURCE_PROFILE).unwrap();
        catalog.register(second).unwrap();

        assert_eq!(catalog.profiles().len(), 2);
        assert_eq!(
            catalog.find_for_devnode(r"ROOT\USERSPACE_NTOS_SECOND\0001", &empty, &empty),
            Some(second),
        );
        assert_eq!(
            catalog.find_for_devnode(r"ROOT\OTHER\0001", &empty, &[r"ROOT\USERSPACE_NTOS_DMA"],),
            Some(ROOT_DMA_TEST_RESOURCE_PROFILE),
        );
    }

    #[test]
    fn root_bus_catalog_rejects_invalid_or_duplicate_profiles() {
        let mut catalog = RootBusResourceCatalog::new();
        assert_eq!(
            catalog.register(RootBusResourceProfile {
                device_id: "",
                mmio_phys: 0x1000,
                mmio_len: 0x1000,
                interrupt_vector: 5,
                interrupt_latched: false,
            }),
            Err(RootBusResourceCatalogError::EmptyDeviceId),
        );
        assert_eq!(
            catalog.register(RootBusResourceProfile {
                device_id: r"ROOT\ZERO",
                mmio_phys: 0,
                mmio_len: 0x1000,
                interrupt_vector: 5,
                interrupt_latched: false,
            }),
            Err(RootBusResourceCatalogError::EmptyResource),
        );
        catalog.register(ROOT_DMA_TEST_RESOURCE_PROFILE).unwrap();
        assert_eq!(
            catalog.register(RootBusResourceProfile {
                device_id: r"root\userspace_ntos_dma",
                mmio_phys: 0x2000_0000,
                mmio_len: 0x1000,
                interrupt_vector: 9,
                interrupt_latched: true,
            }),
            Err(RootBusResourceCatalogError::DuplicateDeviceId),
        );
    }

    #[test]
    fn assign_none_without_any_bar() {
        // A device with no memory or I/O BAR has no device resource to grant.
        let regs = vec![
            ((5, 0, PCI_CFG_VENDOR_DEVICE), 0xBEEF_1234),
            ((5, 0, PCI_CFG_CLASS_REV), 0x0200_0000),
            ((5, 0, PCI_CFG_INTERRUPT), 0x0000_0105),
        ];
        let m = MockConfig {
            regs: RefCell::new(regs),
            bar_masks: vec![],
        };
        let dev =
            enumerate_function(0, 5, 0, |o| m.read(5, 0, o), |o, v| m.write(5, 0, o, v)).unwrap();
        assert!(dev.first_memory_bar().is_none());
        assert!(dev.first_io_bar().is_none());
        assert!(assign_resources(&dev, interrupt(5, true, 1), 0)
            .unwrap()
            .is_none());
    }
}
