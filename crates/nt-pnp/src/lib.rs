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

use alloc::vec::Vec;

pub use nt_cm_resources::{
    InterruptDescriptor, MemoryDescriptor, PortDescriptor, CM_RESOURCE_INTERRUPT_LATCHED,
    CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE, CM_RESOURCE_MEMORY_READ_WRITE, CM_RESOURCE_PORT_BAR,
    CM_RESOURCE_PORT_IO, CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE, MEMORY_INTERRUPT_LIST_SIZE,
    MEMORY_LIST_SIZE, MEMORY_PORT_INTERRUPT_LIST_SIZE, MEMORY_PORT_LIST_SIZE,
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

    /// The first *present I/O-space* BAR.
    pub fn first_io_bar(&self) -> Option<&Bar> {
        self.bars.iter().find(|b| b.is_io && b.is_present())
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
    let addr_mask = if is_io {
        BAR_IO_ADDR_MASK
    } else {
        BAR_MEM_ADDR_MASK
    };
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
    Bar {
        index,
        is_io,
        is_64bit,
        base,
        size,
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

/// Resolve a registry-imported PCI devnode to the enumerated PCI function it represents.
///
/// Match order mirrors NT's ID ranking for this boundary: hardware IDs first, then the `Enum\PCI`
/// instance path as a specific fallback, then compatible IDs from most to least specific.
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

/// The resource assignment PnP produces for a device: which MMIO window + interrupt (+ optional
/// DMA common-buffer) the driver is granted. This is the abstract grant the executive turns into
/// minted caps; [`assignment_to_cm_list`] encodes it as the `CM_RESOURCE_LIST` the driver reads.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResourceAssignment {
    /// The device MMIO physical base (the BAR base).
    pub mmio_phys: u64,
    /// The MMIO window length (rounded up to whole pages by the broker when minting frame caps).
    pub mmio_len: u64,
    /// The device I/O port base, if the PCI function exposes a port BAR.
    pub io_port_base: u64,
    /// The device I/O port range length. `0` means no port resource is granted.
    pub io_port_len: u32,
    /// Flags for the port resource descriptor. `0` when no port resource is granted.
    pub io_port_flags: u16,
    /// The interrupt vector/level assigned to the device (translated form).
    pub int_vector: u32,
    /// True = latched (edge/MSI), false = level-sensitive.
    pub int_latched: bool,
    /// The interrupt affinity mask (CPU set).
    pub int_affinity: u64,
    /// The DMA common-buffer length in bytes (`0` = no DMA resource).
    pub dma_len: u64,
}

/// A root-bus resource profile describes synthetic hardware enumerated by the native root bus.
/// The registry devnode still selects the service; this profile only describes the resource shape
/// the broker can mint for a root-enumerated device ID.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RootBusResourceProfile {
    pub device_id: &'static str,
    pub mmio_phys: u64,
    pub mmio_len: u64,
}

/// The DMA PnP proof device's root-bus register bank. The test driver reads a 4 KiB MMIO range
/// starting at this translated physical address and then acquires interrupt + common-buffer DMA
/// resources through the normal WDM calls.
pub const ROOT_DMA_TEST_RESOURCE_PROFILE: RootBusResourceProfile = RootBusResourceProfile {
    device_id: r"ROOT\USERSPACE_NTOS_DMA",
    mmio_phys: 0x1000_0000,
    mmio_len: 0x1000,
};

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
        if profile.mmio_phys == 0 || profile.mmio_len == 0 {
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
        || int_vector == 0
    {
        return None;
    }
    Some(ResourceAssignment {
        mmio_phys: profile.mmio_phys,
        mmio_len: profile.mmio_len,
        io_port_base: 0,
        io_port_len: 0,
        io_port_flags: 0,
        int_vector,
        int_latched,
        int_affinity,
        dma_len,
    })
}

fn legacy_pci_io_port_range(device: &PciDevice) -> Option<(u64, u32, u16)> {
    // QEMU's std VGA/Bochs display adapter exposes the framebuffer as a PCI memory BAR but its
    // Bochs DISPI control registers are the legacy 0x1CE/0x1CF I/O ports, not a PCI BAR.
    if device.vendor == 0x1234
        && device.device == 0x1111
        && device.base_class() == PCI_CLASS_DISPLAY
    {
        Some((0x01CE, 2, CM_RESOURCE_PORT_IO))
    } else {
        None
    }
}

/// Assign resources to a device bound to `class`, from its enumerated BARs, optional legacy port
/// resources, and optional IRQ. `int_vector` is the translated interrupt vector the executive has
/// arranged for this device; `0` means the bus assigned no interrupt. `dma_len` is the common-buffer
/// size the driver needs (`0` for none). Returns `None` if the device exposes no memory BAR.
pub fn assign_resources(
    device: &PciDevice,
    int_vector: u32,
    int_latched: bool,
    int_affinity: u64,
    dma_len: u64,
) -> Option<ResourceAssignment> {
    let mem_bar = device.first_memory_bar()?;
    let (io_port_base, io_port_len, io_port_flags) = match device.first_io_bar() {
        Some(port_bar) => {
            if port_bar.size > u32::MAX as u64 {
                return None;
            }
            (
                port_bar.base,
                port_bar.size as u32,
                CM_RESOURCE_PORT_IO | CM_RESOURCE_PORT_BAR,
            )
        }
        None => legacy_pci_io_port_range(device).unwrap_or((0, 0, 0)),
    };
    Some(ResourceAssignment {
        mmio_phys: mem_bar.base,
        mmio_len: mem_bar.size,
        io_port_base,
        io_port_len,
        io_port_flags,
        int_vector,
        int_latched,
        int_affinity,
        dma_len,
    })
}

/// The largest `CM_RESOURCE_LIST` this crate currently emits for one device.
pub const ASSIGNMENT_CM_LIST_MAX_SIZE: usize = MEMORY_PORT_INTERRUPT_LIST_SIZE;

/// Encode a [`ResourceAssignment`] as the `CM_RESOURCE_LIST` a WDK driver reads at
/// `IRP_MN_START_DEVICE`. `memory_start` is written into `u.Memory.Start`; callers should pass the
/// translated physical address for real WDM drivers that call `MmMapIoSpace`. The list contains
/// exactly the assigned memory, optional port, and optional interrupt descriptors. Returns the byte
/// length written.
pub fn assignment_to_cm_list(
    buf: &mut [u8],
    bus_number: u32,
    assign: &ResourceAssignment,
    memory_start: u64,
    mmio_len: u32,
) -> Option<usize> {
    let mem = MemoryDescriptor {
        start: memory_start,
        length: mmio_len,
        flags: CM_RESOURCE_MEMORY_READ_WRITE,
        share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
    };
    let port = (assign.io_port_len != 0).then_some(PortDescriptor {
        start: assign.io_port_base,
        length: assign.io_port_len,
        flags: assign.io_port_flags,
        share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
    });
    let int = (assign.int_vector != 0).then_some(InterruptDescriptor {
        level: assign.int_vector,
        vector: assign.int_vector,
        affinity: assign.int_affinity,
        flags: if assign.int_latched {
            CM_RESOURCE_INTERRUPT_LATCHED
        } else {
            CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE
        },
        share: CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE,
    });
    match (port, int) {
        (Some(port), Some(int)) => {
            nt_cm_resources::build_memory_port_interrupt_list(buf, bus_number, mem, port, int)
        }
        (Some(port), None) => nt_cm_resources::build_memory_port_list(buf, bus_number, mem, port),
        (None, Some(int)) => {
            nt_cm_resources::build_memory_interrupt_list(buf, bus_number, mem, int)
        }
        (None, None) => nt_cm_resources::build_memory_list(buf, bus_number, mem),
    }
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
    fn probe_restores_the_bar_after_sizing() {
        let m = nic_mock();
        let _ = enumerate_function(0, 3, 0, |o| m.read(3, 0, o), |o, v| m.write(3, 0, o, v));
        // The BAR must be restored to its original value after the size probe.
        assert_eq!(m.get(3, 0, PCI_CFG_BAR0), 0xFEBC_0000);
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
                    base: 0xFEBC_0000,
                    size: 0x2_0000,
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
        let assign = assign_resources(nic, 5, true, 1, 0x1000).unwrap();
        assert_eq!(assign.mmio_phys, 0xFEBC_0000);
        assert_eq!(assign.mmio_len, 0x2_0000);
        assert_eq!(assign.io_port_base, 0xC000);
        assert_eq!(assign.io_port_len, 0x40);
        assert_eq!(
            assign.io_port_flags,
            CM_RESOURCE_PORT_IO | CM_RESOURCE_PORT_BAR
        );
        assert_eq!(assign.int_vector, 5);
        assert!(assign.int_latched);
        assert_eq!(assign.dma_len, 0x1000);

        // The resource list names the caller-supplied translated memory address, the port BAR, and
        // the translated vector.
        let mut buf = [0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
        let memory_start = 0xFEBC_0000u64;
        let n = assignment_to_cm_list(&mut buf, 0, &assign, memory_start, 0x2_0000).unwrap();
        assert_eq!(n, MEMORY_PORT_INTERRUPT_LIST_SIZE);
        let (mem, port, int) = nt_cm_resources::decode_memory_port_interrupt_list(&buf).unwrap();
        assert_eq!(mem.start, memory_start);
        assert_eq!(mem.length, 0x2_0000);
        assert_eq!(port.start, 0xC000);
        assert_eq!(port.length, 0x40);
        assert_eq!(port.flags, CM_RESOURCE_PORT_IO | CM_RESOURCE_PORT_BAR);
        assert_eq!(int.vector, 5);
        assert_eq!(int.flags, CM_RESOURCE_INTERRUPT_LATCHED);
        assert_eq!(int.affinity, 1);
    }

    #[test]
    fn bochs_display_gets_legacy_dispi_ports_without_interrupt() {
        let regs = vec![
            ((1, 0, PCI_CFG_VENDOR_DEVICE), 0x1111_1234),
            ((1, 0, PCI_CFG_CLASS_REV), 0x0300_0000),
            ((1, 0, PCI_CFG_BAR0), 0xE000_0000),
            ((1, 0, PCI_CFG_INTERRUPT), 0x0000_00FF),
        ];
        let m = MockConfig {
            regs: RefCell::new(regs),
            bar_masks: vec![((1, 0, PCI_CFG_BAR0), 0xFF00_0000)],
        };
        let dev =
            enumerate_function(0, 1, 0, |o| m.read(1, 0, o), |o, v| m.write(1, 0, o, v)).unwrap();
        let assign = assign_resources(&dev, 0, false, 1, 0).unwrap();
        assert_eq!(assign.mmio_phys, 0xE000_0000);
        assert_eq!(assign.mmio_len, 0x0100_0000);
        assert_eq!(assign.io_port_base, 0x01CE);
        assert_eq!(assign.io_port_len, 2);
        assert_eq!(assign.io_port_flags, CM_RESOURCE_PORT_IO);
        assert_eq!(assign.int_vector, 0);
        assert_eq!(assign.dma_len, 0);

        let mut buf = [0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
        let n = assignment_to_cm_list(&mut buf, 0, &assign, assign.mmio_phys, 0x1000).unwrap();
        assert_eq!(n, MEMORY_PORT_LIST_SIZE);
        assert_eq!(u32::from_le_bytes(buf[16..20].try_into().unwrap()), 2);
        assert_eq!(buf[20], nt_cm_resources::CM_RESOURCE_TYPE_MEMORY);
        assert_eq!(buf[40], nt_cm_resources::CM_RESOURCE_TYPE_PORT);
        assert_eq!(u64::from_le_bytes(buf[44..52].try_into().unwrap()), 0x01CE);
        assert_eq!(u32::from_le_bytes(buf[52..56].try_into().unwrap()), 2);
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
        assert_eq!(assignment.mmio_phys, 0x1000_0000);
        assert_eq!(assignment.mmio_len, 0x1000);
        assert_eq!(assignment.io_port_base, 0);
        assert_eq!(assignment.io_port_len, 0);
        assert_eq!(assignment.io_port_flags, 0);
        assert_eq!(assignment.int_vector, 5);
        assert!(!assignment.int_latched);
        assert_eq!(assignment.int_affinity, 1);
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
            }),
            Err(RootBusResourceCatalogError::EmptyDeviceId),
        );
        assert_eq!(
            catalog.register(RootBusResourceProfile {
                device_id: r"ROOT\ZERO",
                mmio_phys: 0,
                mmio_len: 0x1000,
            }),
            Err(RootBusResourceCatalogError::EmptyResource),
        );
        catalog.register(ROOT_DMA_TEST_RESOURCE_PROFILE).unwrap();
        assert_eq!(
            catalog.register(RootBusResourceProfile {
                device_id: r"root\userspace_ntos_dma",
                mmio_phys: 0x2000_0000,
                mmio_len: 0x1000,
            }),
            Err(RootBusResourceCatalogError::DuplicateDeviceId),
        );
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
        let dev =
            enumerate_function(0, 5, 0, |o| m.read(5, 0, o), |o, v| m.write(5, 0, o, v)).unwrap();
        assert!(dev.first_memory_bar().is_none());
        assert!(assign_resources(&dev, 5, true, 1, 0).is_none());
    }
}
