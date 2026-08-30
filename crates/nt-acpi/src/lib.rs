//! Checked ACPI table and fixed-event policy for the NT executive.
//!
//! Physical mapping, I/O-port capabilities, IRQ objects, and acknowledgement remain executive
//! mechanisms. This crate validates firmware bytes and describes only the exact resources those
//! mechanisms may access.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

mod madt;
mod namespace;
mod pci_routing;

pub use madt::{
    parse_madt_interrupt_topology, resolve_ioapic_gsi, validate_ioapic_route_extents,
    IoApicRouteError, IoApicRouteExtent, MadtError, MadtInterruptTopology, MadtIoApic,
    ResolvedIoApicRoute,
};
pub use namespace::{
    immediate_namespace_children_input, namespace_children_required_len, parse_namespace_children,
    resolve_namespace_reference, AcpiNamespaceChild, AcpiNamespaceChildren, AcpiNamespaceError,
    AcpiNamespacePath, ACPI_ENUM_CHILDREN_INPUT_LEN, IOCTL_ACPI_ENUM_CHILDREN,
};
pub use pci_routing::{
    parse_interrupt_resource_template, parse_pci_routing_table, resolve_pci_routing_table,
    InterruptResource, InterruptSource, LegacyIrqOverride, PciInterruptLink, PciRouteSource,
    PciRoutingEntry, PciRoutingError, PciRoutingTable, ResolvedPciRoute,
};

pub const SDT_HEADER_LEN: usize = 36;
pub const FADT_SIGNATURE: [u8; 4] = *b"FACP";
pub const MADT_SIGNATURE: [u8; 4] = *b"APIC";
pub const DSDT_SIGNATURE: [u8; 4] = *b"DSDT";
pub const FACS_SIGNATURE: [u8; 4] = *b"FACS";
pub const FACS_MIN_LEN: usize = 64;
pub const ACPI_PAGE_SIZE: u64 = 0x1000;

pub const ADDRESS_SPACE_SYSTEM_MEMORY: u8 = 0;
pub const ADDRESS_SPACE_SYSTEM_IO: u8 = 1;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum AcpiError {
    Truncated,
    InvalidLength,
    InvalidChecksum,
    InvalidSignature,
    InvalidRootEntryWidth,
    NullTableAddress,
    DuplicateTableAddress,
    DuplicateFadt,
    DuplicateMadt,
    MissingMadt,
    Allocation,
    PhysicalRead,
    DiscoveryLimit,
    MissingFadt,
    InvalidMadt,
    MissingSciInterrupt,
    InvalidRegisterBlock,
    UnsupportedAddressSpace(u8),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SdtHeader {
    pub signature: [u8; 4],
    pub length: u32,
    pub revision: u8,
}

pub fn validate_sdt(bytes: &[u8]) -> Result<SdtHeader, AcpiError> {
    if bytes.len() < SDT_HEADER_LEN {
        return Err(AcpiError::Truncated);
    }
    let length = read_u32(bytes, 4)? as usize;
    if length < SDT_HEADER_LEN || length > bytes.len() {
        return Err(AcpiError::InvalidLength);
    }
    if bytes[..length].iter().copied().fold(0u8, u8::wrapping_add) != 0 {
        return Err(AcpiError::InvalidChecksum);
    }
    Ok(SdtHeader {
        signature: bytes[0..4].try_into().unwrap(),
        length: length as u32,
        revision: bytes[8],
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiRootTable {
    pub header: SdtHeader,
    pub entries: Vec<u64>,
}

impl AcpiRootTable {
    pub fn parse(bytes: &[u8]) -> Result<Self, AcpiError> {
        Self::parse_with_entry_limit(bytes, usize::MAX)
    }

    pub fn parse_with_entry_limit(bytes: &[u8], max_entries: usize) -> Result<Self, AcpiError> {
        let header = validate_sdt(bytes)?;
        let entry_width = match &header.signature {
            b"RSDT" => 4,
            b"XSDT" => 8,
            _ => return Err(AcpiError::InvalidSignature),
        };
        let payload_len = header.length as usize - SDT_HEADER_LEN;
        if payload_len % entry_width != 0 {
            return Err(AcpiError::InvalidRootEntryWidth);
        }
        let count = payload_len / entry_width;
        if count > max_entries {
            return Err(AcpiError::DiscoveryLimit);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| AcpiError::Allocation)?;
        for index in 0..count {
            let offset = SDT_HEADER_LEN + index * entry_width;
            let address = if entry_width == 4 {
                read_u32(bytes, offset)? as u64
            } else {
                read_u64(bytes, offset)?
            };
            if address == 0 {
                return Err(AcpiError::NullTableAddress);
            }
            if entries.contains(&address) {
                return Err(AcpiError::DuplicateTableAddress);
            }
            entries.push(address);
        }
        Ok(Self { header, entries })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct GenericAddress {
    pub address_space: u8,
    pub bit_width: u8,
    pub bit_offset: u8,
    pub access_size: u8,
    pub address: u64,
}

impl GenericAddress {
    fn parse(bytes: &[u8], offset: usize) -> Result<Self, AcpiError> {
        Ok(Self {
            address_space: read_u8(bytes, offset)?,
            bit_width: read_u8(bytes, offset + 1)?,
            bit_offset: read_u8(bytes, offset + 2)?,
            access_size: read_u8(bytes, offset + 3)?,
            address: read_u64(bytes, offset + 4)?,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct RegisterBlock {
    pub address_space: u8,
    pub address: u64,
    pub length: u8,
}

impl RegisterBlock {
    pub fn split_status_enable(self) -> Result<(Self, Self), AcpiError> {
        if self.length == 0 || self.length & 1 != 0 {
            return Err(AcpiError::InvalidRegisterBlock);
        }
        let half = self.length / 2;
        let enable_address = self
            .address
            .checked_add(half as u64)
            .ok_or(AcpiError::InvalidRegisterBlock)?;
        Ok((
            Self {
                length: half,
                ..self
            },
            Self {
                address: enable_address,
                length: half,
                ..self
            },
        ))
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct EventRegisterPair {
    pub status: RegisterBlock,
    pub enable: RegisterBlock,
    /// First AML GPE number represented by this block.
    pub base_event: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedAcpiDescription {
    pub revision: u8,
    pub sci_interrupt: u16,
    pub facs_address: Option<u64>,
    pub dsdt_address: u64,
    pub pm1a_event: Option<EventRegisterPair>,
    pub pm1b_event: Option<EventRegisterPair>,
    pub gpe0: Option<EventRegisterPair>,
    pub gpe1: Option<EventRegisterPair>,
}

impl FixedAcpiDescription {
    pub fn parse(bytes: &[u8]) -> Result<Self, AcpiError> {
        let header = validate_sdt(bytes)?;
        if header.signature != FADT_SIGNATURE {
            return Err(AcpiError::InvalidSignature);
        }
        let table = &bytes[..header.length as usize];
        let sci_interrupt = read_u16(table, 46)?;
        if sci_interrupt == 0 {
            return Err(AcpiError::MissingSciInterrupt);
        }
        let legacy_facs = read_u32(table, 36)? as u64;
        let extended_facs = read_optional_u64(table, 132).unwrap_or(0);
        let facs_address = match (extended_facs, legacy_facs) {
            (address, _) if address != 0 => Some(address),
            (_, address) if address != 0 => Some(address),
            _ => None,
        };
        let legacy_dsdt = read_u32(table, 40)? as u64;
        let extended_dsdt = read_optional_u64(table, 140).unwrap_or(0);
        let dsdt_address = if extended_dsdt != 0 {
            extended_dsdt
        } else {
            legacy_dsdt
        };
        if dsdt_address == 0 {
            return Err(AcpiError::NullTableAddress);
        }

        let pm1_event_len = read_u8(table, 88)?;
        let gpe0_len = read_u8(table, 92)?;
        let gpe1_len = read_u8(table, 93)?;
        let gpe1_base = read_u8(table, 94)?;
        let pm1a_event = parse_event_pair(table, 56, 148, pm1_event_len, 0)?;
        let pm1b_event = parse_event_pair(table, 60, 160, pm1_event_len, 0)?;
        let gpe0 = parse_event_pair(table, 80, 220, gpe0_len, 0)?;
        let gpe1 = parse_event_pair(table, 84, 232, gpe1_len, gpe1_base)?;

        Ok(Self {
            revision: header.revision,
            sci_interrupt,
            facs_address,
            dsdt_address,
            pm1a_event,
            pm1b_event,
            gpe0,
            gpe1,
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryLimits {
    pub max_tables: usize,
    pub max_table_length: usize,
}

impl Default for DiscoveryLimits {
    fn default() -> Self {
        Self {
            max_tables: 256,
            max_table_length: 16 * 1024 * 1024,
        }
    }
}

/// Read an exact physical range. Implementations own mapping lifetime and must not return bytes
/// from outside the caller's firmware-memory authority.
pub trait PhysicalMemoryReader {
    fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, AcpiError>;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PhysicalTable {
    pub address: u64,
    pub length: u32,
    pub signature: [u8; 4],
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PhysicalRange {
    pub start: u64,
    pub length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcpiPlatformResources {
    pub root: PhysicalTable,
    /// Checksum-validated SDTs referenced by the root, followed by the FADT-selected DSDT.
    pub tables: Vec<PhysicalTable>,
    /// The FACS is not an SDT and therefore has no checksum.
    pub facs: Option<PhysicalRange>,
    pub fixed: FixedAcpiDescription,
    /// IOAPICs in firmware MADT order. Hardware route extents are supplied separately by the
    /// microkernel after it validates each controller's version register.
    pub io_apics: Vec<MadtIoApic>,
    /// MADT ISA-source translations used when an ACPI link reports a legacy IRQ.
    pub interrupt_overrides: Vec<LegacyIrqOverride>,
    /// Page-normalized, sorted, non-overlapping extents containing every discovered table.
    pub firmware_memory: Vec<PhysicalRange>,
    /// Sorted, coalesced SystemMemory/SystemIO blocks needed for fixed ACPI events.
    pub fixed_registers: Vec<RegisterBlock>,
}

pub fn discover_platform_resources<R: PhysicalMemoryReader>(
    reader: &mut R,
    root_address: u64,
    root_length: u32,
    limits: DiscoveryLimits,
) -> Result<AcpiPlatformResources, AcpiError> {
    if root_address == 0
        || root_length as usize > limits.max_table_length
        || (root_length as usize) < SDT_HEADER_LEN
        || limits.max_tables == 0
    {
        return Err(AcpiError::DiscoveryLimit);
    }
    let root_bytes = read_exact(reader, root_address, root_length as usize)?;
    let root = AcpiRootTable::parse_with_entry_limit(&root_bytes, limits.max_tables)?;
    if root.header.length != root_length {
        return Err(AcpiError::InvalidLength);
    }

    let root_table = PhysicalTable {
        address: root_address,
        length: root.header.length,
        signature: root.header.signature,
    };
    let mut tables = Vec::new();
    tables
        .try_reserve_exact(root.entries.len().saturating_add(1))
        .map_err(|_| AcpiError::Allocation)?;
    let mut fadt_bytes = None;
    let mut madt_topology = None;
    for address in root.entries {
        let (table, bytes) = read_sdt(reader, address, limits.max_table_length)?;
        if table.signature == FADT_SIGNATURE {
            if fadt_bytes.is_some() {
                return Err(AcpiError::DuplicateFadt);
            }
            fadt_bytes = Some(bytes);
        } else if table.signature == MADT_SIGNATURE {
            if madt_topology.is_some() {
                return Err(AcpiError::DuplicateMadt);
            }
            madt_topology =
                Some(parse_madt_interrupt_topology(&bytes).map_err(|_| AcpiError::InvalidMadt)?);
        }
        tables.push(table);
    }
    let fixed = FixedAcpiDescription::parse(&fadt_bytes.ok_or(AcpiError::MissingFadt)?)?;
    let madt_topology = madt_topology.ok_or(AcpiError::MissingMadt)?;

    if tables.len() >= limits.max_tables {
        return Err(AcpiError::DiscoveryLimit);
    }
    if tables
        .iter()
        .any(|table| table.address == fixed.dsdt_address)
    {
        return Err(AcpiError::DuplicateTableAddress);
    }
    let (dsdt, _) = read_sdt(reader, fixed.dsdt_address, limits.max_table_length)?;
    if dsdt.signature != DSDT_SIGNATURE {
        return Err(AcpiError::InvalidSignature);
    }
    tables.push(dsdt);

    let facs = fixed
        .facs_address
        .map(|address| read_facs(reader, address, limits.max_table_length))
        .transpose()?;
    let mut firmware_extents = Vec::new();
    firmware_extents
        .try_reserve_exact(tables.len().saturating_add(2))
        .map_err(|_| AcpiError::Allocation)?;
    firmware_extents.push(PhysicalRange {
        start: root_table.address,
        length: root_table.length as u64,
    });
    firmware_extents.extend(tables.iter().map(|table| PhysicalRange {
        start: table.address,
        length: table.length as u64,
    }));
    if let Some(facs) = facs {
        firmware_extents.push(facs);
    }

    Ok(AcpiPlatformResources {
        root: root_table,
        tables,
        facs,
        fixed_registers: normalized_fixed_registers(&fixed)?,
        firmware_memory: normalize_physical_ranges(&firmware_extents)?,
        io_apics: madt_topology.io_apics,
        interrupt_overrides: madt_topology.interrupt_overrides,
        fixed,
    })
}

fn read_exact<R: PhysicalMemoryReader>(
    reader: &mut R,
    address: u64,
    length: usize,
) -> Result<Vec<u8>, AcpiError> {
    let bytes = reader.read(address, length)?;
    if bytes.len() != length {
        return Err(AcpiError::PhysicalRead);
    }
    Ok(bytes)
}

fn read_sdt<R: PhysicalMemoryReader>(
    reader: &mut R,
    address: u64,
    max_table_length: usize,
) -> Result<(PhysicalTable, Vec<u8>), AcpiError> {
    if address == 0 {
        return Err(AcpiError::NullTableAddress);
    }
    let header = read_exact(reader, address, SDT_HEADER_LEN)?;
    let length = read_u32(&header, 4)? as usize;
    if length < SDT_HEADER_LEN || length > max_table_length {
        return Err(AcpiError::DiscoveryLimit);
    }
    let bytes = read_exact(reader, address, length)?;
    let header = validate_sdt(&bytes)?;
    Ok((
        PhysicalTable {
            address,
            length: header.length,
            signature: header.signature,
        },
        bytes,
    ))
}

fn read_facs<R: PhysicalMemoryReader>(
    reader: &mut R,
    address: u64,
    max_table_length: usize,
) -> Result<PhysicalRange, AcpiError> {
    if address == 0 {
        return Err(AcpiError::NullTableAddress);
    }
    let header = read_exact(reader, address, 8)?;
    if header[..4] != FACS_SIGNATURE {
        return Err(AcpiError::InvalidSignature);
    }
    let length = read_u32(&header, 4)? as usize;
    if length < FACS_MIN_LEN || length > max_table_length {
        return Err(AcpiError::DiscoveryLimit);
    }
    let _ = read_exact(reader, address, length)?;
    Ok(PhysicalRange {
        start: address,
        length: length as u64,
    })
}

fn normalized_fixed_registers(
    fixed: &FixedAcpiDescription,
) -> Result<Vec<RegisterBlock>, AcpiError> {
    let mut blocks = Vec::new();
    blocks
        .try_reserve_exact(4)
        .map_err(|_| AcpiError::Allocation)?;
    for pair in [fixed.pm1a_event, fixed.pm1b_event, fixed.gpe0, fixed.gpe1]
        .into_iter()
        .flatten()
    {
        let length = pair
            .status
            .length
            .checked_add(pair.enable.length)
            .ok_or(AcpiError::InvalidRegisterBlock)?;
        if pair.status.address_space != pair.enable.address_space
            || pair.status.address.checked_add(pair.status.length as u64)
                != Some(pair.enable.address)
        {
            return Err(AcpiError::InvalidRegisterBlock);
        }
        blocks.push(RegisterBlock {
            address_space: pair.status.address_space,
            address: pair.status.address,
            length,
        });
    }
    blocks.sort_unstable_by_key(|block| (block.address_space, block.address));
    let mut normalized: Vec<RegisterBlock> = Vec::new();
    normalized
        .try_reserve_exact(blocks.len())
        .map_err(|_| AcpiError::Allocation)?;
    for block in blocks {
        if let Some(previous) = normalized.last_mut() {
            let previous_end = previous
                .address
                .checked_add(previous.length as u64)
                .ok_or(AcpiError::InvalidRegisterBlock)?;
            let block_end = block
                .address
                .checked_add(block.length as u64)
                .ok_or(AcpiError::InvalidRegisterBlock)?;
            if previous.address_space == block.address_space && block.address <= previous_end {
                previous.length = u8::try_from(previous_end.max(block_end) - previous.address)
                    .map_err(|_| AcpiError::InvalidRegisterBlock)?;
                continue;
            }
        }
        normalized.push(block);
    }
    Ok(normalized)
}

/// Normalize physical byte extents into sorted, non-overlapping ACPI-page ranges.
///
/// The executive uses this for additional firmware discovery windows while retaining all
/// capability allocation and mapping policy outside this crate.
pub fn normalize_physical_ranges(
    ranges: &[PhysicalRange],
) -> Result<Vec<PhysicalRange>, AcpiError> {
    let mut pages = Vec::new();
    pages
        .try_reserve_exact(ranges.len())
        .map_err(|_| AcpiError::Allocation)?;
    for range in ranges {
        let end = range
            .start
            .checked_add(range.length)
            .ok_or(AcpiError::InvalidLength)?;
        if range.length == 0 {
            return Err(AcpiError::InvalidLength);
        }
        let start = range.start & !(ACPI_PAGE_SIZE - 1);
        let end = end
            .checked_add(ACPI_PAGE_SIZE - 1)
            .ok_or(AcpiError::InvalidLength)?
            & !(ACPI_PAGE_SIZE - 1);
        pages.push(PhysicalRange {
            start,
            length: end - start,
        });
    }
    pages.sort_unstable_by_key(|range| range.start);
    let mut normalized: Vec<PhysicalRange> = Vec::new();
    normalized
        .try_reserve_exact(pages.len())
        .map_err(|_| AcpiError::Allocation)?;
    for range in pages {
        if let Some(previous) = normalized.last_mut() {
            let previous_end = previous
                .start
                .checked_add(previous.length)
                .ok_or(AcpiError::InvalidLength)?;
            let range_end = range
                .start
                .checked_add(range.length)
                .ok_or(AcpiError::InvalidLength)?;
            if range.start <= previous_end {
                previous.length = previous_end.max(range_end) - previous.start;
                continue;
            }
        }
        normalized.push(range);
    }
    Ok(normalized)
}

/// Remove page-normalized exclusions from physical ranges.
///
/// This is useful when one firmware object within a shared page must be writable: the whole page
/// belongs to the writable grant, while the non-overlapping table pages can remain read-only.
pub fn subtract_physical_ranges(
    ranges: &[PhysicalRange],
    exclusions: &[PhysicalRange],
) -> Result<Vec<PhysicalRange>, AcpiError> {
    let ranges = normalize_physical_ranges(ranges)?;
    let exclusions = normalize_physical_ranges(exclusions)?;
    let mut result = Vec::new();
    for range in ranges {
        let range_end = range
            .start
            .checked_add(range.length)
            .ok_or(AcpiError::InvalidLength)?;
        let mut cursor = range.start;
        for exclusion in &exclusions {
            let exclusion_end = exclusion
                .start
                .checked_add(exclusion.length)
                .ok_or(AcpiError::InvalidLength)?;
            if exclusion_end <= cursor {
                continue;
            }
            if exclusion.start >= range_end {
                break;
            }
            if exclusion.start > cursor {
                result.try_reserve(1).map_err(|_| AcpiError::Allocation)?;
                result.push(PhysicalRange {
                    start: cursor,
                    length: exclusion.start.min(range_end) - cursor,
                });
            }
            cursor = cursor.max(exclusion_end);
            if cursor >= range_end {
                break;
            }
        }
        if cursor < range_end {
            result.try_reserve(1).map_err(|_| AcpiError::Allocation)?;
            result.push(PhysicalRange {
                start: cursor,
                length: range_end - cursor,
            });
        }
    }
    Ok(result)
}

fn parse_event_pair(
    table: &[u8],
    legacy_offset: usize,
    extended_offset: usize,
    length: u8,
    base_event: u8,
) -> Result<Option<EventRegisterPair>, AcpiError> {
    if length == 0 {
        return Ok(None);
    }
    let extended = (extended_offset + 12 <= table.len())
        .then(|| GenericAddress::parse(table, extended_offset))
        .transpose()?;
    let block = if let Some(address) = extended.filter(|address| address.address != 0) {
        if !matches!(
            address.address_space,
            ADDRESS_SPACE_SYSTEM_MEMORY | ADDRESS_SPACE_SYSTEM_IO
        ) {
            return Err(AcpiError::UnsupportedAddressSpace(address.address_space));
        }
        if address.bit_offset != 0 || address.bit_width != 0 && address.bit_width != length * 8 {
            return Err(AcpiError::InvalidRegisterBlock);
        }
        RegisterBlock {
            address_space: address.address_space,
            address: address.address,
            length,
        }
    } else {
        let address = read_u32(table, legacy_offset)? as u64;
        if address == 0 {
            return Ok(None);
        }
        RegisterBlock {
            address_space: ADDRESS_SPACE_SYSTEM_IO,
            address,
            length,
        }
    };
    let (status, enable) = block.split_status_enable()?;
    Ok(Some(EventRegisterPair {
        status,
        enable,
        base_event,
    }))
}

pub fn active_event_bits(status: &[u8], enable: &[u8]) -> Result<Vec<u16>, AcpiError> {
    if status.len() != enable.len() {
        return Err(AcpiError::InvalidRegisterBlock);
    }
    let mut active = Vec::new();
    active
        .try_reserve_exact(status.len().saturating_mul(8))
        .map_err(|_| AcpiError::Allocation)?;
    for (byte_index, (&status, &enable)) in status.iter().zip(enable).enumerate() {
        let mut bits = status & enable;
        while bits != 0 {
            let bit = bits.trailing_zeros() as usize;
            let event = byte_index
                .checked_mul(8)
                .and_then(|base| base.checked_add(bit))
                .and_then(|event| u16::try_from(event).ok())
                .ok_or(AcpiError::InvalidRegisterBlock)?;
            active.push(event);
            bits &= !(1 << bit);
        }
    }
    Ok(active)
}

fn read_u8(bytes: &[u8], offset: usize) -> Result<u8, AcpiError> {
    bytes.get(offset).copied().ok_or(AcpiError::Truncated)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, AcpiError> {
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..offset + 2)
            .ok_or(AcpiError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, AcpiError> {
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..offset + 4)
            .ok_or(AcpiError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, AcpiError> {
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..offset + 8)
            .ok_or(AcpiError::Truncated)?
            .try_into()
            .unwrap(),
    ))
}

fn read_optional_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset + 8)
        .map(|value| u64::from_le_bytes(value.try_into().unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    struct TestPhysicalMemory {
        regions: Vec<(u64, Vec<u8>)>,
        reads: Vec<(u64, usize)>,
    }

    impl TestPhysicalMemory {
        fn new(regions: Vec<(u64, Vec<u8>)>) -> Self {
            Self {
                regions,
                reads: Vec::new(),
            }
        }
    }

    impl PhysicalMemoryReader for TestPhysicalMemory {
        fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, AcpiError> {
            self.reads.push((address, length));
            let end = address
                .checked_add(length as u64)
                .ok_or(AcpiError::PhysicalRead)?;
            let Some((base, bytes)) = self.regions.iter().find(|(base, bytes)| {
                let region_end = base.saturating_add(bytes.len() as u64);
                address >= *base && end <= region_end
            }) else {
                return Err(AcpiError::PhysicalRead);
            };
            let offset = (address - *base) as usize;
            Ok(bytes[offset..offset + length].to_vec())
        }
    }

    fn finish_table(mut table: Vec<u8>, signature: &[u8; 4]) -> Vec<u8> {
        table[0..4].copy_from_slice(signature);
        let length = table.len() as u32;
        table[4..8].copy_from_slice(&length.to_le_bytes());
        table[8] = 6;
        table[9] = 0;
        let sum = table.iter().copied().fold(0u8, u8::wrapping_add);
        table[9] = 0u8.wrapping_sub(sum);
        table
    }

    fn write_u16(table: &mut [u8], offset: usize, value: u16) {
        table[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u32(table: &mut [u8], offset: usize, value: u32) {
        table[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn write_u64(table: &mut [u8], offset: usize, value: u64) {
        table[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn write_gas(table: &mut [u8], offset: usize, space: u8, width: u8, address: u64) {
        table[offset] = space;
        table[offset + 1] = width;
        table[offset + 2] = 0;
        table[offset + 3] = 1;
        write_u64(table, offset + 4, address);
    }

    fn facs(length: usize) -> Vec<u8> {
        let mut table = vec![0; length];
        table[..4].copy_from_slice(b"FACS");
        write_u32(&mut table, 4, length as u32);
        table
    }

    #[test]
    fn xsdt_entries_are_checked_and_preserve_physical_addresses() {
        let mut xsdt = vec![0; SDT_HEADER_LEN + 16];
        write_u64(&mut xsdt, SDT_HEADER_LEN, 0x7ffe_1000);
        write_u64(&mut xsdt, SDT_HEADER_LEN + 8, 0x7ffe_3000);
        let root = AcpiRootTable::parse(&finish_table(xsdt, b"XSDT")).unwrap();
        assert_eq!(root.entries, vec![0x7ffe_1000, 0x7ffe_3000]);
    }

    #[test]
    fn fadt_prefers_extended_blocks_and_splits_status_from_enable() {
        let mut fadt = vec![0; 244];
        write_u16(&mut fadt, 46, 9);
        write_u32(&mut fadt, 40, 0x1234_5000);
        write_u64(&mut fadt, 140, 0x1_2345_6000);
        fadt[88] = 4;
        fadt[92] = 8;
        fadt[93] = 4;
        fadt[94] = 32;
        write_gas(&mut fadt, 148, ADDRESS_SPACE_SYSTEM_IO, 32, 0x600);
        write_gas(&mut fadt, 220, ADDRESS_SPACE_SYSTEM_MEMORY, 64, 0xfed8_0000);
        write_gas(&mut fadt, 232, ADDRESS_SPACE_SYSTEM_IO, 32, 0x620);
        let parsed = FixedAcpiDescription::parse(&finish_table(fadt, b"FACP")).unwrap();
        assert_eq!(parsed.sci_interrupt, 9);
        assert_eq!(parsed.dsdt_address, 0x1_2345_6000);
        assert_eq!(parsed.pm1a_event.unwrap().status.length, 2);
        assert_eq!(parsed.pm1a_event.unwrap().enable.address, 0x602);
        assert_eq!(
            parsed.gpe0.unwrap().status.address_space,
            ADDRESS_SPACE_SYSTEM_MEMORY
        );
        assert_eq!(parsed.gpe0.unwrap().enable.address, 0xfed8_0004);
        assert_eq!(parsed.gpe1.unwrap().base_event, 32);
    }

    #[test]
    fn fadt_uses_legacy_io_blocks_when_extended_addresses_are_absent() {
        let mut fadt = vec![0; 116];
        write_u16(&mut fadt, 46, 9);
        write_u32(&mut fadt, 40, 0x7ffe_4000);
        write_u32(&mut fadt, 56, 0x600);
        write_u32(&mut fadt, 80, 0x620);
        fadt[88] = 4;
        fadt[92] = 8;
        let parsed = FixedAcpiDescription::parse(&finish_table(fadt, b"FACP")).unwrap();
        assert_eq!(parsed.pm1a_event.unwrap().enable.address, 0x602);
        assert_eq!(parsed.gpe0.unwrap().enable.address, 0x624);
        assert!(parsed.gpe1.is_none());
    }

    #[test]
    fn active_event_bits_require_both_status_and_enable() {
        assert_eq!(
            active_event_bits(&[0b1010_0100], &[0b1110_0001]).unwrap(),
            vec![5, 7]
        );
        assert_eq!(
            active_event_bits(&[0], &[0, 0]),
            Err(AcpiError::InvalidRegisterBlock)
        );
    }

    #[test]
    fn writable_firmware_pages_are_removed_from_read_only_extents() {
        let read_only = [PhysicalRange {
            start: 0x1800,
            length: 0x4800,
        }];
        let writable = [PhysicalRange {
            start: 0x2f80,
            length: 64,
        }];
        assert_eq!(
            subtract_physical_ranges(&read_only, &writable).unwrap(),
            vec![
                PhysicalRange {
                    start: 0x1000,
                    length: 0x1000,
                },
                PhysicalRange {
                    start: 0x3000,
                    length: 0x3000,
                },
            ]
        );
    }

    #[test]
    fn checksum_and_register_shapes_fail_closed() {
        let mut bad = finish_table(vec![0; SDT_HEADER_LEN], b"XSDT");
        bad[12] ^= 1;
        assert_eq!(validate_sdt(&bad), Err(AcpiError::InvalidChecksum));

        let block = RegisterBlock {
            address_space: ADDRESS_SPACE_SYSTEM_IO,
            address: 0x600,
            length: 3,
        };
        assert_eq!(
            block.split_status_enable(),
            Err(AcpiError::InvalidRegisterBlock)
        );
    }

    #[test]
    fn platform_discovery_walks_fadt_dsdt_and_facs_into_exact_resources() {
        const ROOT: u64 = 0x7ffe_1000;
        const FADT: u64 = 0x7ffe_2000;
        const SSDT: u64 = 0x7ffe_2800;
        const MADT: u64 = 0x7ffe_2c00;
        const DSDT: u64 = 0x7ffe_3000;
        const FACS: u64 = 0x7ffe_3f80;

        let mut xsdt = vec![0; SDT_HEADER_LEN + 24];
        write_u64(&mut xsdt, SDT_HEADER_LEN, FADT);
        write_u64(&mut xsdt, SDT_HEADER_LEN + 8, SSDT);
        write_u64(&mut xsdt, SDT_HEADER_LEN + 16, MADT);
        let xsdt = finish_table(xsdt, b"XSDT");

        let mut fadt = vec![0; 244];
        write_u32(&mut fadt, 36, FACS as u32);
        write_u32(&mut fadt, 40, DSDT as u32);
        write_u64(&mut fadt, 132, FACS);
        write_u64(&mut fadt, 140, DSDT);
        write_u16(&mut fadt, 46, 9);
        fadt[88] = 4;
        fadt[92] = 8;
        write_gas(&mut fadt, 148, ADDRESS_SPACE_SYSTEM_IO, 32, 0x600);
        write_gas(&mut fadt, 220, ADDRESS_SPACE_SYSTEM_MEMORY, 64, 0xfed8_0000);

        let mut madt = vec![0; SDT_HEADER_LEN + 8];
        write_u32(&mut madt, SDT_HEADER_LEN + 4, 1);
        madt.extend_from_slice(&[1, 12, 0, 0]);
        madt.extend_from_slice(&0xfec0_0000u32.to_le_bytes());
        madt.extend_from_slice(&0u32.to_le_bytes());
        madt.extend_from_slice(&[2, 10, 0, 9]);
        madt.extend_from_slice(&20u32.to_le_bytes());
        madt.extend_from_slice(&0x000fu16.to_le_bytes());

        let regions = vec![
            (ROOT, xsdt.clone()),
            (FADT, finish_table(fadt, b"FACP")),
            (SSDT, finish_table(vec![0; 80], b"SSDT")),
            (MADT, finish_table(madt, b"APIC")),
            (DSDT, finish_table(vec![0; 0x900], b"DSDT")),
            (FACS, facs(FACS_MIN_LEN)),
        ];
        let mut memory = TestPhysicalMemory::new(regions);
        let resources = discover_platform_resources(
            &mut memory,
            ROOT,
            xsdt.len() as u32,
            DiscoveryLimits::default(),
        )
        .unwrap();

        assert_eq!(resources.root.signature, *b"XSDT");
        assert_eq!(resources.fixed.sci_interrupt, 9);
        assert_eq!(resources.fixed.facs_address, Some(FACS));
        assert_eq!(resources.tables.len(), 4);
        assert_eq!(resources.tables.last().unwrap().signature, *b"DSDT");
        assert_eq!(
            resources.io_apics,
            vec![MadtIoApic {
                id: 0,
                address: 0xfec0_0000,
                gsi_base: 0,
            }]
        );
        assert_eq!(
            resources.interrupt_overrides,
            vec![LegacyIrqOverride {
                irq: 9,
                gsi: 20,
                level_sensitive: Some(true),
                active_low: Some(true),
            }]
        );
        assert_eq!(
            resources.firmware_memory,
            vec![PhysicalRange {
                start: ROOT,
                length: 0x3000,
            }]
        );
        assert_eq!(
            resources.fixed_registers,
            vec![
                RegisterBlock {
                    address_space: ADDRESS_SPACE_SYSTEM_MEMORY,
                    address: 0xfed8_0000,
                    length: 8,
                },
                RegisterBlock {
                    address_space: ADDRESS_SPACE_SYSTEM_IO,
                    address: 0x600,
                    length: 4,
                },
            ]
        );
        assert!(memory.reads.contains(&(FACS, FACS_MIN_LEN)));
    }

    #[test]
    fn platform_discovery_rejects_duplicate_fadt_and_table_limits_before_body_read() {
        const ROOT: u64 = 0x1000;
        const FADT_A: u64 = 0x2000;
        const FADT_B: u64 = 0x3000;
        let mut xsdt = vec![0; SDT_HEADER_LEN + 16];
        write_u64(&mut xsdt, SDT_HEADER_LEN, FADT_A);
        write_u64(&mut xsdt, SDT_HEADER_LEN + 8, FADT_B);
        let xsdt = finish_table(xsdt, b"XSDT");
        let mut fadt = vec![0; 116];
        write_u16(&mut fadt, 46, 9);
        write_u32(&mut fadt, 40, 0x4000);
        let fadt = finish_table(fadt, b"FACP");
        let mut memory = TestPhysicalMemory::new(vec![
            (ROOT, xsdt.clone()),
            (FADT_A, fadt.clone()),
            (FADT_B, fadt),
        ]);
        assert_eq!(
            discover_platform_resources(
                &mut memory,
                ROOT,
                xsdt.len() as u32,
                DiscoveryLimits::default(),
            ),
            Err(AcpiError::DuplicateFadt)
        );

        let mut limited = TestPhysicalMemory::new(vec![(ROOT, xsdt.clone())]);
        assert_eq!(
            discover_platform_resources(
                &mut limited,
                ROOT,
                xsdt.len() as u32,
                DiscoveryLimits {
                    max_tables: 1,
                    ..DiscoveryLimits::default()
                },
            ),
            Err(AcpiError::DiscoveryLimit)
        );
        assert_eq!(limited.reads, vec![(ROOT, xsdt.len())]);
    }
}
