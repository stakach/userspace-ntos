//! HAL's validated ACPI PCI root bridge description and exact domain ownership.

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciRootOwner {
    pub domain_id: u64,
    pub domain_cookie: u64,
    pub vspace: u64,
}

pub const HAL_ACPI_PCI_ROOT_INFO_BYTES: usize = 152;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciWindow {
    pub base: u64,
    pub limit: u64,
    pub translation: u64,
    pub translated: bool,
    pub translation_type: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PciRootDescriptor {
    pub segment: u16,
    pub bus: u8,
    pub bus_range: Option<(u8, u8)>,
    pub config_space_base: Option<u64>,
    pub io_window: Option<PciWindow>,
    pub memory_window: Option<PciWindow>,
    pub prefetch_window: Option<PciWindow>,
    pub max_gsi: u32,
    pub osc: [u8; 20],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PciRootError { Malformed, InvalidOwner, Conflict, NoMemory }

fn u32_at(raw: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(raw[offset..offset + 4].try_into().unwrap())
}

fn u64_at(raw: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(raw[offset..offset + 8].try_into().unwrap())
}

fn window(raw: &[u8], offset: usize) -> Result<Option<PciWindow>, PciRootError> {
    let present = raw[offset];
    let translated = raw[offset + 1];
    if present > 1 || translated > 1 || raw[offset + 3] != 0 {
        return Err(PciRootError::Malformed);
    }
    if present == 0 {
        if raw[offset + 1..offset + 32].iter().any(|&byte| byte != 0) {
            return Err(PciRootError::Malformed);
        }
        return Ok(None);
    }
    let base = u64_at(raw, offset + 8);
    let limit = u64_at(raw, offset + 16);
    let translation = u64_at(raw, offset + 24);
    if base > limit || (translated == 1 && limit.checked_add(translation).is_none()) {
        return Err(PciRootError::Malformed);
    }
    Ok(Some(PciWindow { base, limit, translation,
        translated: translated == 1, translation_type: raw[offset + 2] }))
}

impl PciRootDescriptor {
    /// Decodes the pinned x64 `HAL_ACPI_PCI_ROOT_INFO` layout without retaining a pointer.
    pub fn decode(raw: &[u8]) -> Result<Self, PciRootError> {
        if raw.len() != HAL_ACPI_PCI_ROOT_INFO_BYTES { return Err(PciRootError::Malformed); }
        let segment = u16::try_from(u32_at(raw, 0)).map_err(|_| PciRootError::Malformed)?;
        let bus = u8::try_from(u32_at(raw, 4)).map_err(|_| PciRootError::Malformed)?;
        if raw[8] > 1 || raw[9..12].iter().any(|&b| b != 0)
            || raw[20] > 1 || raw[21..24].iter().any(|&b| b != 0)
        { return Err(PciRootError::Malformed); }
        let start = u8::try_from(u32_at(raw, 12)).map_err(|_| PciRootError::Malformed)?;
        let end = u8::try_from(u32_at(raw, 16)).map_err(|_| PciRootError::Malformed)?;
        let bus_range = if raw[8] == 1 {
            if start > bus || bus > end { return Err(PciRootError::Malformed); }
            Some((start, end))
        } else {
            if start != 0 || end != 0 { return Err(PciRootError::Malformed); }
            None
        };
        let config_base = u64_at(raw, 24);
        if raw[20] == 0 && config_base != 0 { return Err(PciRootError::Malformed); }
        let mut osc = [0u8; 20];
        osc.copy_from_slice(&raw[132..152]);
        Ok(Self { segment, bus, bus_range,
            config_space_base: (raw[20] == 1).then_some(config_base),
            io_window: window(raw, 32)?, memory_window: window(raw, 64)?,
            prefetch_window: window(raw, 96)?, max_gsi: u32_at(raw, 128), osc })
    }
}

#[derive(Default)]
pub struct PciRootLedger { entries: Vec<(PciRootOwner, PciRootDescriptor)> }

impl PciRootLedger {
    pub fn new() -> Self { Self::default() }
    /// Identical publication is idempotent; a changed descriptor needs exact retirement.
    pub fn publish(&mut self, owner: PciRootOwner, root: PciRootDescriptor) -> Result<(), PciRootError> {
        if owner.domain_id == 0 || owner.domain_cookie == 0 || owner.vspace == 0 {
            return Err(PciRootError::InvalidOwner);
        }
        if let Some((_, existing)) = self.entries.iter().find(|(entry_owner, entry)|
            *entry_owner == owner && entry.segment == root.segment && entry.bus == root.bus)
        { return if *existing == root { Ok(()) } else { Err(PciRootError::Conflict) }; }
        self.entries.try_reserve(1).map_err(|_| PciRootError::NoMemory)?;
        self.entries.push((owner, root));
        Ok(())
    }
    pub fn lookup(&self, owner: PciRootOwner, segment: u16, bus: u8) -> Option<&PciRootDescriptor> {
        self.entries.iter().find(|(entry_owner, root)|
            *entry_owner == owner && root.segment == segment && root.bus == bus)
            .map(|(_, root)| root)
    }
    pub fn retire(&mut self, owner: PciRootOwner) -> Vec<PciRootDescriptor> {
        let mut removed = Vec::new();
        let mut index = 0;
        while index < self.entries.len() {
            if self.entries[index].0 == owner { removed.push(self.entries.swap_remove(index).1); }
            else { index += 1; }
        }
        removed
    }
}
