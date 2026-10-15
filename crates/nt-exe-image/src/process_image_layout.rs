//! Actual process placement, independent of immutable executable Section metadata.
use crate::ImageError;

/// Arithmetic bounds only. Native placement separately validates VAD policy and paging ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessImageLayout {
    base: u64,
    size: u64,
    entry_rva: u32,
}

impl ProcessImageLayout {
    pub fn checked(base: u64, size: u64, entry_rva: u32) -> Result<Self, ImageError> {
        if base == 0
            || size == 0
            || base.checked_add(size).is_none()
            || u64::from(entry_rva) >= size
        {
            return Err(ImageError::InvalidMetadata);
        }
        Ok(Self {
            base,
            size,
            entry_rva,
        })
    }
    pub fn base(self) -> u64 {
        self.base
    }
    pub fn size(self) -> u64 {
        self.size
    }
    pub fn entry_rva(self) -> u32 {
        self.entry_rva
    }
    pub fn entry(self) -> u64 {
        self.base + u64::from(self.entry_rva)
    }
    pub fn end(self) -> u64 {
        self.base + self.size
    }
    pub fn rva(self, address: u64) -> Option<u64> {
        address
            .checked_sub(self.base)
            .filter(|rva| *rva < self.size)
    }
    pub fn address_for_rva(self, rva: u64) -> Option<u64> {
        (rva < self.size).then(|| self.base + rva)
    }
}
