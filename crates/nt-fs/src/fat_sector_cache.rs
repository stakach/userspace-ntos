//! One mounted FAT sector kept outside any device DMA buffer.

use crate::STATUS_DATA_ERROR;

/// A sector fetched under an exact mount generation. A failed fetch never publishes partial data.
pub struct FatSectorCache {
    mount_generation: u64,
    sector: u32,
    valid: bool,
    data: [u8; 512],
}

impl FatSectorCache {
    pub const fn new() -> Self {
        Self {
            mount_generation: 0,
            sector: 0,
            valid: false,
            data: [0; 512],
        }
    }

    pub fn invalidate(&mut self) {
        self.valid = false;
    }

    /// Read a little-endian FAT entry, fetching its containing sector only on a cache miss.
    pub fn read_entry(
        &mut self,
        mount_generation: u64,
        sector: u32,
        byte_offset: u32,
        mut fetch: impl FnMut(u32, &mut [u8; 512]) -> Result<(), u32>,
    ) -> Result<u32, u32> {
        let offset = byte_offset as usize;
        if offset > self.data.len() - 4 {
            return Err(STATUS_DATA_ERROR);
        }
        if !self.valid || self.mount_generation != mount_generation || self.sector != sector {
            self.valid = false;
            fetch(sector, &mut self.data)?;
            self.mount_generation = mount_generation;
            self.sector = sector;
            self.valid = true;
        }
        let mut entry = [0; 4];
        entry.copy_from_slice(&self.data[offset..offset + 4]);
        Ok(u32::from_le_bytes(entry))
    }
}

impl Default for FatSectorCache {
    fn default() -> Self {
        Self::new()
    }
}
