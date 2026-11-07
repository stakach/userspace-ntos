//! Resumable complete FAT directory snapshot over exact caller-supplied sectors.

use alloc::vec::Vec;

use crate::{DirectoryEntry, FatDirectoryDecoder, FatDirectorySlot, FatPathError,
    FatPathGeometry, FatPathRequest, FatPathRequestKind};

const EOC: u32 = 0x0fff_fff8;
const BAD: u32 = 0x0fff_fff7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatDirectoryProgress { Pending, Complete }

pub struct FatDirectoryLookup {
    geometry: FatPathGeometry,
    root_cluster: u32,
    cluster: u32,
    sector_in_cluster: u32,
    file_index: u32,
    decoder: FatDirectoryDecoder,
    entries: Vec<DirectoryEntry>,
    visited: Vec<u32>,
    phase: FatPathRequestKind,
    complete: bool,
}

impl FatDirectoryLookup {
    pub fn new(geometry: FatPathGeometry, cluster: u32) -> Result<Self, FatPathError> {
        let clusters = geometry.total_sectors.checked_sub(geometry.data_start_sector)
            .and_then(|sectors| sectors.checked_div(geometry.sectors_per_cluster))
            .ok_or(FatPathError::Invalid)?;
        let fat_sectors = clusters.checked_add(2).and_then(|count| count.checked_mul(4))
            .map(|bytes| bytes.div_ceil(512)).ok_or(FatPathError::Invalid)?;
        if geometry.fat_start_sector >= geometry.data_start_sector
            || geometry.data_start_sector >= geometry.total_sectors
            || geometry.fat_start_sector.checked_add(fat_sectors)
                .is_none_or(|end| end > geometry.data_start_sector)
            || cluster < 2 || cluster.checked_sub(2).is_none_or(|index| index >= clusters)
        { return Err(FatPathError::Invalid); }
        let mut visited = Vec::new();
        visited.try_reserve(1).map_err(|_| FatPathError::NoCapacity)?;
        visited.push(cluster);
        Ok(Self { geometry, root_cluster: cluster, cluster, sector_in_cluster: 0,
            file_index: 0, decoder: FatDirectoryDecoder::new(), entries: Vec::new(),
            visited, phase: FatPathRequestKind::Directory, complete: false })
    }

    pub fn request(&self) -> Option<FatPathRequest> {
        if self.complete { return None; }
        let sector = match self.phase {
            FatPathRequestKind::Directory => self.geometry.data_start_sector.checked_add(
                self.cluster.checked_sub(2)?.checked_mul(self.geometry.sectors_per_cluster)?
            )?.checked_add(self.sector_in_cluster)?,
            FatPathRequestKind::Fat => self.geometry.fat_start_sector.checked_add(self.cluster.checked_mul(4)? / 512)?,
        };
        let limit = if self.phase == FatPathRequestKind::Fat {
            self.geometry.data_start_sector
        } else { self.geometry.total_sectors };
        (sector < limit).then_some(FatPathRequest { sector, kind: self.phase })
    }

    pub fn feed(&mut self, request: FatPathRequest, bytes: &[u8; 512])
        -> Result<FatDirectoryProgress, FatPathError>
    {
        if self.request() != Some(request) { return Err(FatPathError::WrongRequest); }
        match request.kind {
            FatPathRequestKind::Directory => {
                let cluster_bytes = self.geometry.sectors_per_cluster.checked_mul(512)
                    .ok_or(FatPathError::Corrupt)?;
                for slot in bytes.chunks_exact(32) {
                    let mut raw = [0; 32];
                    raw.copy_from_slice(slot);
                    match self.decoder.consume(&raw, self.file_index, cluster_bytes) {
                        FatDirectorySlot::End => {
                            self.complete = true;
                            return Ok(FatDirectoryProgress::Complete);
                        }
                        FatDirectorySlot::Skipped => {}
                        FatDirectorySlot::Entry(record) => {
                            self.entries.try_reserve(1).map_err(|_| FatPathError::NoCapacity)?;
                            self.entries.push(record.with_parent_cluster(self.root_cluster).entry);
                        }
                    }
                    self.file_index = self.file_index.checked_add(32).ok_or(FatPathError::Corrupt)?;
                }
                self.sector_in_cluster += 1;
                if self.sector_in_cluster == self.geometry.sectors_per_cluster {
                    self.phase = FatPathRequestKind::Fat;
                }
            }
            FatPathRequestKind::Fat => {
                let byte = (self.cluster as usize % 128) * 4;
                let next = u32::from_le_bytes(bytes[byte..byte + 4].try_into().unwrap()) & 0x0fff_ffff;
                if next >= EOC {
                    self.complete = true;
                    return Ok(FatDirectoryProgress::Complete);
                }
                let clusters = (self.geometry.total_sectors - self.geometry.data_start_sector)
                    / self.geometry.sectors_per_cluster;
                if next == BAD || next < 2
                    || next.checked_sub(2).is_none_or(|index| index >= clusters)
                    || self.visited.contains(&next)
                { return Err(FatPathError::Corrupt); }
                self.visited.try_reserve(1).map_err(|_| FatPathError::NoCapacity)?;
                self.visited.push(next);
                self.cluster = next;
                self.sector_in_cluster = 0;
                self.phase = FatPathRequestKind::Directory;
            }
        }
        Ok(FatDirectoryProgress::Pending)
    }

    pub fn take_entries(&mut self) -> Option<Vec<DirectoryEntry>> {
        self.complete.then(|| core::mem::take(&mut self.entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geometry() -> FatPathGeometry {
        FatPathGeometry { fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 1 }
    }

    #[test]
    fn exact_directory_sector_completes_only_on_end_marker() {
        let mut lookup = FatDirectoryLookup::new(geometry(), 2).unwrap();
        let claim = lookup.request().unwrap();
        assert_eq!(claim.sector, 10);
        assert_eq!(lookup.feed(FatPathRequest { sector: 11, ..claim }, &[0; 512]),
            Err(FatPathError::WrongRequest));
        let mut sector = [0xe5; 512];
        sector[32] = 0;
        assert_eq!(lookup.feed(claim, &sector), Ok(FatDirectoryProgress::Complete));
        assert_eq!(lookup.take_entries().unwrap().len(), 0);
        assert!(lookup.request().is_none());
    }

    #[test]
    fn directory_chain_cycle_is_corrupt() {
        let mut lookup = FatDirectoryLookup::new(geometry(), 2).unwrap();
        lookup.feed(lookup.request().unwrap(), &[0xe5; 512]).unwrap();
        let claim = lookup.request().unwrap();
        assert_eq!(claim.kind, FatPathRequestKind::Fat);
        let mut fat = [0; 512];
        fat[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(lookup.feed(claim, &fat), Err(FatPathError::Corrupt));
    }
}
