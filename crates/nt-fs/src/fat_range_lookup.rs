//! Resumable FAT file-range reads over exact caller-supplied sectors.

use alloc::vec::Vec;

use crate::{FatPathError, FatPathGeometry};

const EOC: u32 = 0x0fff_fff8;
const BAD: u32 = 0x0fff_fff7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatRangeRequestKind { Data, Fat }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FatRangeRequest { pub sector: u32, pub kind: FatRangeRequestKind }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatRangeProgress { Pending, Complete }

pub struct FatRangeLookup {
    geometry: FatPathGeometry,
    cluster: u32,
    cluster_index: u32,
    target_cluster: u32,
    target_sector: u32,
    sector_in_cluster: u32,
    first_skip: usize,
    remaining: usize,
    written: usize,
    visited: Vec<u32>,
    phase: FatRangeRequestKind,
    complete: bool,
}

impl FatRangeLookup {
    pub fn new(geometry: FatPathGeometry, first_cluster: u32, offset: u32, length: usize)
        -> Result<Self, FatPathError>
    {
        let cluster_bytes = geometry.sectors_per_cluster.checked_mul(512)
            .filter(|bytes| *bytes != 0).ok_or(FatPathError::Invalid)?;
        let clusters = geometry.total_sectors.checked_sub(geometry.data_start_sector)
            .map(|sectors| sectors / geometry.sectors_per_cluster)
            .ok_or(FatPathError::Invalid)?;
        let fat_sectors = clusters.checked_add(2).and_then(|count| count.checked_mul(4))
            .map(|bytes| bytes.div_ceil(512)).ok_or(FatPathError::Invalid)?;
        if length == 0 || geometry.fat_start_sector >= geometry.data_start_sector
            || geometry.data_start_sector >= geometry.total_sectors
            || geometry.fat_start_sector.checked_add(fat_sectors)
                .is_none_or(|end| end > geometry.data_start_sector)
            || first_cluster < 2 || first_cluster.checked_sub(2).is_none_or(|index| index >= clusters)
        { return Err(FatPathError::Invalid); }
        let target_cluster = offset / cluster_bytes;
        if target_cluster >= clusters { return Err(FatPathError::Invalid); }
        let within = offset % cluster_bytes;
        let mut visited = Vec::new();
        visited.try_reserve(1).map_err(|_| FatPathError::NoCapacity)?;
        visited.push(first_cluster);
        Ok(Self {
            geometry, cluster: first_cluster, cluster_index: 0, target_cluster,
            target_sector: within / 512,
            sector_in_cluster: if target_cluster == 0 { within / 512 } else { 0 },
            first_skip: (within % 512) as usize, remaining: length, written: 0,
            visited, phase: if target_cluster == 0 { FatRangeRequestKind::Data } else { FatRangeRequestKind::Fat },
            complete: false,
        })
    }

    pub fn request(&self) -> Option<FatRangeRequest> {
        if self.complete { return None; }
        let sector = match self.phase {
            FatRangeRequestKind::Data => self.geometry.data_start_sector.checked_add(
                self.cluster.checked_sub(2)?.checked_mul(self.geometry.sectors_per_cluster)?
            )?.checked_add(self.sector_in_cluster)?,
            FatRangeRequestKind::Fat => self.geometry.fat_start_sector.checked_add(self.cluster.checked_mul(4)? / 512)?,
        };
        let limit = if self.phase == FatRangeRequestKind::Fat {
            self.geometry.data_start_sector
        } else { self.geometry.total_sectors };
        (sector < limit).then_some(FatRangeRequest { sector, kind: self.phase })
    }

    /// Number of file-data sectors that may be read together without crossing a FAT-chain
    /// boundary. The caller must still retain the exact first request until completion.
    pub fn contiguous_data_sectors(&self, max: u32) -> Option<u32> {
        if max == 0 || self.phase != FatRangeRequestKind::Data || self.request().is_none() {
            return None;
        }
        let skip = if self.written == 0 { self.first_skip } else { 0 };
        // Split before adding: `remaining + skip` can overflow usize for a large request.
        let needed = self.remaining / 512 + (self.remaining % 512 + skip).div_ceil(512);
        let within_cluster = self.geometry.sectors_per_cluster.checked_sub(self.sector_in_cluster)?;
        Some(max.min(within_cluster).min(u32::try_from(needed).unwrap_or(u32::MAX)))
            .filter(|count| *count != 0)
    }

    /// Feed an exact contiguous data read. Validate the whole transfer before changing the
    /// cursor or caller-owned output, so a malformed completion cannot publish a prefix.
    pub fn feed_contiguous_data(&mut self, request: FatRangeRequest, bytes: &[u8],
        output: &mut [u8]) -> Result<FatRangeProgress, FatPathError>
    {
        let count = u32::try_from(bytes.len() / 512).map_err(|_| FatPathError::WrongRequest)?;
        if bytes.is_empty() || bytes.len() % 512 != 0
            || request.kind != FatRangeRequestKind::Data
            || self.request() != Some(request)
            || self.contiguous_data_sectors(count) != Some(count)
            || output.len() < self.written + self.remaining
        { return Err(FatPathError::WrongRequest); }
        let mut progress = FatRangeProgress::Pending;
        for (index, sector) in bytes.chunks_exact(512).enumerate() {
            let expected = request.sector.checked_add(index as u32)
                .map(|sector| FatRangeRequest { sector, kind: FatRangeRequestKind::Data })
                .ok_or(FatPathError::WrongRequest)?;
            progress = self.feed(expected, sector.try_into().unwrap(), output)?;
        }
        Ok(progress)
    }

    pub fn feed(&mut self, request: FatRangeRequest, bytes: &[u8; 512], output: &mut [u8])
        -> Result<FatRangeProgress, FatPathError>
    {
        if self.request() != Some(request) || output.len() < self.written + self.remaining {
            return Err(FatPathError::WrongRequest);
        }
        match request.kind {
            FatRangeRequestKind::Data => {
                let start = if self.written == 0 { self.first_skip } else { 0 };
                let amount = self.remaining.min(512 - start);
                output[self.written..self.written + amount].copy_from_slice(&bytes[start..start + amount]);
                self.written += amount;
                self.remaining -= amount;
                if self.remaining == 0 {
                    self.complete = true;
                    return Ok(FatRangeProgress::Complete);
                }
                self.sector_in_cluster += 1;
                if self.sector_in_cluster == self.geometry.sectors_per_cluster {
                    self.phase = FatRangeRequestKind::Fat;
                }
            }
            FatRangeRequestKind::Fat => {
                let byte = (self.cluster as usize % 128) * 4;
                let next = u32::from_le_bytes(bytes[byte..byte + 4].try_into().unwrap()) & 0x0fff_ffff;
                let clusters = (self.geometry.total_sectors - self.geometry.data_start_sector)
                    / self.geometry.sectors_per_cluster;
                if next >= EOC || next == BAD || next < 2
                    || next.checked_sub(2).is_none_or(|index| index >= clusters)
                    || self.visited.contains(&next)
                { return Err(FatPathError::Corrupt); }
                self.visited.try_reserve(1).map_err(|_| FatPathError::NoCapacity)?;
                self.visited.push(next);
                self.cluster = next;
                self.cluster_index += 1;
                self.sector_in_cluster = if self.cluster_index == self.target_cluster {
                    self.target_sector
                } else { 0 };
                self.phase = if self.cluster_index < self.target_cluster {
                    FatRangeRequestKind::Fat
                } else { FatRangeRequestKind::Data };
            }
        }
        Ok(FatRangeProgress::Pending)
    }

    pub fn written(&self) -> usize { self.written }
    pub fn is_complete(&self) -> bool { self.complete }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geometry() -> FatPathGeometry {
        FatPathGeometry { fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 2 }
    }

    #[test]
    fn sector_claim_is_exact_and_range_output_is_owned_by_caller() {
        let mut cursor = FatRangeLookup::new(geometry(), 2, 510, 6).unwrap();
        let mut output = [0; 6];
        let first = cursor.request().unwrap();
        assert_eq!(first, FatRangeRequest { sector: 10, kind: FatRangeRequestKind::Data });
        assert_eq!(cursor.feed(FatRangeRequest { sector: 11, ..first }, &[1; 512], &mut output),
            Err(FatPathError::WrongRequest));
        let mut sector = [0; 512];
        sector[510..].copy_from_slice(&[1, 2]);
        assert_eq!(cursor.feed(first, &sector, &mut output), Ok(FatRangeProgress::Pending));
        let second = cursor.request().unwrap();
        assert_eq!(second.sector, 11);
        sector[..4].copy_from_slice(&[3, 4, 5, 6]);
        assert_eq!(cursor.feed(second, &sector, &mut output), Ok(FatRangeProgress::Complete));
        assert_eq!(output, [1, 2, 3, 4, 5, 6]);
        assert!(cursor.request().is_none());
    }

    #[test]
    fn skips_unneeded_data_with_fat_hops_and_rejects_cycle() {
        let mut cursor = FatRangeLookup::new(geometry(), 2, 1024, 1).unwrap();
        let mut output = [0; 1];
        let fat = cursor.request().unwrap();
        assert_eq!(fat, FatRangeRequest { sector: 1, kind: FatRangeRequestKind::Fat });
        let mut sector = [0; 512];
        sector[8..12].copy_from_slice(&3u32.to_le_bytes());
        cursor.feed(fat, &sector, &mut output).unwrap();
        assert_eq!(cursor.request().unwrap().sector, 12);
        assert_eq!(cursor.feed(cursor.request().unwrap(), &[9; 512], &mut output),
            Ok(FatRangeProgress::Complete));
        assert_eq!(output, [9]);

        let mut cyclic = FatRangeLookup::new(geometry(), 2, 2048, 1).unwrap();
        cyclic.feed(cyclic.request().unwrap(), &sector, &mut output).unwrap();
        sector[12..16].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(cyclic.feed(cyclic.request().unwrap(), &sector, &mut output),
            Err(FatPathError::Corrupt));
    }

    #[test]
    fn batches_only_data_needed_within_one_validated_cluster() {
        let mut cursor = FatRangeLookup::new(geometry(), 2, 510, 5).unwrap();
        assert_eq!(cursor.contiguous_data_sectors(32), Some(2));
        let mut bytes = [0; 1024];
        bytes[510..515].copy_from_slice(&[1, 2, 3, 4, 5]);
        let mut output = [0; 5];
        let first = cursor.request().unwrap();
        assert_eq!(cursor.feed_contiguous_data(first, &bytes, &mut output),
            Ok(FatRangeProgress::Complete));
        assert_eq!(output, [1, 2, 3, 4, 5]);

        let mut boundary = FatRangeLookup::new(geometry(), 2, 0, 1536).unwrap();
        assert_eq!(boundary.contiguous_data_sectors(32), Some(2));
        assert_eq!(boundary.contiguous_data_sectors(1), Some(1));
        assert_eq!(boundary.feed_contiguous_data(boundary.request().unwrap(), &[7; 1024],
            &mut [0; 1536]), Ok(FatRangeProgress::Pending));
        assert_eq!(boundary.request().unwrap().kind, FatRangeRequestKind::Fat);
        assert_eq!(boundary.contiguous_data_sectors(32), None);
    }

    #[test]
    fn malformed_batch_does_not_change_cursor_or_output() {
        let mut cursor = FatRangeLookup::new(geometry(), 2, 0, 1536).unwrap();
        let request = cursor.request().unwrap();
        let mut output = [9; 1536];
        for bytes in [&[1; 511][..], &[1; 1536][..], &[][..]] {
            assert_eq!(cursor.feed_contiguous_data(request, bytes, &mut output),
                Err(FatPathError::WrongRequest));
            assert_eq!(cursor.request(), Some(request));
            assert_eq!(cursor.written(), 0);
            assert!(output.iter().all(|byte| *byte == 9));
        }
        let wrong = FatRangeRequest { sector: request.sector + 1, ..request };
        assert_eq!(cursor.feed_contiguous_data(wrong, &[1; 512], &mut output),
            Err(FatPathError::WrongRequest));
        assert_eq!(cursor.request(), Some(request));
    }

    #[test]
    fn batch_bound_handles_large_requested_length_without_overflow() {
        let cursor = FatRangeLookup::new(geometry(), 2, 510, usize::MAX).unwrap();
        assert_eq!(cursor.contiguous_data_sectors(32), Some(2));
    }
}
