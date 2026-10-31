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

/// A verified prefix of one immutable installed file's FAT chain. Only successful cursor
/// completions can extend it; a new range may resume from any proven cluster.
pub struct FatVerifiedChain {
    geometry: FatPathGeometry,
    first_cluster: u32,
    clusters: Vec<u32>,
}

impl FatVerifiedChain {
    pub fn new(geometry: FatPathGeometry, first_cluster: u32) -> Result<Self, FatPathError> {
        let cursor = FatRangeLookup::new(geometry, first_cluster, 0, 1)?;
        Ok(Self { geometry, first_cluster, clusters: cursor.visited })
    }

    pub fn absorb(&mut self, cursor: &FatRangeLookup) -> Result<(), FatPathError> {
        if self.geometry != cursor.geometry || cursor.visited.first() != Some(&self.first_cluster) {
            return Err(FatPathError::Invalid);
        }
        let common = self.clusters.len().min(cursor.visited.len());
        if self.clusters[..common] != cursor.visited[..common] {
            return Err(FatPathError::Corrupt);
        }
        if cursor.visited.len() > self.clusters.len() {
            self.clusters.try_reserve(cursor.visited.len() - self.clusters.len())
                .map_err(|_| FatPathError::NoCapacity)?;
            self.clusters.extend_from_slice(&cursor.visited[self.clusters.len()..]);
        }
        Ok(())
    }

    pub fn lookup(&self, offset: u32, length: usize) -> Result<FatRangeLookup, FatPathError> {
        let mut cursor = FatRangeLookup::new(self.geometry, self.first_cluster, offset, length)?;
        cursor.visited.try_reserve(self.clusters.len().saturating_sub(1))
            .map_err(|_| FatPathError::NoCapacity)?;
        cursor.visited.clear();
        cursor.visited.extend_from_slice(&self.clusters);
        let index = (cursor.target_cluster as usize).min(self.clusters.len() - 1);
        cursor.cluster_index = index as u32;
        cursor.cluster = self.clusters[index];
        cursor.sector_in_cluster = if cursor.cluster_index == cursor.target_cluster {
            cursor.target_sector
        } else { 0 };
        cursor.phase = if cursor.cluster_index == cursor.target_cluster {
            FatRangeRequestKind::Data
        } else { FatRangeRequestKind::Fat };
        Ok(cursor)
    }

    pub fn geometry(&self) -> FatPathGeometry { self.geometry }
    pub fn first_cluster(&self) -> u32 { self.first_cluster }
    pub fn len(&self) -> usize { self.clusters.len() }
}

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
    // Retained only by this file-range owner after its exact FAT read completes.
    // A new cursor must obtain its own sector from the installed backing volume.
    cached_fat_sector: Option<(u32, [u8; 512])>,
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
            visited, cached_fat_sector: None,
            phase: if target_cluster == 0 { FatRangeRequestKind::Data } else { FatRangeRequestKind::Fat },
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

    /// Number of physically adjacent file-data sectors proven by this cursor's completed
    /// FAT sector. The caller still retains the exact first request until completion.
    pub fn contiguous_data_sectors(&self, max: u32) -> Option<u32> {
        if max == 0 || self.phase != FatRangeRequestKind::Data || self.request().is_none() {
            return None;
        }
        let skip = if self.written == 0 { self.first_skip } else { 0 };
        // Split before adding: `remaining + skip` can overflow usize for a large request.
        let needed = self.remaining / 512 + (self.remaining % 512 + skip).div_ceil(512);
        let limit = max.min(u32::try_from(needed).unwrap_or(u32::MAX));
        let mut count = limit.min(self.geometry.sectors_per_cluster.checked_sub(self.sector_in_cluster)?);
        let mut cluster = self.cluster;
        let mut index = self.cluster_index as usize;
        while count < limit {
            if let Some(&next) = self.visited.get(index + 1) {
                if cluster.checked_add(1) != Some(next) { break; }
                count += (limit - count).min(self.geometry.sectors_per_cluster);
                cluster = next;
                index += 1;
                continue;
            }
            let fat_sector = self.geometry.fat_start_sector.checked_add(cluster.checked_mul(4)? / 512)?;
            let Some((cached_sector, bytes)) = self.cached_fat_sector.as_ref() else { break; };
            if *cached_sector != fat_sector { break; }
            let byte = (cluster as usize % 128) * 4;
            let next = u32::from_le_bytes(bytes[byte..byte + 4].try_into().unwrap()) & 0x0fff_ffff;
            let clusters = (self.geometry.total_sectors - self.geometry.data_start_sector)
                / self.geometry.sectors_per_cluster;
            if cluster.checked_add(1) != Some(next) || next >= EOC || next == BAD
                || next.checked_sub(2).is_none_or(|index| index >= clusters)
                || self.visited.contains(&next)
            { break; }
            count += (limit - count).min(self.geometry.sectors_per_cluster);
            cluster = next;
            index += 1;
        }
        Some(count).filter(|count| *count != 0)
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
                    self.follow_cached_fat()?;
                }
            }
            FatRangeRequestKind::Fat => {
                let byte = (self.cluster as usize % 128) * 4;
                let next = u32::from_le_bytes(bytes[byte..byte + 4].try_into().unwrap()) & 0x0fff_ffff;
                self.advance_fat_entry(next)?;
                self.cached_fat_sector = Some((request.sector, *bytes));
                self.follow_cached_fat()?;
            }
        }
        Ok(FatRangeProgress::Pending)
    }

    fn advance_fat_entry(&mut self, next: u32) -> Result<(), FatPathError> {
        let clusters = (self.geometry.total_sectors - self.geometry.data_start_sector)
            / self.geometry.sectors_per_cluster;
        if next >= EOC || next == BAD || next < 2
            || next.checked_sub(2).is_none_or(|index| index >= clusters)
            || self.visited.get(self.cluster_index as usize + 1).is_some_and(|known| *known != next)
            || (self.visited.get(self.cluster_index as usize + 1).is_none()
                && self.visited.contains(&next))
        { return Err(FatPathError::Corrupt); }
        if self.visited.get(self.cluster_index as usize + 1).is_none() {
            self.visited.try_reserve(1).map_err(|_| FatPathError::NoCapacity)?;
            self.visited.push(next);
        }
        self.cluster = next;
        self.cluster_index += 1;
        self.sector_in_cluster = if self.cluster_index == self.target_cluster {
            self.target_sector
        } else { 0 };
        self.phase = if self.cluster_index < self.target_cluster {
            FatRangeRequestKind::Fat
        } else { FatRangeRequestKind::Data };
        Ok(())
    }

    fn follow_cached_fat(&mut self) -> Result<(), FatPathError> {
        while self.phase == FatRangeRequestKind::Fat {
            if let Some(&next) = self.visited.get(self.cluster_index as usize + 1) {
                self.advance_fat_entry(next)?;
                continue;
            }
            let request = self.request().ok_or(FatPathError::Invalid)?;
            let Some((sector, bytes)) = self.cached_fat_sector.as_ref() else { break; };
            if *sector != request.sector { break; }
            let byte = (self.cluster as usize % 128) * 4;
            let next = u32::from_le_bytes(bytes[byte..byte + 4].try_into().unwrap()) & 0x0fff_ffff;
            self.advance_fat_entry(next)?;
        }
        Ok(())
    }

    pub fn written(&self) -> usize { self.written }
    pub fn geometry(&self) -> FatPathGeometry { self.geometry }
    pub fn first_cluster(&self) -> u32 { self.visited[0] }
    pub fn verified_len(&self) -> usize { self.visited.len() }
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
        sector[12..16].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(cyclic.feed(cyclic.request().unwrap(), &sector, &mut output),
            Err(FatPathError::Corrupt));
    }

    #[test]
    fn one_verified_fat_sector_advances_all_clusters_it_describes() {
        let mut cursor = FatRangeLookup::new(geometry(), 2, 0, 5 * 512).unwrap();
        let mut output = [0; 5 * 512];
        let mut fat_sector = [0; 512];
        fat_sector[2 * 4..3 * 4].copy_from_slice(&3u32.to_le_bytes());
        fat_sector[3 * 4..4 * 4].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(cursor.feed_contiguous_data(cursor.request().unwrap(), &[1; 1024],
            &mut output), Ok(FatRangeProgress::Pending));
        let fat = cursor.request().unwrap();
        assert_eq!(fat, FatRangeRequest { sector: 1, kind: FatRangeRequestKind::Fat });
        assert_eq!(cursor.feed(fat, &fat_sector, &mut output), Ok(FatRangeProgress::Pending));
        assert_eq!(cursor.request(), Some(FatRangeRequest {
            sector: 12, kind: FatRangeRequestKind::Data,
        }));
        assert_eq!(cursor.feed_contiguous_data(cursor.request().unwrap(), &[2; 1024],
            &mut output), Ok(FatRangeProgress::Pending));
        assert_eq!(cursor.request(), Some(FatRangeRequest {
            sector: 14, kind: FatRangeRequestKind::Data,
        }), "the retained FAT sector covers the next cluster without another I/O");
        assert_eq!(cursor.feed(cursor.request().unwrap(), &[3; 512], &mut output),
            Ok(FatRangeProgress::Complete));
        assert_eq!(&output[..1024], &[1; 1024]);
        assert_eq!(&output[1024..2048], &[2; 1024]);
        assert_eq!(&output[2048..], &[3; 512]);

        let fresh = FatRangeLookup::new(geometry(), 2, 2 * 1024, 1).unwrap();
        assert_eq!(fresh.request(), Some(fat), "a new cursor must obtain its own FAT proof");
    }

    #[test]
    fn verified_file_chain_starts_later_range_without_rewalking_earlier_fat() {
        let geometry = FatPathGeometry { sectors_per_cluster: 1, ..geometry() };
        let mut first = FatRangeLookup::new(geometry, 2, 0, 3 * 512).unwrap();
        let mut output = [0; 3 * 512];
        first.feed(first.request().unwrap(), &[1; 512], &mut output).unwrap();
        let mut fat = [0; 512];
        fat[8..12].copy_from_slice(&3u32.to_le_bytes());
        fat[12..16].copy_from_slice(&4u32.to_le_bytes());
        first.feed(first.request().unwrap(), &fat, &mut output).unwrap();
        first.feed(first.request().unwrap(), &[2; 512], &mut output).unwrap();
        first.feed(first.request().unwrap(), &[3; 512], &mut output).unwrap();

        let mut chain = FatVerifiedChain::new(geometry, 2).unwrap();
        chain.absorb(&first).unwrap();
        let later = chain.lookup(2 * 512, 512).unwrap();
        assert_eq!(later.request(), Some(FatRangeRequest { sector: 12,
            kind: FatRangeRequestKind::Data }));
        assert_eq!(later.contiguous_data_sectors(32), Some(1));

        let beyond = chain.lookup(3 * 512, 512).unwrap();
        assert_eq!(beyond.request(), Some(FatRangeRequest { sector: 1,
            kind: FatRangeRequestKind::Fat }), "unverified tail still requires FAT I/O");

        let mut extended = chain.lookup(512, 3 * 512).unwrap();
        let mut output = [0; 3 * 512];
        extended.feed(extended.request().unwrap(), &[1; 512], &mut output).unwrap();
        extended.feed(extended.request().unwrap(), &[2; 512], &mut output).unwrap();
        let mut cycle = [0; 512];
        cycle[4 * 4..5 * 4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(extended.feed(extended.request().unwrap(), &cycle, &mut output),
            Err(FatPathError::Corrupt), "a later loop into the shared prefix remains corrupt");
    }

    #[test]
    fn cached_fat_sector_does_not_cross_into_an_unread_sector() {
        let mut cursor = FatRangeLookup::new(geometry(), 127, 0, 5 * 512).unwrap();
        let mut output = [0; 5 * 512];
        cursor.feed_contiguous_data(cursor.request().unwrap(), &[1; 1024], &mut output).unwrap();
        let first = cursor.request().unwrap();
        assert_eq!(first.sector, 1);
        let mut sector = [0; 512];
        sector[127 * 4..128 * 4].copy_from_slice(&128u32.to_le_bytes());
        cursor.feed(first, &sector, &mut output).unwrap();
        cursor.feed_contiguous_data(cursor.request().unwrap(), &[2; 1024], &mut output).unwrap();
        assert_eq!(cursor.request(), Some(FatRangeRequest {
            sector: 2, kind: FatRangeRequestKind::Fat,
        }));
        assert_eq!(cursor.feed(first, &sector, &mut output), Err(FatPathError::WrongRequest));
        assert_eq!(cursor.written(), 4 * 512);
    }

    #[test]
    fn completed_fat_proof_batches_physically_adjacent_clusters() {
        let mut one_sector_clusters = geometry();
        one_sector_clusters.sectors_per_cluster = 1;
        let mut cursor = FatRangeLookup::new(one_sector_clusters, 2, 0, 4 * 512).unwrap();
        let mut output = [0; 4 * 512];
        assert_eq!(cursor.contiguous_data_sectors(32), Some(1));
        cursor.feed(cursor.request().unwrap(), &[1; 512], &mut output).unwrap();
        let mut fat = [0; 512];
        for cluster in 2..5 {
            fat[cluster * 4..(cluster + 1) * 4]
                .copy_from_slice(&((cluster + 1) as u32).to_le_bytes());
        }
        cursor.feed(cursor.request().unwrap(), &fat, &mut output).unwrap();
        assert_eq!(cursor.contiguous_data_sectors(32), Some(3));
        assert_eq!(cursor.feed_contiguous_data(cursor.request().unwrap(), &[2; 3 * 512],
            &mut output), Ok(FatRangeProgress::Complete));
        assert_eq!(&output[..512], &[1; 512]);
        assert_eq!(&output[512..], &[2; 3 * 512]);

        let mut fragmented = FatRangeLookup::new(one_sector_clusters, 2, 0, 4 * 512).unwrap();
        let mut fragment_output = [0; 4 * 512];
        fragmented.feed(fragmented.request().unwrap(), &[1; 512], &mut fragment_output).unwrap();
        fat[3 * 4..4 * 4].copy_from_slice(&7u32.to_le_bytes());
        fragmented.feed(fragmented.request().unwrap(), &fat, &mut fragment_output).unwrap();
        assert_eq!(fragmented.contiguous_data_sectors(32), Some(1),
            "a nonadjacent cluster must start another physical command");
    }

    #[test]
    fn adjacent_cluster_batch_stops_at_the_caller_command_limit() {
        let mut one_sector_clusters = geometry();
        one_sector_clusters.sectors_per_cluster = 1;
        let mut cursor = FatRangeLookup::new(one_sector_clusters, 2, 0, 40 * 512).unwrap();
        let mut output = [0; 40 * 512];
        cursor.feed(cursor.request().unwrap(), &[1; 512], &mut output).unwrap();
        let mut fat = [0; 512];
        for cluster in 2..42 {
            fat[cluster * 4..(cluster + 1) * 4]
                .copy_from_slice(&((cluster + 1) as u32).to_le_bytes());
        }
        cursor.feed(cursor.request().unwrap(), &fat, &mut output).unwrap();
        let first = cursor.request().unwrap();
        assert_eq!(cursor.contiguous_data_sectors(32), Some(32));
        assert_eq!(cursor.feed_contiguous_data(first, &[2; 32 * 512], &mut output),
            Ok(FatRangeProgress::Pending));
        assert_eq!(cursor.contiguous_data_sectors(32), Some(7));
        assert_eq!(cursor.feed_contiguous_data(cursor.request().unwrap(), &[3; 7 * 512],
            &mut output), Ok(FatRangeProgress::Complete));
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
