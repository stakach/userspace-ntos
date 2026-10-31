//! Retained output of mounted installed-file reads accepted as pending.
//!
//! A backend owns these bytes until the I/O Manager acknowledges the exact completion.
//! A borrowed dispatch buffer cannot survive native SCSI transport entry.

use alloc::vec::Vec;
use crate::{checked_partition_lba, BlockOperation, FatPathError, FatPathGeometry, FatRangeLookup, FatRangeProgress, FatRangeRequest, FatRangeRequestKind, FatVerifiedChain, STATUS_DATA_ERROR};

// The installed layer is immutable for this mount generation. A larger file remains readable
// when a bounded chain index stops growing; the cursor resumes from its longest proven prefix.
const CHAIN_INDEX_CAP: usize = 16;
const CHAIN_CLUSTER_CAP: usize = 65_536;

struct IndexedChain {
    mount: u64,
    chain: FatVerifiedChain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    Invalid,
    Duplicate,
    NoCapacity,
    WrongIdentity,
    Incomplete,
    NotPublished,
    WrongClaim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReadSectorClaim {
    pub irp: u64,
    pub mount: u64,
    pub file: u64,
    pub request: FatRangeRequest,
    pub sectors: u32,
    pub generation: u64,
}

impl ReadSectorClaim {
    /// Translate the exact claimed range to a physical read. The route owner checks disk bounds
    /// before entry; this also rejects relative-sector and LBA arithmetic overflow.
    pub fn block_read_operation(self, partition_start: u64) -> Option<BlockOperation> {
        if self.sectors == 0
            || (self.sectors > 1 && self.request.kind != FatRangeRequestKind::Data)
        {
            return None;
        }
        let last = self.request.sector.checked_add(self.sectors.checked_sub(1)?)?;
        let lba = checked_partition_lba(partition_start, self.request.sector)?;
        checked_partition_lba(partition_start, last)?;
        Some(BlockOperation::Read { lba, sectors: self.sectors })
    }

    /// The installed layer is immutable for this mount generation. File data and multi-sector
    /// claims retain their own completion ownership and cannot share this metadata cache.
    pub const fn installed_fat_metadata_sector(self) -> Option<u32> {
        if matches!(self.request.kind, FatRangeRequestKind::Fat) && self.sectors == 1 {
            Some(self.request.sector)
        } else {
            None
        }
    }
}

struct Entry {
    irp: u64,
    mount: u64,
    file: u64,
    expected: usize,
    output: Vec<u8>,
    terminal: Option<(i32, usize)>,
    published: bool,
    cursor: Option<FatRangeLookup>,
    indexed_clusters: usize,
    claimed: Option<ReadSectorClaim>,
    position: Option<(u32, u64)>,
    position_committed: bool,
}

pub struct ReadCompletions {
    entries: Vec<Entry>,
    next_generation: u64,
    chains: Vec<IndexedChain>,
    next_chain_eviction: usize,
}

impl ReadCompletions {
    pub const fn new() -> Self {
        Self { entries: Vec::new(), next_generation: 0,
            chains: Vec::new(), next_chain_eviction: 0 }
    }

    pub fn has_outstanding(&self) -> bool { !self.entries.is_empty() }

    pub fn has_claimable_sector(&self) -> bool {
        self.entries.iter().any(|entry| entry.cursor.as_ref().is_some_and(|cursor| cursor.request().is_some())
            && entry.claimed.is_none() && entry.terminal.is_none())
    }

    pub fn needs_backend_service(&self) -> bool { self.pending_position().is_some() }

    /// Allocate the complete output owner before entering a native provider.
    pub fn reserve(&mut self, irp: u64, mount: u64, file: u64, expected: usize) -> Result<(), ReadError> {
        if irp == 0 || mount == 0 || file == 0 || expected == 0 {
            return Err(ReadError::Invalid);
        }
        if self.entries.iter().any(|entry| entry.irp == irp) {
            return Err(ReadError::Duplicate);
        }
        self.entries.try_reserve(1).map_err(|_| ReadError::NoCapacity)?;
        let mut output = Vec::new();
        output.try_reserve_exact(expected).map_err(|_| ReadError::NoCapacity)?;
        output.resize(expected, 0);
        self.entries.push(Entry { irp, mount, file, expected, output, terminal: None,
            published: false, cursor: None, indexed_clusters: 0, claimed: None,
            position: None, position_committed: true });
        Ok(())
    }

    pub fn capture_range(&mut self, irp: u64, mount: u64, file: u64,
        geometry: FatPathGeometry, first_cluster: u32, offset: u32, expected: usize,
        position: Option<(u32, u64)>) -> Result<(), ReadError>
    {
        let cursor = self.chains.iter()
            .find(|entry| entry.mount == mount && entry.chain.geometry() == geometry
                && entry.chain.first_cluster() == first_cluster)
            .map_or_else(
                || FatRangeLookup::new(geometry, first_cluster, offset, expected),
                |entry| match entry.chain.lookup(offset, expected) {
                    // The index is an optimization. A failed prefix clone must not turn a
                    // readable file into a failed I/O when a fresh cursor can be allocated.
                    Err(FatPathError::NoCapacity) =>
                        FatRangeLookup::new(geometry, first_cluster, offset, expected),
                    result => result,
                },
            )
            .map_err(|_| ReadError::Invalid)?;
        self.reserve(irp, mount, file, expected)?;
        let entry = self.entry_mut(irp, mount, file)?;
        entry.cursor = Some(cursor);
        entry.position = position;
        entry.position_committed = position.is_none();
        Ok(())
    }

    pub fn claim_next(&mut self) -> Option<ReadSectorClaim> {
        self.claim_next_bounded(32)
    }

    /// The caller supplies the live transport's numeric sector ceiling. FAT and data claims
    /// retain the same exact generation and completion owner regardless of that ceiling.
    pub fn claim_next_bounded(&mut self, max_sectors: u32) -> Option<ReadSectorClaim> {
        if max_sectors == 0 { return None; }
        let generation = self.next_generation.checked_add(1)?;
        let entry = self.entries.iter_mut().find(|entry| entry.cursor.is_some()
            && entry.claimed.is_none() && entry.terminal.is_none())?;
        let request = entry.cursor.as_ref()?.request()?;
        let sectors = entry.cursor.as_ref()?.contiguous_data_sectors(max_sectors).unwrap_or(1);
        let claim = ReadSectorClaim { irp: entry.irp, mount: entry.mount, file: entry.file,
            request, sectors, generation };
        self.next_generation = generation;
        entry.claimed = Some(claim);
        Some(claim)
    }

    pub fn release_unentered(&mut self, claim: ReadSectorClaim) -> Result<(), ReadError> {
        let entry = self.entry_mut(claim.irp, claim.mount, claim.file)?;
        if entry.claimed != Some(claim) { return Err(ReadError::WrongClaim); }
        entry.claimed = None;
        Ok(())
    }

    /// Refuse a certainly unentered physical request without losing its pending IRP owner.
    /// The terminal remains retained until the caller publishes and acknowledges it.
    pub fn refuse_unentered(&mut self, claim: ReadSectorClaim, status: i32)
        -> Result<(), ReadError>
    {
        if status >= 0 { return Err(ReadError::Invalid); }
        let entry = self.entry_mut(claim.irp, claim.mount, claim.file)?;
        if entry.claimed != Some(claim) || entry.terminal.is_some() {
            return Err(ReadError::WrongClaim);
        }
        entry.claimed = None;
        entry.terminal = Some((status, 0));
        entry.position_committed = true;
        Ok(())
    }

    pub fn complete_sectors(&mut self, claim: ReadSectorClaim,
        sectors: Result<&[u8], FatPathError>) -> Result<FatRangeProgress, ReadError>
    {
        let entry = self.entries.iter_mut()
            .find(|entry| entry.irp == claim.irp && entry.mount == claim.mount
                && entry.file == claim.file).ok_or(ReadError::WrongIdentity)?;
        if entry.claimed != Some(claim) || entry.terminal.is_some() {
            return Err(ReadError::WrongClaim);
        }
        let result = match sectors {
            Ok(bytes) if bytes.len() == claim.sectors as usize * 512 => {
                let cursor = entry.cursor.as_mut().ok_or(ReadError::WrongClaim)?;
                if claim.sectors == 1 {
                    cursor.feed(claim.request, bytes.try_into().expect("exact sector length"),
                        &mut entry.output)
                } else {
                    cursor.feed_contiguous_data(claim.request, bytes, &mut entry.output)
                }
            }
            Ok(_) => Err(FatPathError::WrongRequest),
            Err(error) => Err(error),
        };
        entry.claimed = None;
        let valid_completion = result.is_ok();
        let progress = match result {
            Ok(FatRangeProgress::Complete) => {
                entry.terminal = Some((0, entry.expected));
                Ok(FatRangeProgress::Complete)
            }
            Ok(FatRangeProgress::Pending) => Ok(FatRangeProgress::Pending),
            Err(_) => {
                entry.terminal = Some((STATUS_DATA_ERROR as i32, 0));
                entry.position_committed = true;
                Ok(FatRangeProgress::Complete)
            }
        };
        if valid_completion {
            let cursor = entry.cursor.as_ref().expect("completed read owner retains cursor");
            if cursor.verified_len() > entry.indexed_clusters {
                if matches!(Self::retain_chain(&mut self.chains, &mut self.next_chain_eviction,
                    claim.mount, cursor), Err(FatPathError::Corrupt | FatPathError::Invalid))
                {
                    entry.terminal = Some((STATUS_DATA_ERROR as i32, 0));
                    entry.position_committed = true;
                    return Ok(FatRangeProgress::Complete);
                }
                // NoCapacity also leaves this read valid. Avoid retrying the same optional
                // index update on every data sector in the current cluster.
                entry.indexed_clusters = cursor.verified_len();
            }
        }
        progress
    }

    fn retain_chain(chains: &mut Vec<IndexedChain>, next_eviction: &mut usize,
        mount: u64, cursor: &FatRangeLookup) -> Result<(), FatPathError>
    {
        if cursor.verified_len() > CHAIN_CLUSTER_CAP { return Ok(()); }
        if let Some(index) = chains.iter_mut().find(|index| index.mount == mount
            && index.chain.geometry() == cursor.geometry()
            && index.chain.first_cluster() == cursor.first_cluster()) {
            return index.chain.absorb(cursor);
        }
        let mut chain = FatVerifiedChain::new(cursor.geometry(), cursor.first_cluster())?;
        chain.absorb(cursor)?;
        let indexed = IndexedChain { mount, chain };
        if chains.len() < CHAIN_INDEX_CAP {
            chains.try_reserve(1).map_err(|_| FatPathError::NoCapacity)?;
            chains.push(indexed);
        } else {
            chains[*next_eviction] = indexed;
            *next_eviction = (*next_eviction + 1) % CHAIN_INDEX_CAP;
        }
        Ok(())
    }

    pub fn pending_position(&self) -> Option<(u64, u32, u64)> {
        self.entries.iter().find_map(|entry| {
            (entry.terminal.is_some_and(|(status, _)| status == 0) && !entry.position_committed)
                .then(|| entry.position.map(|(open, next)| (entry.irp, open, next))).flatten()
        })
    }

    pub fn mark_position_committed(&mut self, irp: u64) -> Result<(), ReadError> {
        let entry = self.entries.iter_mut().find(|entry| entry.irp == irp)
            .ok_or(ReadError::WrongIdentity)?;
        if entry.terminal.is_none() || entry.position.is_none() { return Err(ReadError::Invalid); }
        entry.position_committed = true;
        Ok(())
    }

    fn entry_mut(&mut self, irp: u64, mount: u64, file: u64) -> Result<&mut Entry, ReadError> {
        self.entries.iter_mut().find(|entry| entry.irp == irp && entry.mount == mount && entry.file == file)
            .ok_or(ReadError::WrongIdentity)
    }

    pub fn complete(&mut self, irp: u64, mount: u64, file: u64, bytes: &[u8]) -> Result<(), ReadError> {
        let entry = self.entry_mut(irp, mount, file)?;
        if entry.terminal.is_some() {
            return Err(ReadError::Duplicate);
        }
        if bytes.len() != entry.expected {
            return Err(ReadError::Incomplete);
        }
        entry.output.copy_from_slice(bytes);
        entry.terminal = Some((0, bytes.len()));
        Ok(())
    }

    pub fn fail(&mut self, irp: u64, mount: u64, file: u64, status: i32) -> Result<(), ReadError> {
        if status >= 0 {
            return Err(ReadError::Invalid);
        }
        let entry = self.entry_mut(irp, mount, file)?;
        if entry.terminal.is_some() {
            return Err(ReadError::Duplicate);
        }
        entry.terminal = Some((status, 0));
        entry.position_committed = true;
        Ok(())
    }

    pub fn next_completion(&mut self) -> Option<(u64, i32, usize)> {
        let entry = self.entries.iter_mut().find(|entry| entry.terminal.is_some()
            && entry.position_committed && !entry.published)?;
        entry.published = true;
        let (status, transferred) = entry.terminal?;
        Some((entry.irp, status, transferred))
    }

    pub fn copy(&self, irp: u64, offset: usize, output: &mut [u8]) -> Result<usize, ReadError> {
        let entry = self.entries.iter().find(|entry| entry.irp == irp).ok_or(ReadError::WrongIdentity)?;
        if !entry.published { return Err(ReadError::NotPublished); }
        let (_, transferred) = entry.terminal.ok_or(ReadError::NotPublished)?;
        let remaining = transferred.checked_sub(offset).ok_or(ReadError::Invalid)?;
        let copied = remaining.min(output.len());
        output[..copied].copy_from_slice(&entry.output[offset..offset + copied]);
        Ok(copied)
    }

    pub fn ack(&mut self, irp: u64) -> Result<(), ReadError> {
        let index = self.entries.iter().position(|entry| entry.irp == irp).ok_or(ReadError::WrongIdentity)?;
        if !self.entries[index].published { return Err(ReadError::NotPublished); }
        self.entries.swap_remove(index);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_single_sector_fat_reads_are_installed_metadata() {
        let mut claim = ReadSectorClaim {
            irp: 1,
            mount: 2,
            file: 3,
            request: FatRangeRequest { sector: 42, kind: FatRangeRequestKind::Fat },
            sectors: 1,
            generation: 4,
        };
        assert_eq!(claim.installed_fat_metadata_sector(), Some(42));

        claim.request.kind = FatRangeRequestKind::Data;
        assert_eq!(claim.installed_fat_metadata_sector(), None);
        claim.sectors = 4;
        assert_eq!(claim.installed_fat_metadata_sector(), None);

        claim.request.kind = FatRangeRequestKind::Fat;
        assert_eq!(claim.installed_fat_metadata_sector(), None);
    }

    #[test]
    fn pending_read_retains_output_until_exact_ack() {
        let mut reads = ReadCompletions::new();
        reads.reserve(0x1_0001, 7, 9, 4).unwrap();
        assert_eq!(reads.reserve(0x1_0001, 7, 9, 4), Err(ReadError::Duplicate));
        assert_eq!(reads.complete(0x1_0002, 7, 9, &[1, 2, 3, 4]), Err(ReadError::WrongIdentity));
        assert_eq!(reads.copy(0x1_0001, 0, &mut [0; 4]), Err(ReadError::NotPublished));
        let mut source = [1, 2, 3, 4];
        reads.complete(0x1_0001, 7, 9, &source).unwrap();
        source.fill(0);
        assert_eq!(reads.next_completion(), Some((0x1_0001, 0, 4)));
        assert_eq!(reads.next_completion(), None);
        let mut out = [0; 4];
        assert_eq!(reads.copy(0x1_0001, 0, &mut out), Ok(4));
        assert_eq!(out, [1, 2, 3, 4]);
        assert_eq!(reads.ack(0x1_0002), Err(ReadError::WrongIdentity));
        assert_eq!(reads.ack(0x1_0001), Ok(()));
        assert_eq!(reads.copy(0x1_0001, 0, &mut out), Err(ReadError::WrongIdentity));
    }

    #[test]
    fn generation_and_length_mismatch_do_not_publish() {
        let mut reads = ReadCompletions::new();
        reads.reserve(0x1_0001, 7, 9, 4).unwrap();
        assert_eq!(reads.complete(0x1_0001, 8, 9, &[1; 4]), Err(ReadError::WrongIdentity));
        assert_eq!(reads.complete(0x1_0001, 7, 9, &[1; 3]), Err(ReadError::Incomplete));
        assert_eq!(reads.next_completion(), None);
        assert_eq!(reads.ack(0x1_0001), Err(ReadError::NotPublished));
    }

    #[test]
    fn terminal_failure_keeps_exact_owner_until_ack() {
        let mut reads = ReadCompletions::new();
        reads.reserve(0x1_0001, 7, 9, 512).unwrap();
        assert_eq!(reads.fail(0x1_0001, 7, 8, -1), Err(ReadError::WrongIdentity));
        reads.fail(0x1_0001, 7, 9, -1).unwrap();
        assert_eq!(reads.next_completion(), Some((0x1_0001, -1, 0)));
        assert_eq!(reads.copy(0x1_0001, 0, &mut [0; 1]), Ok(0));
        reads.ack(0x1_0001).unwrap();
    }

    #[test]
    fn unentered_refusal_requires_exact_claim_and_publishes_one_failure() {
        let mut reads = ReadCompletions::new();
        let geometry = FatPathGeometry {
            fat_start_sector: 1, data_start_sector: 2, total_sectors: 18,
            sectors_per_cluster: 1,
        };
        reads.capture_range(0x51, 7, 9, geometry, 2, 0, 512, Some((11, 512)))
            .unwrap();
        let claim = reads.claim_next_bounded(4).unwrap();
        assert_eq!(reads.refuse_unentered(ReadSectorClaim { generation: claim.generation + 1, ..claim },
            STATUS_DATA_ERROR as i32), Err(ReadError::WrongClaim));
        assert_eq!(reads.refuse_unentered(ReadSectorClaim { file: 10, ..claim },
            STATUS_DATA_ERROR as i32), Err(ReadError::WrongIdentity));
        assert_eq!(reads.refuse_unentered(claim, 0), Err(ReadError::Invalid));
        assert_eq!(reads.next_completion(), None);
        reads.refuse_unentered(claim, STATUS_DATA_ERROR as i32).unwrap();
        assert_eq!(reads.next_completion(), Some((0x51, STATUS_DATA_ERROR as i32, 0)));
        assert_eq!(reads.next_completion(), None);
        assert!(reads.claim_next_bounded(1).is_none());
        assert_eq!(reads.refuse_unentered(claim, STATUS_DATA_ERROR as i32),
            Err(ReadError::WrongClaim));
        reads.ack(0x51).unwrap();
        assert!(!reads.has_outstanding());
    }

    #[test]
    fn native_sector_claim_is_exact_and_completed_read_waits_for_position_commit() {
        let geometry = FatPathGeometry { fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 2 };
        let mut reads = ReadCompletions::new();
        reads.capture_range(11, 7, 9, geometry, 2, 510, 4, Some((5, 514))).unwrap();
        let first = reads.claim_next().unwrap();
        assert_eq!(first.request.sector, 10);
        assert_eq!(first.sectors, 2);
        assert!(reads.claim_next().is_none());
        assert_eq!(reads.complete_sectors(ReadSectorClaim { mount: 8, ..first }, Ok(&[0; 1024])),
            Err(ReadError::WrongIdentity));
        let mut sectors = [0; 1024];
        sectors[510..514].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(reads.complete_sectors(first, Ok(&sectors)), Ok(FatRangeProgress::Complete));
        assert!(!reads.has_claimable_sector());
        assert!(reads.needs_backend_service());
        assert!(reads.has_outstanding());
        assert_eq!(reads.next_completion(), None);
        assert_eq!(reads.pending_position(), Some((11, 5, 514)));
        reads.mark_position_committed(11).unwrap();
        assert!(!reads.needs_backend_service());
        assert_eq!(reads.next_completion(), Some((11, 0, 4)));
        let mut output = [0; 4];
        assert_eq!(reads.copy(11, 0, &mut output), Ok(4));
        assert_eq!(output, [1, 2, 3, 4]);
        reads.ack(11).unwrap();
    }

    #[test]
    fn transport_bound_preserves_exact_claim_and_rejects_short_completion() {
        let geometry = FatPathGeometry { fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 4 };
        let mut reads = ReadCompletions::new();
        reads.capture_range(11, 7, 9, geometry, 2, 0, 2048, None).unwrap();
        assert!(reads.claim_next_bounded(0).is_none());
        let first = reads.claim_next_bounded(2).unwrap();
        assert_eq!(first.sectors, 2);
        assert!(reads.claim_next_bounded(2).is_none());
        assert_eq!(reads.complete_sectors(first, Ok(&[1; 512])),
            Ok(FatRangeProgress::Complete));
        assert_eq!(reads.next_completion(), Some((11, STATUS_DATA_ERROR as i32, 0)));
        reads.ack(11).unwrap();

        reads.capture_range(12, 7, 9, geometry, 2, 0, 2048, None).unwrap();
        let first = reads.claim_next_bounded(2).unwrap();
        assert_eq!(first.sectors, 2);
        assert_eq!(reads.complete_sectors(first, Ok(&[1; 1024])),
            Ok(FatRangeProgress::Pending));
        let second = reads.claim_next_bounded(2).unwrap();
        assert_eq!(second.request.sector, first.request.sector + 2);
        assert_eq!(second.sectors, 2);
        assert_eq!(reads.complete_sectors(second, Ok(&[2; 1024])),
            Ok(FatRangeProgress::Complete));
        assert_eq!(reads.next_completion(), Some((12, 0, 2048)));
        let mut output = [0; 2048];
        assert_eq!(reads.copy(12, 0, &mut output), Ok(2048));
        assert_eq!(&output[..1024], &[1; 1024]);
        assert_eq!(&output[1024..], &[2; 1024]);
        reads.ack(12).unwrap();
    }

    #[test]
    fn native_block_read_uses_the_entire_verified_claim_and_exact_completion() {
        let geometry = FatPathGeometry { fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 4 };
        let mut reads = ReadCompletions::new();
        reads.capture_range(21, 7, 9, geometry, 2, 0, 2048, None).unwrap();
        let claim = reads.claim_next_bounded(4).unwrap();
        assert_eq!(claim.block_read_operation(100), Some(BlockOperation::Read {
            lba: 110, sectors: 4,
        }));
        assert_eq!(reads.complete_sectors(claim, Ok(&[7; 2048])),
            Ok(FatRangeProgress::Complete));
        assert_eq!(reads.next_completion(), Some((21, 0, 2048)));
        let mut output = [0; 2048];
        assert_eq!(reads.copy(21, 0, &mut output), Ok(2048));
        assert_eq!(output, [7; 2048]);

        assert_eq!(ReadSectorClaim { sectors: 2, request: FatRangeRequest {
            sector: u32::MAX, kind: FatRangeRequestKind::Data,
        }, ..claim }.block_read_operation(100), None);
        assert_eq!(ReadSectorClaim { sectors: 2, request: FatRangeRequest {
            sector: 1, kind: FatRangeRequestKind::Fat,
        }, ..claim }.block_read_operation(100), None);
    }

    #[test]
    fn changed_transport_bound_releases_unentered_claim_before_replanning() {
        let geometry = FatPathGeometry { fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 4 };
        let mut reads = ReadCompletions::new();
        reads.capture_range(11, 7, 9, geometry, 2, 0, 2048, None).unwrap();
        let obsolete = reads.claim_next_bounded(4).unwrap();
        assert_eq!(obsolete.sectors, 4);
        reads.release_unentered(obsolete).unwrap();
        let current = reads.claim_next_bounded(1).unwrap();
        assert_eq!(current.sectors, 1);
        assert_ne!(current.generation, obsolete.generation);
        assert_eq!(reads.complete_sectors(obsolete, Ok(&[1; 2048])),
            Err(ReadError::WrongClaim));
        for expected_sector in 10..14 {
            let claim = if expected_sector == 10 { current }
                else { reads.claim_next_bounded(1).unwrap() };
            assert_eq!(claim.request.sector, expected_sector);
            let progress = reads.complete_sectors(claim, Ok(&[1; 512])).unwrap();
            assert_eq!(progress, if expected_sector == 13 {
                FatRangeProgress::Complete
            } else { FatRangeProgress::Pending });
        }
        assert_eq!(reads.next_completion(), Some((11, 0, 2048)));
    }

    #[test]
    fn later_page_window_reuses_only_verified_chain_of_the_same_mount() {
        let geometry = FatPathGeometry { fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 1 };
        let mut reads = ReadCompletions::new();
        reads.capture_range(11, 7, 9, geometry, 2, 0, 1536, None).unwrap();
        let data = reads.claim_next().unwrap();
        assert_eq!(data.request, FatRangeRequest { sector: 10, kind: FatRangeRequestKind::Data });
        reads.complete_sectors(data, Ok(&[1; 512])).unwrap();
        let fat = reads.claim_next().unwrap();
        assert_eq!(fat.request, FatRangeRequest { sector: 1, kind: FatRangeRequestKind::Fat });
        let mut sector = [0; 512];
        sector[8..12].copy_from_slice(&3u32.to_le_bytes());
        sector[12..16].copy_from_slice(&4u32.to_le_bytes());
        reads.complete_sectors(fat, Ok(&sector)).unwrap();
        let data = reads.claim_next().unwrap();
        assert_eq!(data.request.sector, 11);
        assert_eq!(data.sectors, 2);
        reads.complete_sectors(data, Ok(&[2; 1024])).unwrap();
        assert_eq!(reads.next_completion(), Some((11, 0, 1536)));
        reads.ack(11).unwrap();

        reads.capture_range(12, 7, 9, geometry, 2, 1024, 512, None).unwrap();
        let cached = reads.claim_next().unwrap();
        assert_eq!(cached.request, FatRangeRequest { sector: 12,
            kind: FatRangeRequestKind::Data });
        reads.complete_sectors(cached, Ok(&[3; 512])).unwrap();
        assert_eq!(reads.next_completion(), Some((12, 0, 512)));
        reads.ack(12).unwrap();

        reads.capture_range(13, 8, 9, geometry, 2, 1024, 512, None).unwrap();
        let other_mount = reads.claim_next().unwrap();
        assert_eq!(other_mount.request.kind, FatRangeRequestKind::Fat);
    }

    #[test]
    fn corrupt_fat_completion_never_extends_verified_chain() {
        let geometry = FatPathGeometry { fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 1 };
        let mut reads = ReadCompletions::new();
        reads.capture_range(11, 7, 9, geometry, 2, 512, 512, None).unwrap();
        let fat = reads.claim_next().unwrap();
        assert_eq!(fat.request.kind, FatRangeRequestKind::Fat);
        assert_eq!(reads.complete_sectors(fat, Ok(&[0; 512])),
            Ok(FatRangeProgress::Complete));
        assert_eq!(reads.next_completion(), Some((11, STATUS_DATA_ERROR as i32, 0)));
        reads.ack(11).unwrap();

        reads.capture_range(12, 7, 9, geometry, 2, 512, 512, None).unwrap();
        assert_eq!(reads.claim_next().unwrap().request.kind, FatRangeRequestKind::Fat);
    }

    #[test]
    fn settled_sector_exposes_next_queued_read_without_retry_delay() {
        let geometry = FatPathGeometry { fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 1 };
        let mut reads = ReadCompletions::new();
        reads.capture_range(11, 7, 9, geometry, 2, 0, 512, None).unwrap();
        reads.capture_range(12, 7, 10, geometry, 3, 0, 512, None).unwrap();
        let first = reads.claim_next().unwrap();
        assert_eq!(first.irp, 11);
        assert_eq!(reads.complete_sectors(first, Ok(&[1; 512])),
            Ok(FatRangeProgress::Complete));
        let next = reads.claim_next().unwrap();
        assert_eq!(next.irp, 12);
        assert_eq!(next.request.sector, 11);
    }

    #[test]
    fn later_window_extends_the_index_only_after_new_fat_evidence() {
        let geometry = FatPathGeometry { fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 1 };
        let mut reads = ReadCompletions::new();
        reads.capture_range(11, 7, 9, geometry, 2, 0, 1024, None).unwrap();
        let first = reads.claim_next().unwrap();
        reads.complete_sectors(first, Ok(&[1; 512])).unwrap();
        let fat = reads.claim_next().unwrap();
        let mut sector = [0; 512];
        sector[8..12].copy_from_slice(&3u32.to_le_bytes());
        sector[12..16].copy_from_slice(&4u32.to_le_bytes());
        sector[16..20].copy_from_slice(&5u32.to_le_bytes());
        reads.complete_sectors(fat, Ok(&sector)).unwrap();
        let second = reads.claim_next().unwrap();
        reads.complete_sectors(second, Ok(&[2; 512])).unwrap();
        assert_eq!(reads.next_completion(), Some((11, 0, 1024)));
        reads.ack(11).unwrap();

        reads.capture_range(12, 7, 9, geometry, 2, 1536, 512, None).unwrap();
        let new_tail = reads.claim_next().unwrap();
        assert_eq!(new_tail.request.kind, FatRangeRequestKind::Fat);
        reads.complete_sectors(new_tail, Ok(&sector)).unwrap();
        let data = reads.claim_next().unwrap();
        assert_eq!(data.request.sector, 13);
        reads.complete_sectors(data, Ok(&[3; 512])).unwrap();
        assert_eq!(reads.next_completion(), Some((12, 0, 512)));
        reads.ack(12).unwrap();

        reads.capture_range(13, 7, 9, geometry, 2, 1536, 512, None).unwrap();
        assert_eq!(reads.claim_next().unwrap().request,
            FatRangeRequest { sector: 13, kind: FatRangeRequestKind::Data });
    }

    #[test]
    fn conflicting_concurrent_fat_successor_fails_without_poisoning_index() {
        let geometry = FatPathGeometry { fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 1 };
        let mut reads = ReadCompletions::new();
        reads.capture_range(11, 7, 9, geometry, 2, 512, 512, None).unwrap();
        reads.capture_range(12, 7, 10, geometry, 2, 512, 512, None).unwrap();
        let first = reads.claim_next().unwrap();
        let second = reads.claim_next().unwrap();
        let mut fat = [0; 512];
        fat[8..12].copy_from_slice(&3u32.to_le_bytes());
        reads.complete_sectors(first, Ok(&fat)).unwrap();
        fat[8..12].copy_from_slice(&4u32.to_le_bytes());
        assert_eq!(reads.complete_sectors(second, Ok(&fat)),
            Ok(FatRangeProgress::Complete));
        assert_eq!(reads.next_completion(), Some((12, STATUS_DATA_ERROR as i32, 0)));
        reads.ack(12).unwrap();
        let first_data = reads.claim_next().unwrap();
        assert_eq!(first_data.irp, 11);
        reads.complete_sectors(first_data, Ok(&[1; 512])).unwrap();
        assert_eq!(reads.next_completion(), Some((11, 0, 512)));
        reads.ack(11).unwrap();
        reads.capture_range(13, 7, 11, geometry, 2, 512, 512, None).unwrap();
        let retained = reads.claim_next().unwrap();
        assert_eq!(retained.irp, 13);
        assert_eq!(retained.request,
            FatRangeRequest { sector: 11, kind: FatRangeRequestKind::Data });
    }

    #[test]
    fn evicted_chain_can_still_be_read_from_fresh_fat_evidence() {
        let geometry = FatPathGeometry { fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 1 };
        let mut reads = ReadCompletions::new();
        for index in 0..=CHAIN_INDEX_CAP {
            let cluster = 2 + index as u32;
            let irp = 100 + index as u64;
            reads.capture_range(irp, 7, irp, geometry, cluster, 0, 512, None).unwrap();
            let data = reads.claim_next().unwrap();
            reads.complete_sectors(data, Ok(&[1; 512])).unwrap();
            assert_eq!(reads.next_completion(), Some((irp, 0, 512)));
            reads.ack(irp).unwrap();
        }
        assert_eq!(reads.chains.len(), CHAIN_INDEX_CAP);
        assert!(!reads.chains.iter().any(|entry| entry.chain.first_cluster() == 2));
        reads.capture_range(200, 7, 200, geometry, 2, 512, 512, None).unwrap();
        assert_eq!(reads.claim_next().unwrap().request.kind, FatRangeRequestKind::Fat);
    }
}
