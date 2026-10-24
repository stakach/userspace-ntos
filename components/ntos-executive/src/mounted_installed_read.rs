//! Retained output of mounted installed-file reads accepted as pending.
//!
//! A backend owns these bytes until the I/O Manager acknowledges the exact completion.
//! A borrowed dispatch buffer cannot survive native SCSI transport entry.

use alloc::vec::Vec;
use nt_fs::{FatPathError, FatPathGeometry, FatRangeLookup, FatRangeProgress, FatRangeRequest};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReadError {
    Invalid,
    Duplicate,
    NoCapacity,
    WrongIdentity,
    Incomplete,
    NotPublished,
    WrongClaim,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReadSectorClaim {
    pub irp: u64,
    pub mount: u64,
    pub file: u64,
    pub request: FatRangeRequest,
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
    claimed: Option<FatRangeRequest>,
    position: Option<(u32, u64)>,
    position_committed: bool,
}

pub(crate) struct ReadCompletions {
    entries: Vec<Entry>,
}

impl ReadCompletions {
    pub const fn new() -> Self {
        Self { entries: Vec::new() }
    }

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
            published: false, cursor: None, claimed: None, position: None, position_committed: true });
        Ok(())
    }

    pub fn capture_range(&mut self, irp: u64, mount: u64, file: u64,
        geometry: FatPathGeometry, first_cluster: u32, offset: u32, expected: usize,
        position: Option<(u32, u64)>) -> Result<(), ReadError>
    {
        let cursor = FatRangeLookup::new(geometry, first_cluster, offset, expected)
            .map_err(|_| ReadError::Invalid)?;
        self.reserve(irp, mount, file, expected)?;
        let entry = self.entry_mut(irp, mount, file)?;
        entry.cursor = Some(cursor);
        entry.position = position;
        entry.position_committed = position.is_none();
        Ok(())
    }

    pub fn claim_next(&mut self) -> Option<ReadSectorClaim> {
        let entry = self.entries.iter_mut().find(|entry| entry.cursor.is_some()
            && entry.claimed.is_none() && entry.terminal.is_none())?;
        let request = entry.cursor.as_ref()?.request()?;
        entry.claimed = Some(request);
        Some(ReadSectorClaim { irp: entry.irp, mount: entry.mount, file: entry.file, request })
    }

    pub fn release_unentered(&mut self, claim: ReadSectorClaim) -> Result<(), ReadError> {
        let entry = self.entry_mut(claim.irp, claim.mount, claim.file)?;
        if entry.claimed != Some(claim.request) { return Err(ReadError::WrongClaim); }
        entry.claimed = None;
        Ok(())
    }

    pub fn complete_sector(&mut self, claim: ReadSectorClaim,
        sector: Result<&[u8; 512], FatPathError>) -> Result<FatRangeProgress, ReadError>
    {
        let entry = self.entry_mut(claim.irp, claim.mount, claim.file)?;
        if entry.claimed != Some(claim.request) || entry.terminal.is_some() {
            return Err(ReadError::WrongClaim);
        }
        let result = match sector {
            Ok(bytes) => entry.cursor.as_mut().ok_or(ReadError::WrongClaim)?
                .feed(claim.request, bytes, &mut entry.output),
            Err(error) => Err(error),
        };
        entry.claimed = None;
        match result {
            Ok(FatRangeProgress::Complete) => {
                entry.terminal = Some((0, entry.expected));
                Ok(FatRangeProgress::Complete)
            }
            Ok(FatRangeProgress::Pending) => Ok(FatRangeProgress::Pending),
            Err(_) => {
                entry.terminal = Some((nt_fs::STATUS_DATA_ERROR as i32, 0));
                entry.position_committed = true;
                Ok(FatRangeProgress::Complete)
            }
        }
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
    fn native_sector_claim_is_exact_and_completed_read_waits_for_position_commit() {
        let geometry = FatPathGeometry { fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 2 };
        let mut reads = ReadCompletions::new();
        reads.capture_range(11, 7, 9, geometry, 2, 510, 4, Some((5, 514))).unwrap();
        let first = reads.claim_next().unwrap();
        assert_eq!(first.request.sector, 10);
        assert!(reads.claim_next().is_none());
        assert_eq!(reads.complete_sector(ReadSectorClaim { mount: 8, ..first }, Ok(&[0; 512])),
            Err(ReadError::WrongIdentity));
        let mut sector = [0; 512];
        sector[510..].copy_from_slice(&[1, 2]);
        assert_eq!(reads.complete_sector(first, Ok(&sector)), Ok(FatRangeProgress::Pending));
        let second = reads.claim_next().unwrap();
        assert_eq!(second.request.sector, 11);
        sector[..2].copy_from_slice(&[3, 4]);
        assert_eq!(reads.complete_sector(second, Ok(&sector)), Ok(FatRangeProgress::Complete));
        assert_eq!(reads.next_completion(), None);
        assert_eq!(reads.pending_position(), Some((11, 5, 514)));
        reads.mark_position_committed(11).unwrap();
        assert_eq!(reads.next_completion(), Some((11, 0, 4)));
        let mut output = [0; 4];
        assert_eq!(reads.copy(11, 0, &mut output), Ok(4));
        assert_eq!(output, [1, 2, 3, 4]);
        reads.ack(11).unwrap();
    }
}
