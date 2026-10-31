//! Retained mounted directory snapshot lookup; native entry and completion live outside dispatch.

use alloc::vec::Vec;
use nt_fs::{DirectoryEntry, FatDirectoryLookup, FatDirectoryProgress, FatPathError, FatPathRequest};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DirectoryLookupError { Invalid, Duplicate, NoCapacity, WrongClaim }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DirectorySectorClaim {
    pub irp: u64,
    pub mount: u64,
    pub request: FatPathRequest,
}

pub(crate) struct ResolvedDirectory<P> {
    pub irp: u64,
    pub mount: u64,
    pub payload: P,
    pub result: Result<Vec<DirectoryEntry>, FatPathError>,
    lookup: FatDirectoryLookup,
}

struct Entry<P> {
    irp: u64,
    mount: u64,
    payload: Option<P>,
    lookup: FatDirectoryLookup,
    claimed: Option<FatPathRequest>,
    result: Option<Result<Vec<DirectoryEntry>, FatPathError>>,
}

pub(crate) struct DirectoryLookupQueue<P> { entries: Vec<Entry<P>> }

impl<P> DirectoryLookupQueue<P> {
    pub const fn new() -> Self { Self { entries: Vec::new() } }

    pub fn capture(&mut self, irp: u64, mount: u64, payload: P,
        lookup: FatDirectoryLookup) -> Result<(), DirectoryLookupError>
    {
        if irp == 0 || mount == 0 || lookup.request().is_none() {
            return Err(DirectoryLookupError::Invalid);
        }
        if self.entries.iter().any(|entry| entry.irp == irp) {
            return Err(DirectoryLookupError::Duplicate);
        }
        self.entries.try_reserve(1).map_err(|_| DirectoryLookupError::NoCapacity)?;
        self.entries.push(Entry { irp, mount, payload: Some(payload), lookup,
            claimed: None, result: None });
        Ok(())
    }

    pub fn claim_next(&mut self) -> Option<DirectorySectorClaim> {
        // Directory cursor mutation follows dispatch order, including two IRPs on one File.
        let entry = self.entries.first_mut()
            .filter(|entry| entry.claimed.is_none() && entry.result.is_none())?;
        let request = entry.lookup.request()?;
        entry.claimed = Some(request);
        Some(DirectorySectorClaim { irp: entry.irp, mount: entry.mount, request })
    }

    pub fn release_unentered(&mut self, claim: DirectorySectorClaim)
        -> Result<(), DirectoryLookupError>
    {
        let entry = self.entries.iter_mut().find(|entry| entry.irp == claim.irp
            && entry.mount == claim.mount).ok_or(DirectoryLookupError::WrongClaim)?;
        if entry.claimed != Some(claim.request) { return Err(DirectoryLookupError::WrongClaim); }
        entry.claimed = None;
        Ok(())
    }

    pub fn complete(&mut self, claim: DirectorySectorClaim,
        sector: Result<&[u8; 512], FatPathError>)
        -> Result<FatDirectoryProgress, DirectoryLookupError>
    {
        let entry = self.entries.iter_mut().find(|entry| entry.irp == claim.irp
            && entry.mount == claim.mount).ok_or(DirectoryLookupError::WrongClaim)?;
        if entry.claimed != Some(claim.request) || entry.result.is_some() {
            return Err(DirectoryLookupError::WrongClaim);
        }
        let result = match sector {
            Ok(bytes) => entry.lookup.feed(claim.request, bytes),
            Err(error) => Err(error),
        };
        entry.claimed = None;
        match result {
            Ok(FatDirectoryProgress::Pending) => Ok(FatDirectoryProgress::Pending),
            Ok(FatDirectoryProgress::Complete) => {
                entry.result = Some(Ok(entry.lookup.take_entries()
                    .expect("completed directory cursor owns entries")));
                Ok(FatDirectoryProgress::Complete)
            }
            Err(error) => {
                entry.result = Some(Err(error));
                Ok(FatDirectoryProgress::Complete)
            }
        }
    }

    pub fn take_resolved(&mut self) -> Option<ResolvedDirectory<P>> {
        if !self.entries.first().is_some_and(|entry| entry.result.is_some()) { return None; }
        let mut entry = self.entries.remove(0);
        Some(ResolvedDirectory { irp: entry.irp, mount: entry.mount,
            payload: entry.payload.take()?, result: entry.result.take()?, lookup: entry.lookup })
    }

    pub fn restore_resolved(&mut self, resolved: ResolvedDirectory<P>)
        -> Result<(), DirectoryLookupError>
    {
        if self.entries.iter().any(|entry| entry.irp == resolved.irp) {
            return Err(DirectoryLookupError::Duplicate);
        }
        self.entries.try_reserve(1).map_err(|_| DirectoryLookupError::NoCapacity)?;
        self.entries.insert(0, Entry { irp: resolved.irp, mount: resolved.mount,
            payload: Some(resolved.payload), lookup: resolved.lookup,
            claimed: None, result: Some(resolved.result) });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nt_fs::FatPathGeometry;

    #[test]
    fn exact_directory_claim_and_busy_restore_do_not_reissue() {
        let geometry = FatPathGeometry { fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 1 };
        let mut queue = DirectoryLookupQueue::new();
        queue.capture(9, 7, 42, FatDirectoryLookup::new(geometry, 2).unwrap()).unwrap();
        let claim = queue.claim_next().unwrap();
        assert_eq!(claim.request.sector, 10);
        assert!(queue.claim_next().is_none());
        assert_eq!(queue.complete(DirectorySectorClaim { mount: 8, ..claim }, Ok(&[0; 512])),
            Err(DirectoryLookupError::WrongClaim));
        assert_eq!(queue.complete(claim, Ok(&[0; 512])), Ok(FatDirectoryProgress::Complete));
        let resolved = queue.take_resolved().unwrap();
        assert_eq!(resolved.payload, 42);
        queue.restore_resolved(resolved).unwrap();
        assert!(queue.claim_next().is_none());
        assert_eq!(queue.take_resolved().unwrap().result.unwrap().len(), 0);
    }
}
