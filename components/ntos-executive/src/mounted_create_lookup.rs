//! Pending mounted CREATE metadata lookup. No native I/O or completion pump runs here.

use alloc::vec::Vec;

use nt_fs::{FatDirectoryRecord, FatPathError, FatPathLookup, FatPathProgress, FatPathRequest};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CreateLookupError { Invalid, Duplicate, NoCapacity, WrongClaim }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CreateSectorClaim {
    pub irp: u64,
    pub mount: u64,
    pub request: FatPathRequest,
}

pub(crate) struct ResolvedCreate<P> {
    pub irp: u64,
    pub mount: u64,
    pub payload: P,
    pub result: Result<CreateLookupFound, FatPathError>,
    lookup: Option<FatPathLookup>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CreateLookupFound {
    Path(Option<FatDirectoryRecord>),
    Root,
}

struct Entry<P> {
    irp: u64,
    mount: u64,
    payload: Option<P>,
    lookup: Option<FatPathLookup>,
    claimed: Option<FatPathRequest>,
    result: Option<Result<CreateLookupFound, FatPathError>>,
}

pub(crate) struct CreateLookupQueue<P> {
    entries: Vec<Entry<P>>,
}

impl<P> CreateLookupQueue<P> {
    pub const fn new() -> Self { Self { entries: Vec::new() } }

    pub fn capture(&mut self, irp: u64, mount: u64, payload: P, lookup: FatPathLookup) -> Result<(), CreateLookupError> {
        if irp == 0 || mount == 0 || lookup.request().is_none() {
            return Err(CreateLookupError::Invalid);
        }
        if self.entries.iter().any(|entry| entry.irp == irp) {
            return Err(CreateLookupError::Duplicate);
        }
        self.entries.try_reserve(1).map_err(|_| CreateLookupError::NoCapacity)?;
        self.entries.push(Entry { irp, mount, payload: Some(payload), lookup: Some(lookup), claimed: None, result: None });
        Ok(())
    }

    pub fn capture_resolved_root(&mut self, irp: u64, mount: u64, payload: P)
        -> Result<(), CreateLookupError>
    {
        if irp == 0 || mount == 0 { return Err(CreateLookupError::Invalid); }
        if self.entries.iter().any(|entry| entry.irp == irp) {
            return Err(CreateLookupError::Duplicate);
        }
        self.entries.try_reserve(1).map_err(|_| CreateLookupError::NoCapacity)?;
        self.entries.push(Entry { irp, mount, payload: Some(payload), lookup: None,
            claimed: None, result: Some(Ok(CreateLookupFound::Root)) });
        Ok(())
    }

    /// Claim one exact request before dispatch. An uncertain native effect retains this claim.
    pub fn claim_next(&mut self) -> Option<CreateSectorClaim> {
        let entry = self.entries.iter_mut().find(|entry| entry.claimed.is_none() && entry.result.is_none())?;
        let request = entry.lookup.as_ref()?.request()?;
        entry.claimed = Some(request);
        Some(CreateSectorClaim { irp: entry.irp, mount: entry.mount, request })
    }

    /// Roll back only a provider refusal proven to have had no native effect.
    pub fn release_unentered(&mut self, claim: CreateSectorClaim) -> Result<(), CreateLookupError> {
        let entry = self.entries.iter_mut().find(|entry| entry.irp == claim.irp && entry.mount == claim.mount)
            .ok_or(CreateLookupError::WrongClaim)?;
        if entry.claimed != Some(claim.request) { return Err(CreateLookupError::WrongClaim); }
        entry.claimed = None;
        Ok(())
    }

    /// Feed only bytes from the exact completed native read. A failure keeps the owner for
    /// terminal CREATE completion; no ambiguous command is replayed through this method.
    pub fn complete(&mut self, claim: CreateSectorClaim, sector: Result<&[u8; 512], FatPathError>)
        -> Result<FatPathProgress, CreateLookupError>
    {
        let entry = self.entries.iter_mut().find(|entry| entry.irp == claim.irp && entry.mount == claim.mount)
            .ok_or(CreateLookupError::WrongClaim)?;
        if entry.claimed != Some(claim.request) || entry.result.is_some() {
            return Err(CreateLookupError::WrongClaim);
        }
        let result = match sector {
            Ok(bytes) => entry.lookup.as_mut().ok_or(CreateLookupError::WrongClaim)?
                .feed(claim.request, bytes),
            Err(error) => Err(error),
        };
        entry.claimed = None;
        match result {
            Ok(FatPathProgress::Pending) => Ok(FatPathProgress::Pending),
            Ok(FatPathProgress::Found) => {
                entry.result = Some(Ok(CreateLookupFound::Path(
                    entry.lookup.as_mut().and_then(FatPathLookup::take_found))));
                Ok(FatPathProgress::Found)
            }
            Ok(FatPathProgress::NotFound) => {
                entry.result = Some(Ok(CreateLookupFound::Path(None)));
                Ok(FatPathProgress::NotFound)
            }
            Err(error) => {
                entry.result = Some(Err(error));
                Err(CreateLookupError::Invalid)
            }
        }
    }

    pub fn take_resolved(&mut self) -> Option<ResolvedCreate<P>> {
        let index = self.entries.iter().position(|entry| entry.result.is_some())?;
        let mut entry = self.entries.swap_remove(index);
        Some(ResolvedCreate {
            irp: entry.irp,
            mount: entry.mount,
            payload: entry.payload.take()?,
            result: entry.result.take()?,
            lookup: entry.lookup,
        })
    }

    /// A resident dependency was busy before CREATE entered any native effect.
    pub fn restore_resolved(&mut self, resolved: ResolvedCreate<P>) -> Result<(), CreateLookupError> {
        if self.entries.iter().any(|entry| entry.irp == resolved.irp) {
            return Err(CreateLookupError::Duplicate);
        }
        self.entries.try_reserve(1).map_err(|_| CreateLookupError::NoCapacity)?;
        self.entries.push(Entry {
            irp: resolved.irp, mount: resolved.mount, payload: Some(resolved.payload),
            lookup: resolved.lookup, claimed: None, result: Some(resolved.result),
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nt_fs::FatPathGeometry;

    fn lookup() -> FatPathLookup {
        FatPathLookup::new(FatPathGeometry {
            fat_start_sector: 1, data_start_sector: 10,
            total_sectors: 1000, sectors_per_cluster: 1,
        }, 2, b"windows\\system32").unwrap()
    }

    #[test]
    fn exact_claim_is_not_reissued_and_wrong_completion_is_rejected() {
        let mut queue = CreateLookupQueue::new();
        queue.capture(7, 3, 41, lookup()).unwrap();
        let claim = queue.claim_next().unwrap();
        assert_eq!(claim.request.sector, 10);
        assert!(queue.claim_next().is_none());
        assert_eq!(queue.complete(CreateSectorClaim { mount: 4, ..claim }, Ok(&[0; 512])),
            Err(CreateLookupError::WrongClaim));
        assert!(queue.claim_next().is_none());
        assert_eq!(queue.complete(claim, Ok(&[0; 512])), Ok(FatPathProgress::NotFound));
        let resolved = queue.take_resolved().unwrap();
        assert_eq!((resolved.irp, resolved.mount, resolved.payload), (7, 3, 41));
        assert_eq!(resolved.result, Ok(CreateLookupFound::Path(None)));
    }

    #[test]
    fn busy_resident_dependency_restores_terminal_lookup_without_replay() {
        let mut queue = CreateLookupQueue::new();
        queue.capture(8, 3, 42, lookup()).unwrap();
        let claim = queue.claim_next().unwrap();
        queue.complete(claim, Ok(&[0; 512])).unwrap();
        let resolved = queue.take_resolved().unwrap();
        queue.restore_resolved(resolved).unwrap();
        assert!(queue.claim_next().is_none());
        assert_eq!(queue.take_resolved().unwrap().payload, 42);
    }

    #[test]
    fn resolved_root_retains_busy_retry_without_a_sector_claim() {
        let mut queue = CreateLookupQueue::new();
        queue.capture_resolved_root(12, 4, 81).unwrap();
        assert!(queue.claim_next().is_none());
        let resolved = queue.take_resolved().unwrap();
        assert_eq!(resolved.result, Ok(CreateLookupFound::Root));
        queue.restore_resolved(resolved).unwrap();
        assert!(queue.claim_next().is_none());
        assert_eq!(queue.take_resolved().unwrap().payload, 81);
    }
}
