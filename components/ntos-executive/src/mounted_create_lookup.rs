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
    pub attribution: CreateLookupAttribution,
    lookup: Option<FatPathLookup>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CreateLookupAttribution {
    pub copied_cache_completions: u64,
    pub physical_settlements: u64,
}

#[derive(Clone, Copy)]
enum CompletionSource { Cached, Physical, Unattributed }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CreateLookupFound {
    Path(Option<FatDirectoryRecord>),
    Root,
    DeferredBoot,
}

struct Entry<P> {
    irp: u64,
    mount: u64,
    payload: Option<P>,
    lookup: Option<FatPathLookup>,
    claimed: Option<FatPathRequest>,
    result: Option<Result<CreateLookupFound, FatPathError>>,
    attribution: CreateLookupAttribution,
}

pub(crate) struct CreateLookupQueue<P> {
    entries: Vec<Entry<P>>,
}

impl<P> CreateLookupQueue<P> {
    pub const fn new() -> Self { Self { entries: Vec::new() } }

    /// Includes a sector claim, a completed lookup awaiting publication, and a deferred Boot
    /// CREATE. All retain a File IRP that can still wake its caller.
    pub fn has_outstanding(&self) -> bool { !self.entries.is_empty() }

    pub fn has_claimable_sector(&self) -> bool {
        self.entries.iter().find(|entry| entry.claimed.is_none() && entry.result.is_none())
            .is_some_and(|entry| entry.lookup.as_ref().is_some_and(|lookup| lookup.request().is_some()))
    }

    /// Read-only census of the oldest retained CREATE. A resolved or deferred entry has no
    /// claimable sector, even though it still owns a File IRP and can wake its caller.
    pub fn first_state(&self) -> Option<(u64, u64, &'static [u8])> {
        let entry = self.entries.first()?;
        let phase = if entry.claimed.is_some() {
            b"sector-entered".as_slice()
        } else if matches!(&entry.result, Some(Ok(CreateLookupFound::DeferredBoot))) {
            b"deferred-boot".as_slice()
        } else if entry.result.is_some() {
            b"resolved".as_slice()
        } else {
            b"sector-ready".as_slice()
        };
        Some((entry.irp, entry.mount, phase))
    }

    pub fn capture(&mut self, irp: u64, mount: u64, payload: P, lookup: FatPathLookup) -> Result<(), CreateLookupError> {
        if irp == 0 || mount == 0 || lookup.request().is_none() {
            return Err(CreateLookupError::Invalid);
        }
        if self.entries.iter().any(|entry| entry.irp == irp) {
            return Err(CreateLookupError::Duplicate);
        }
        self.entries.try_reserve(1).map_err(|_| CreateLookupError::NoCapacity)?;
        self.entries.push(Entry { irp, mount, payload: Some(payload), lookup: Some(lookup), claimed: None,
            result: None, attribution: CreateLookupAttribution::default() });
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
            claimed: None, result: Some(Ok(CreateLookupFound::Root)),
            attribution: CreateLookupAttribution::default() });
        Ok(())
    }

    /// A boot-route CREATE waits for exclusive journal ownership to return before it inspects
    /// either the installed FAT tree or the overlay. No sector may be claimed in this state.
    pub fn capture_deferred_boot(&mut self, irp: u64, mount: u64, payload: P)
        -> Result<(), CreateLookupError>
    {
        if irp == 0 || mount == 0 { return Err(CreateLookupError::Invalid); }
        if self.entries.iter().any(|entry| entry.irp == irp) {
            return Err(CreateLookupError::Duplicate);
        }
        self.entries.try_reserve(1).map_err(|_| CreateLookupError::NoCapacity)?;
        self.entries.push(Entry { irp, mount, payload: Some(payload), lookup: None,
            claimed: None, result: Some(Ok(CreateLookupFound::DeferredBoot)),
            attribution: CreateLookupAttribution::default() });
        Ok(())
    }

    /// The physical route changed while a boot CREATE waited for the journal. Convert the
    /// retained owner to a native sector lookup without allocating or changing its identity.
    pub fn activate_deferred_boot(&mut self, irp: u64, mount: u64, lookup: FatPathLookup)
        -> Result<(), CreateLookupError>
    {
        let entry = self.entries.iter_mut().find(|entry| entry.irp == irp && entry.mount == mount)
            .ok_or(CreateLookupError::WrongClaim)?;
        if entry.result != Some(Ok(CreateLookupFound::DeferredBoot)) || entry.claimed.is_some() {
            return Err(CreateLookupError::WrongClaim);
        }
        entry.lookup = Some(lookup);
        entry.result = None;
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

    /// Preserve the existing unattributed completion path, including an unentered refusal.
    /// A failure keeps the owner for terminal CREATE completion; no command is replayed.
    pub fn complete(&mut self, claim: CreateSectorClaim, sector: Result<&[u8; 512], FatPathError>)
        -> Result<FatPathProgress, CreateLookupError>
    {
        self.complete_attributed(claim, sector, CompletionSource::Unattributed)
    }

    /// The native block owner calls this only after the command has reached an exact
    /// terminal and a pending command has passed strict provider ACK.
    pub fn complete_physical(&mut self, claim: CreateSectorClaim,
        sector: Result<&[u8; 512], FatPathError>) -> Result<FatPathProgress, CreateLookupError>
    {
        self.complete_attributed(claim, sector, CompletionSource::Physical)
    }

    /// A copied sector has no provider command or terminal; count it only after the exact
    /// logical claim has been accepted. Physical completions use `complete_physical`.
    pub fn complete_cached(&mut self, claim: CreateSectorClaim,
        sector: Result<&[u8; 512], FatPathError>) -> Result<FatPathProgress, CreateLookupError>
    {
        self.complete_attributed(claim, sector, CompletionSource::Cached)
    }

    fn complete_attributed(&mut self, claim: CreateSectorClaim,
        sector: Result<&[u8; 512], FatPathError>, source: CompletionSource)
        -> Result<FatPathProgress, CreateLookupError>
    {
        let entry = self.entries.iter_mut().find(|entry| entry.irp == claim.irp && entry.mount == claim.mount)
            .ok_or(CreateLookupError::WrongClaim)?;
        if entry.claimed != Some(claim.request) || entry.result.is_some() {
            return Err(CreateLookupError::WrongClaim);
        }
        match source {
            CompletionSource::Cached if sector.is_ok() => {
                entry.attribution.copied_cache_completions =
                    entry.attribution.copied_cache_completions.saturating_add(1);
            }
            CompletionSource::Physical => {
                entry.attribution.physical_settlements =
                    entry.attribution.physical_settlements.saturating_add(1);
            }
            CompletionSource::Cached | CompletionSource::Unattributed => {}
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
            attribution: entry.attribution,
            lookup: entry.lookup,
        })
    }

    pub fn attribution(&self, irp: u64, mount: u64) -> Option<CreateLookupAttribution> {
        self.entries.iter().find(|entry| entry.irp == irp && entry.mount == mount)
            .map(|entry| entry.attribution)
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
            attribution: resolved.attribution,
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

    #[test]
    fn deferred_boot_create_never_claims_a_sector_before_route_activation() {
        let mut queue = CreateLookupQueue::new();
        queue.capture_deferred_boot(21, 7, b"msgina.dll".to_vec()).unwrap();
        assert!(!queue.has_claimable_sector());
        assert!(queue.claim_next().is_none());
        let resolved = queue.take_resolved().unwrap();
        assert_eq!(resolved.result, Ok(CreateLookupFound::DeferredBoot));
        assert_eq!(resolved.payload, b"msgina.dll");
        queue.restore_resolved(resolved).unwrap();
        assert!(queue.claim_next().is_none());
        assert_eq!(queue.activate_deferred_boot(21, 8, lookup()), Err(CreateLookupError::WrongClaim));
        queue.activate_deferred_boot(21, 7, lookup()).unwrap();
        assert!(queue.has_claimable_sector());
        let claim = queue.claim_next().unwrap();
        assert!(!queue.has_claimable_sector());
        assert_eq!((claim.irp, claim.mount), (21, 7));
        assert!(queue.claim_next().is_none());
    }

    #[test]
    fn exact_create_attributes_acknowledged_cache_and_physical_sectors() {
        let mut queue = CreateLookupQueue::new();
        queue.capture(31, 7, (), lookup()).unwrap();
        let first = queue.claim_next().unwrap();
        assert_eq!(queue.complete_cached(CreateSectorClaim { irp: 32, ..first }, Ok(&[0; 512])),
            Err(CreateLookupError::WrongClaim));
        assert_eq!(queue.attribution(31, 7), Some(CreateLookupAttribution::default()));
        queue.release_unentered(first).unwrap();
        assert_eq!(queue.attribution(31, 7), Some(CreateLookupAttribution::default()));
        let first = queue.claim_next().unwrap();
        let mut root = [0u8; 512];
        root[..11].copy_from_slice(b"WINDOWS    ");
        root[11] = 0x10;
        root[26..28].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(queue.complete_cached(first, Ok(&root)), Ok(FatPathProgress::Pending));
        assert_eq!(queue.attribution(31, 7), Some(CreateLookupAttribution {
            copied_cache_completions: 1, physical_settlements: 0,
        }));
        let second = queue.claim_next().unwrap();
        assert_eq!(second.request.sector, 11);
        assert_eq!(queue.complete_physical(CreateSectorClaim { mount: 8, ..second }, Ok(&[0; 512])),
            Err(CreateLookupError::WrongClaim));
        assert_eq!(queue.complete_physical(second, Ok(&[0; 512])), Ok(FatPathProgress::NotFound));
        let resolved = queue.take_resolved().unwrap();
        assert_eq!(resolved.attribution,
            CreateLookupAttribution { copied_cache_completions: 1, physical_settlements: 1 });
        queue.restore_resolved(resolved).unwrap();
        assert_eq!(queue.take_resolved().unwrap().attribution,
            CreateLookupAttribution { copied_cache_completions: 1, physical_settlements: 1 },
            "resident retry cannot reattribute a settled physical command");
    }

    #[test]
    fn unentered_refusal_is_not_attributed_to_a_physical_settlement() {
        let mut queue = CreateLookupQueue::new();
        queue.capture(32, 7, (), lookup()).unwrap();
        let refused = queue.claim_next().unwrap();
        assert_eq!(queue.complete(refused, Err(FatPathError::Corrupt)),
            Err(CreateLookupError::Invalid));
        assert_eq!(queue.take_resolved().unwrap().attribution,
            CreateLookupAttribution::default());
    }
}
