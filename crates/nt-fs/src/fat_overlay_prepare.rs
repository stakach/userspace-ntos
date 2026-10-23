//! Retained FAT inputs for a writable-overlay CREATE after target-name resolution.
//!
//! The caller owns each sector claim before entering native I/O. A claimed request remains
//! unavailable across a wait or uncertain provider result; only a refusal known to have had no
//! effect may release it. Prepared contents remain owned until the exact CREATE consumes them.

use alloc::vec::Vec;

use crate::{
    FatDirectoryRecord, FatPathError, FatPathGeometry, FatPathLookup, FatPathProgress,
    FatPathRequest, FatRangeLookup, FatRangeProgress, FatRangeRequest,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlayCopyPlan {
    None,
    MetadataOnly,
    Contents { first_cluster: u32, length: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlayPrepareError {
    Invalid,
    Duplicate,
    NoCapacity,
    WrongClaim,
    ParentMissing,
    ParentNotDirectory,
    Fat(FatPathError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlaySectorRequest {
    Parent(FatPathRequest),
    Contents(FatRangeRequest),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OverlaySectorClaim {
    pub irp: u64,
    pub mount: u64,
    pub generation: u64,
    pub request: OverlaySectorRequest,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlayPrepareProgress {
    Pending,
    Ready,
}

pub struct PreparedOverlay {
    /// The installed parent, if its path required lookup. The caller must use this exact record
    /// when materializing the parent, rather than looking up the path again.
    pub parent: Option<FatDirectoryRecord>,
    /// Complete installed file bytes for `Contents`; empty for `MetadataOnly`, `None`, or EOF 0.
    pub contents: Vec<u8>,
}

pub struct ResolvedOverlay<P> {
    pub irp: u64,
    pub mount: u64,
    pub payload: P,
    pub copy: OverlayCopyPlan,
    pub result: Result<PreparedOverlay, OverlayPrepareError>,
}

enum Phase {
    Parent(FatPathLookup),
    Contents(FatRangeLookup),
    Ready(Result<(), OverlayPrepareError>),
}

struct Entry<P> {
    irp: u64,
    mount: u64,
    payload: P,
    copy: OverlayCopyPlan,
    parent: Option<FatDirectoryRecord>,
    contents: Vec<u8>,
    next_contents: Option<FatRangeLookup>,
    phase: Phase,
    claimed: Option<OverlaySectorClaim>,
}

impl<P> Entry<P> {
    fn request(&self) -> Option<OverlaySectorRequest> {
        match &self.phase {
            Phase::Parent(cursor) => cursor.request().map(OverlaySectorRequest::Parent),
            Phase::Contents(cursor) => cursor.request().map(OverlaySectorRequest::Contents),
            Phase::Ready(_) => None,
        }
    }
}

pub struct OverlayPreparations<P> {
    entries: Vec<Entry<P>>,
    next_generation: u64,
}

impl<P> OverlayPreparations<P> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next_generation: 0,
        }
    }

    pub fn has_outstanding(&self) -> bool {
        !self.entries.is_empty()
    }

    pub fn has_claimable_sector(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.claimed.is_none() && entry.request().is_some())
    }

    pub fn has_ready(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| matches!(entry.phase, Phase::Ready(_)))
    }

    /// Capture all output storage and both FAT cursors before the first native effect.
    /// `parent_path` is the installed parent relative to `root_cluster`; `None` means no
    /// installed-parent materialization is needed. Zero-length files need no FAT data sectors.
    pub fn capture(
        &mut self,
        irp: u64,
        mount: u64,
        payload: P,
        geometry: FatPathGeometry,
        root_cluster: u32,
        parent_path: Option<&[u8]>,
        copy: OverlayCopyPlan,
    ) -> Result<(), OverlayPrepareError> {
        self.capture_owned(irp, mount, payload, geometry, root_cluster, parent_path, copy)
            .map_err(|(error, _payload)| error)
    }

    /// Return the captured owner on admission failure so the caller can complete or retry its
    /// exact IRP without losing the CREATE parameters.
    pub fn capture_owned(
        &mut self,
        irp: u64,
        mount: u64,
        payload: P,
        geometry: FatPathGeometry,
        root_cluster: u32,
        parent_path: Option<&[u8]>,
        copy: OverlayCopyPlan,
    ) -> Result<(), (OverlayPrepareError, P)> {
        let prepared = (|| -> Result<_, OverlayPrepareError> {
            if irp == 0 || mount == 0 || parent_path.is_some_and(|path| path.is_empty()) {
                return Err(OverlayPrepareError::Invalid);
            }
            if self.entries.iter().any(|entry| entry.irp == irp) {
                return Err(OverlayPrepareError::Duplicate);
            }
            let parent = parent_path
                .map(|path| FatPathLookup::new(geometry, root_cluster, path))
                .transpose()
                .map_err(map_fat_error)?;
            let mut contents = Vec::new();
            let next_contents = match copy {
                OverlayCopyPlan::Contents { first_cluster, length } if length != 0 => {
                    contents.try_reserve_exact(length as usize)
                        .map_err(|_| OverlayPrepareError::NoCapacity)?;
                    contents.resize(length as usize, 0);
                    Some(FatRangeLookup::new(geometry, first_cluster, 0, length as usize)
                        .map_err(map_fat_error)?)
                }
                _ => None,
            };
            self.entries.try_reserve(1).map_err(|_| OverlayPrepareError::NoCapacity)?;
            let (phase, next_contents) = match (parent, next_contents) {
                (Some(parent), contents) => (Phase::Parent(parent), contents),
                (None, Some(contents)) => (Phase::Contents(contents), None),
                (None, None) => (Phase::Ready(Ok(())), None),
            };
            Ok((phase, next_contents, contents))
        })();
        let (phase, next_contents, contents) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => return Err((error, payload)),
        };
        self.entries.push(Entry {
            irp,
            mount,
            payload,
            copy,
            parent: None,
            contents,
            next_contents,
            phase,
            claimed: None,
        });
        Ok(())
    }

    /// Claim exactly one sector. A new generation distinguishes an old released claim from
    /// a later claim for the same FAT request.
    pub fn claim_next(&mut self) -> Option<OverlaySectorClaim> {
        let index = self
            .entries
            .iter()
            .position(|entry| entry.claimed.is_none() && entry.request().is_some())?;
        let generation = self.next_generation.checked_add(1)?;
        self.next_generation = generation;
        let entry = &mut self.entries[index];
        let claim = OverlaySectorClaim {
            irp: entry.irp,
            mount: entry.mount,
            generation,
            request: entry.request()?,
        };
        entry.claimed = Some(claim);
        Some(claim)
    }

    /// Only call this when the provider proves the command never entered native I/O.
    pub fn release_unentered(
        &mut self,
        claim: OverlaySectorClaim,
    ) -> Result<(), OverlayPrepareError> {
        let entry = self.exact_claim_mut(claim)?;
        entry.claimed = None;
        Ok(())
    }

    pub fn complete_sector(
        &mut self,
        claim: OverlaySectorClaim,
        sector: Result<&[u8; 512], FatPathError>,
    ) -> Result<OverlayPrepareProgress, OverlayPrepareError> {
        let entry = self.exact_claim_mut(claim)?;
        let mut next = None;
        match (&mut entry.phase, claim.request) {
            (Phase::Parent(cursor), OverlaySectorRequest::Parent(request)) => {
                let progress = sector.and_then(|bytes| cursor.feed(request, bytes));
                match progress {
                    Ok(FatPathProgress::Pending) => {}
                    Ok(FatPathProgress::Found) => match cursor.take_found() {
                        Some(record) if record.metadata().is_directory => {
                            entry.parent = Some(record);
                            next = Some(
                                entry
                                    .next_contents
                                    .take()
                                    .map(Phase::Contents)
                                    .unwrap_or(Phase::Ready(Ok(()))),
                            );
                        }
                        Some(_) => {
                            next = Some(Phase::Ready(Err(OverlayPrepareError::ParentNotDirectory)))
                        }
                        None => next = Some(Phase::Ready(Err(OverlayPrepareError::ParentMissing))),
                    },
                    Ok(FatPathProgress::NotFound) => {
                        next = Some(Phase::Ready(Err(OverlayPrepareError::ParentMissing)))
                    }
                    Err(error) => next = Some(Phase::Ready(Err(map_fat_error(error)))),
                }
            }
            (Phase::Contents(cursor), OverlaySectorRequest::Contents(request)) => {
                let progress =
                    sector.and_then(|bytes| cursor.feed(request, bytes, &mut entry.contents));
                match progress {
                    Ok(FatRangeProgress::Pending) => {}
                    Ok(FatRangeProgress::Complete) => next = Some(Phase::Ready(Ok(()))),
                    Err(error) => next = Some(Phase::Ready(Err(map_fat_error(error)))),
                }
            }
            _ => return Err(OverlayPrepareError::WrongClaim),
        }
        entry.claimed = None;
        if let Some(next) = next {
            entry.phase = next;
        }
        Ok(if matches!(entry.phase, Phase::Ready(_)) {
            OverlayPrepareProgress::Ready
        } else {
            OverlayPrepareProgress::Pending
        })
    }

    pub fn take_ready_for(&mut self, irp: u64, mount: u64) -> Option<ResolvedOverlay<P>> {
        let index = self.entries.iter().position(|entry| {
            entry.irp == irp && entry.mount == mount && matches!(entry.phase, Phase::Ready(_))
        })?;
        let entry = self.entries.swap_remove(index);
        let Phase::Ready(result) = entry.phase else {
            unreachable!()
        };
        Some(ResolvedOverlay {
            irp,
            mount,
            payload: entry.payload,
            copy: entry.copy,
            result: result.map(|()| PreparedOverlay {
                parent: entry.parent,
                contents: entry.contents,
            }),
        })
    }

    pub fn take_next_ready(&mut self) -> Option<ResolvedOverlay<P>> {
        let (irp, mount) = self.entries.iter()
            .find(|entry| matches!(entry.phase, Phase::Ready(_)))
            .map(|entry| (entry.irp, entry.mount))?;
        self.take_ready_for(irp, mount)
    }

    /// A resident dependency was unavailable before materialization or import began.
    pub fn restore_ready(&mut self, resolved: ResolvedOverlay<P>) -> Result<(), OverlayPrepareError> {
        if self.entries.iter().any(|entry| entry.irp == resolved.irp) {
            return Err(OverlayPrepareError::Duplicate);
        }
        // `take_ready_for` only removes an entry; its existing Vec capacity is retained.
        let (parent, contents, phase) = match resolved.result {
            Ok(prepared) => (prepared.parent, prepared.contents, Phase::Ready(Ok(()))),
            Err(error) => (None, Vec::new(), Phase::Ready(Err(error))),
        };
        self.entries.push(Entry {
            irp: resolved.irp, mount: resolved.mount, payload: resolved.payload,
            copy: resolved.copy, parent, contents, next_contents: None,
            phase, claimed: None,
        });
        Ok(())
    }

    fn exact_claim_mut(
        &mut self,
        claim: OverlaySectorClaim,
    ) -> Result<&mut Entry<P>, OverlayPrepareError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|entry| entry.irp == claim.irp && entry.mount == claim.mount)
            .ok_or(OverlayPrepareError::WrongClaim)?;
        if entry.claimed != Some(claim) {
            return Err(OverlayPrepareError::WrongClaim);
        }
        Ok(entry)
    }
}

fn map_fat_error(error: FatPathError) -> OverlayPrepareError {
    match error {
        FatPathError::NoCapacity => OverlayPrepareError::NoCapacity,
        _ => OverlayPrepareError::Fat(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geometry() -> FatPathGeometry {
        FatPathGeometry {
            fat_start_sector: 1,
            data_start_sector: 10,
            total_sectors: 1000,
            sectors_per_cluster: 2,
        }
    }

    fn parent_sector(directory: bool) -> [u8; 512] {
        let mut sector = [0; 512];
        sector[..11].copy_from_slice(b"WINDOWS    ");
        sector[11] = if directory { 0x10 } else { 0x20 };
        sector[26..28].copy_from_slice(&3u16.to_le_bytes());
        sector
    }

    #[test]
    fn retained_copy_contents_rejects_wrong_and_stale_claims() {
        let mut queue = OverlayPreparations::new();
        queue
            .capture(
                11,
                7,
                99,
                geometry(),
                2,
                None,
                OverlayCopyPlan::Contents {
                    first_cluster: 2,
                    length: 514,
                },
            )
            .unwrap();
        let first = queue.claim_next().unwrap();
        assert_eq!(
            first.request,
            OverlaySectorRequest::Contents(FatRangeRequest {
                sector: 10,
                kind: crate::FatRangeRequestKind::Data
            })
        );
        assert!(queue.claim_next().is_none());
        assert_eq!(
            queue.complete_sector(OverlaySectorClaim { mount: 8, ..first }, Ok(&[0; 512])),
            Err(OverlayPrepareError::WrongClaim)
        );
        queue.release_unentered(first).unwrap();
        let replacement = queue.claim_next().unwrap();
        assert_ne!(first.generation, replacement.generation);
        assert_eq!(
            queue.complete_sector(first, Ok(&[0; 512])),
            Err(OverlayPrepareError::WrongClaim)
        );
        let first_bytes = [3; 512];
        assert_eq!(
            queue.complete_sector(replacement, Ok(&first_bytes)),
            Ok(OverlayPrepareProgress::Pending)
        );
        let second = queue.claim_next().unwrap();
        let last_bytes = [4; 512];
        assert_eq!(
            queue.complete_sector(second, Ok(&last_bytes)),
            Ok(OverlayPrepareProgress::Ready)
        );
        let resolved = queue.take_ready_for(11, 7).unwrap();
        assert_eq!(resolved.payload, 99);
        let data = resolved.result.unwrap().contents;
        assert_eq!(data.len(), 514);
        assert_eq!(&data[..512], &[3; 512]);
        assert_eq!(&data[512..], &[4; 2]);
        assert!(!queue.has_outstanding());
    }

    #[test]
    fn metadata_only_and_empty_contents_issue_no_sector_requests() {
        let mut queue = OverlayPreparations::new();
        queue
            .capture(1, 7, 10, geometry(), 2, None, OverlayCopyPlan::MetadataOnly)
            .unwrap();
        queue
            .capture(
                2,
                7,
                20,
                geometry(),
                2,
                None,
                OverlayCopyPlan::Contents {
                    first_cluster: 0,
                    length: 0,
                },
            )
            .unwrap();
        assert!(!queue.has_claimable_sector());
        assert!(queue.claim_next().is_none());
        assert!(queue.take_ready_for(1, 8).is_none());
        assert!(queue
            .take_ready_for(1, 7)
            .unwrap()
            .result
            .unwrap()
            .contents
            .is_empty());
        assert!(queue
            .take_ready_for(2, 7)
            .unwrap()
            .result
            .unwrap()
            .contents
            .is_empty());
    }

    #[test]
    fn missing_parent_terminates_without_copying_contents() {
        let mut queue = OverlayPreparations::new();
        queue
            .capture(
                1,
                7,
                10,
                geometry(),
                2,
                Some(b"missing"),
                OverlayCopyPlan::Contents {
                    first_cluster: 3,
                    length: 20,
                },
            )
            .unwrap();
        let claim = queue.claim_next().unwrap();
        assert!(matches!(claim.request, OverlaySectorRequest::Parent(_)));
        assert_eq!(
            queue.complete_sector(claim, Ok(&[0; 512])),
            Ok(OverlayPrepareProgress::Ready)
        );
        assert!(queue.claim_next().is_none());
        assert!(matches!(
            queue.take_ready_for(1, 7).unwrap().result,
            Err(OverlayPrepareError::ParentMissing)
        ));
    }

    #[test]
    fn parent_lookup_finishes_before_installed_content_read() {
        let mut queue = OverlayPreparations::new();
        queue
            .capture(
                4,
                7,
                40,
                geometry(),
                2,
                Some(b"windows"),
                OverlayCopyPlan::Contents {
                    first_cluster: 3,
                    length: 2,
                },
            )
            .unwrap();
        let parent = queue.claim_next().unwrap();
        assert!(matches!(parent.request, OverlaySectorRequest::Parent(_)));
        assert_eq!(
            queue.complete_sector(parent, Ok(&parent_sector(true))),
            Ok(OverlayPrepareProgress::Pending)
        );
        let content = queue.claim_next().unwrap();
        assert!(matches!(content.request, OverlaySectorRequest::Contents(_)));
        let sector = [8; 512];
        assert_eq!(
            queue.complete_sector(content, Ok(&sector)),
            Ok(OverlayPrepareProgress::Ready)
        );
        let prepared = queue.take_ready_for(4, 7).unwrap().result.unwrap();
        assert_eq!(prepared.parent.unwrap().first_cluster, 3);
        assert_eq!(prepared.contents, [8, 8]);
    }

    #[test]
    fn nondirectory_parent_blocks_copy_up_content_io() {
        let mut queue = OverlayPreparations::new();
        queue
            .capture(
                5,
                7,
                50,
                geometry(),
                2,
                Some(b"windows"),
                OverlayCopyPlan::Contents {
                    first_cluster: 3,
                    length: 2,
                },
            )
            .unwrap();
        let claim = queue.claim_next().unwrap();
        assert_eq!(
            queue.complete_sector(claim, Ok(&parent_sector(false))),
            Ok(OverlayPrepareProgress::Ready)
        );
        assert!(queue.claim_next().is_none());
        assert!(matches!(
            queue.take_ready_for(5, 7).unwrap().result,
            Err(OverlayPrepareError::ParentNotDirectory)
        ));
    }

    #[test]
    fn native_error_retains_terminal_owner_until_exact_consumer_takes_it() {
        let mut queue = OverlayPreparations::new();
        queue
            .capture(
                3,
                7,
                30,
                geometry(),
                2,
                None,
                OverlayCopyPlan::Contents {
                    first_cluster: 2,
                    length: 1,
                },
            )
            .unwrap();
        let claim = queue.claim_next().unwrap();
        assert_eq!(
            queue.complete_sector(claim, Err(FatPathError::Corrupt)),
            Ok(OverlayPrepareProgress::Ready)
        );
        assert!(!queue.has_claimable_sector());
        assert!(queue.take_ready_for(3, 8).is_none());
        assert!(matches!(
            queue.take_ready_for(3, 7).unwrap().result,
            Err(OverlayPrepareError::Fat(FatPathError::Corrupt))
        ));
    }
}
