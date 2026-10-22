//! Retained identity proof between native LUN discovery and durable PnP publication.
//!
//! The executive owns the actual IRPs, SRBs, MDLs, provider Reply caps, and mount lease. This
//! ledger records when each entered effect may be consumed; it never manufactures completion.

use crate::pci_dma_handoff::{ControllerState, PciController, PciDmaHandoff};
use alloc::vec::Vec;

/// Identity copied from the same retained BusRelations query that discovered the native LUN.
/// `generation` is the prepared relation generation, not an old published relation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageRelation {
    pub bus_device: u64,
    pub generation: u64,
    pub provider_domain: u64,
    pub provider_cookie: u64,
}

/// Canonical I/O Manager device and the exact hosted driver pointer that reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoragePdo {
    pub device: u64,
    pub raw_pointer: u64,
    pub provider_driver: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageHandoffKey {
    pub controller: PciController,
    pub dma_root: u64,
    pub mount: u64,
    pub relation: StorageRelation,
    pub pdo: StoragePdo,
}

/// Exact pre-drain observations of the mounted physical disk. The current FAT mount requires
/// 512-byte sectors; no partition or controller identity is inferred from a device name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpectedDisk {
    pub sector_count: u64,
    pub volume_lba: u64,
    pub sector_zero: [u8; 512],
    pub volume_sector: [u8; 512],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProofStep {
    Capacity,
    SectorZero,
    VolumeSector,
}

/// One entered native SRB. The caller must retain its buffers and completion owner until the
/// exact result is confirmed, or retain them in quarantine after uncertainty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SrbProofRequest {
    pub key: StorageHandoffKey,
    pub ticket: u64,
    pub step: ProofStep,
    pub lba: u64,
    pub bytes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MountCommit {
    pub key: StorageHandoffKey,
    pub ticket: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffPhase {
    NeedCapacity,
    NeedSectorZero,
    NeedVolumeSector,
    AwaitingSrb,
    Proven,
    MountCommitEntered,
    NativeMounted,
    RelationPublished,
    Refused,
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidIdentity,
    ControllerClaimed,
    InsufficientResources,
    WrongControllerPhase,
    WrongOwner,
    WrongPhase,
    WrongTicket,
    WrongProofKind,
    GeometryMismatch,
    SectorMismatch,
    Refused,
    Uncertain,
    IdExhausted,
}

/// One handoff claim per physical controller for this executive lifetime. It is never released:
/// dropping a request owner, including after an uncertain effect, cannot authorize a new one.
pub struct NativeStorageAdmissions {
    controllers: Vec<PciController>,
}

impl Default for NativeStorageAdmissions {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeStorageAdmissions {
    pub const fn new() -> Self {
        Self {
            controllers: Vec::new(),
        }
    }

    fn claim(&mut self, controller: PciController) -> Result<(), Error> {
        if self.controllers.iter().any(|existing| {
            existing.bus == controller.bus
                && existing.device == controller.device
                && existing.function == controller.function
        }) {
            return Err(Error::ControllerClaimed);
        }
        self.controllers
            .try_reserve(1)
            .map_err(|_| Error::InsufficientResources)?;
        self.controllers.push(controller);
        Ok(())
    }
}

/// A single-use, non-clonable handoff. Completion of a native request is separate from its
/// submission, and a lost result can never be replayed as a fresh request.
pub struct NativeStorageHandoff {
    key: StorageHandoffKey,
    expected: ExpectedDisk,
    phase: HandoffPhase,
    pending: Option<SrbProofRequest>,
    next_ticket: u64,
    mount_commit: Option<MountCommit>,
}

impl NativeStorageHandoff {
    pub fn new(
        admissions: &mut NativeStorageAdmissions,
        dma: &PciDmaHandoff,
        key: StorageHandoffKey,
        expected: ExpectedDisk,
    ) -> Result<Self, Error> {
        if key.dma_root == 0
            || key.mount == 0
            || key.relation.bus_device == 0
            || key.relation.generation == 0
            || key.relation.provider_domain == 0
            || key.relation.provider_cookie == 0
            || key.pdo.device == 0
            || key.pdo.raw_pointer == 0
            || key.pdo.provider_driver == 0
            || expected.sector_count == 0
            || expected.volume_lba == 0
            || expected.volume_lba >= expected.sector_count
        {
            return Err(Error::InvalidIdentity);
        }
        Self::check_dma_starting(dma, key)?;
        admissions.claim(key.controller)?;
        Ok(Self {
            key,
            expected,
            phase: HandoffPhase::NeedCapacity,
            pending: None,
            next_ticket: 1,
            mount_commit: None,
        })
    }

    fn check_dma_starting(dma: &PciDmaHandoff, key: StorageHandoffKey) -> Result<(), Error> {
        match dma.state(key.controller, key.dma_root) {
            Ok(ControllerState::NativeStarting) => Ok(()),
            _ => Err(Error::WrongControllerPhase),
        }
    }

    fn check_owner(&self, key: StorageHandoffKey) -> Result<(), Error> {
        if self.key == key {
            Ok(())
        } else {
            Err(Error::WrongOwner)
        }
    }

    pub const fn phase(&self) -> HandoffPhase {
        self.phase
    }

    pub const fn key(&self) -> StorageHandoffKey {
        self.key
    }

    pub const fn pending_srb(&self) -> Option<SrbProofRequest> {
        self.pending
    }

    /// Reserve the next SRB before the native call. A pending SRB is never issued twice.
    pub fn enter_srb(
        &mut self,
        dma: &PciDmaHandoff,
        key: StorageHandoffKey,
    ) -> Result<SrbProofRequest, Error> {
        self.check_owner(key)?;
        Self::check_dma_starting(dma, key)?;
        let (step, lba, bytes) = match self.phase {
            HandoffPhase::NeedCapacity => (ProofStep::Capacity, 0, 0),
            HandoffPhase::NeedSectorZero => (ProofStep::SectorZero, 0, 512),
            HandoffPhase::NeedVolumeSector => {
                (ProofStep::VolumeSector, self.expected.volume_lba, 512)
            }
            HandoffPhase::Refused => return Err(Error::Refused),
            HandoffPhase::Uncertain => return Err(Error::Uncertain),
            _ => return Err(Error::WrongPhase),
        };
        let ticket = self.next_ticket;
        self.next_ticket = ticket.checked_add(1).ok_or(Error::IdExhausted)?;
        let request = SrbProofRequest {
            key,
            ticket,
            step,
            lba,
            bytes,
        };
        self.pending = Some(request);
        self.phase = HandoffPhase::AwaitingSrb;
        Ok(request)
    }

    fn take_exact(&mut self, request: SrbProofRequest) -> Result<(), Error> {
        self.check_owner(request.key)?;
        // An uncertain send still owns the exact entered SRB. Its authenticated late
        // completion may settle that request, but no second SRB may be issued in its place.
        if !matches!(
            self.phase,
            HandoffPhase::AwaitingSrb | HandoffPhase::Uncertain
        ) {
            return Err(Error::WrongPhase);
        }
        if self.pending != Some(request) {
            return Err(Error::WrongTicket);
        }
        self.pending = None;
        Ok(())
    }

    /// Confirm a completed capacity SRB using the sector size and count returned by the device.
    pub fn complete_capacity(
        &mut self,
        request: SrbProofRequest,
        sector_size: u32,
        sector_count: u64,
    ) -> Result<(), Error> {
        if request.step != ProofStep::Capacity {
            return Err(Error::WrongProofKind);
        }
        self.take_exact(request)?;
        if sector_size != 512 || sector_count != self.expected.sector_count {
            self.phase = HandoffPhase::Refused;
            return Err(Error::GeometryMismatch);
        }
        self.phase = HandoffPhase::NeedSectorZero;
        Ok(())
    }

    /// Confirm exact physical sector bytes, including the partition boot sector at its expected
    /// absolute LBA. Hash-only comparisons are not authority for mounting the writable reserve.
    pub fn complete_sector(&mut self, request: SrbProofRequest, bytes: &[u8]) -> Result<(), Error> {
        if request.step == ProofStep::Capacity {
            return Err(Error::WrongProofKind);
        }
        self.take_exact(request)?;
        let expected = match request.step {
            ProofStep::SectorZero => &self.expected.sector_zero[..],
            ProofStep::VolumeSector => &self.expected.volume_sector[..],
            ProofStep::Capacity => unreachable!(),
        };
        if bytes != expected {
            self.phase = HandoffPhase::Refused;
            return Err(Error::SectorMismatch);
        }
        self.phase = match request.step {
            ProofStep::SectorZero => HandoffPhase::NeedVolumeSector,
            ProofStep::VolumeSector => HandoffPhase::Proven,
            ProofStep::Capacity => unreachable!(),
        };
        Ok(())
    }

    pub fn refuse_srb(&mut self, request: SrbProofRequest) -> Result<(), Error> {
        self.take_exact(request)?;
        self.phase = HandoffPhase::Refused;
        Ok(())
    }

    /// A lost completion leaves the entered request retained and prevents any new SRB or mount.
    pub fn lose_srb(&mut self, request: SrbProofRequest) -> Result<(), Error> {
        self.check_owner(request.key)?;
        if self.phase != HandoffPhase::AwaitingSrb || self.pending != Some(request) {
            return Err(Error::WrongTicket);
        }
        self.phase = HandoffPhase::Uncertain;
        Ok(())
    }

    /// Reserve the single transition of both FAT and snapshot storage under the same mount.
    pub fn enter_mount_commit(
        &mut self,
        dma: &PciDmaHandoff,
        key: StorageHandoffKey,
    ) -> Result<MountCommit, Error> {
        self.check_owner(key)?;
        Self::check_dma_starting(dma, key)?;
        if self.phase != HandoffPhase::Proven {
            return Err(Error::WrongPhase);
        }
        let ticket = self.next_ticket;
        self.next_ticket = ticket.checked_add(1).ok_or(Error::IdExhausted)?;
        let commit = MountCommit { key, ticket };
        self.mount_commit = Some(commit);
        self.phase = HandoffPhase::MountCommitEntered;
        Ok(commit)
    }

    /// Called only after the external mount backend has atomically switched and acknowledged the
    /// exact commit. The DMA ledger then records the authenticated native route.
    pub fn complete_mount_commit(
        &mut self,
        dma: &mut PciDmaHandoff,
        commit: MountCommit,
    ) -> Result<(), Error> {
        self.check_owner(commit.key)?;
        // The backend may acknowledge an uncertain commit later. Only the original ticket
        // can settle the native route; a new commit must never replace it.
        if !matches!(
            self.phase,
            HandoffPhase::MountCommitEntered | HandoffPhase::Uncertain
        ) || self.mount_commit != Some(commit)
        {
            return Err(Error::WrongTicket);
        }
        if dma
            .activate_native(self.key.controller, self.key.dma_root, self.key.pdo.device)
            .is_err()
        {
            self.phase = HandoffPhase::Uncertain;
            return Err(Error::WrongControllerPhase);
        }
        self.mount_commit = None;
        self.phase = HandoffPhase::NativeMounted;
        Ok(())
    }

    pub fn lose_mount_commit(&mut self, commit: MountCommit) -> Result<(), Error> {
        self.check_owner(commit.key)?;
        if self.phase != HandoffPhase::MountCommitEntered || self.mount_commit != Some(commit) {
            return Err(Error::WrongTicket);
        }
        self.phase = HandoffPhase::Uncertain;
        Ok(())
    }

    /// The retained BusRelations publication may advance only after native storage owns the
    /// mounted disk. Publication is separately durable and generation checked by its CM owner.
    pub fn mark_relation_published(
        &mut self,
        dma: &PciDmaHandoff,
        key: StorageHandoffKey,
    ) -> Result<(), Error> {
        self.check_owner(key)?;
        if self.phase != HandoffPhase::NativeMounted
            || dma.state(key.controller, key.dma_root) != Ok(ControllerState::NativeActive)
            || dma.native_route(key.controller, key.dma_root) != Ok(Some(key.pdo.device))
        {
            return Err(Error::WrongPhase);
        }
        self.phase = HandoffPhase::RelationPublished;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (PciDmaHandoff, StorageHandoffKey, ExpectedDisk) {
        let controller = PciController::new(0, 2, 0, 7).unwrap();
        let mut dma = PciDmaHandoff::new();
        dma.register(controller, 17, 0x1000, 1).unwrap();
        let key = StorageHandoffKey {
            controller,
            dma_root: 17,
            mount: 23,
            relation: StorageRelation {
                bus_device: 31,
                generation: 41,
                provider_domain: 43,
                provider_cookie: 47,
            },
            pdo: StoragePdo {
                device: 53,
                raw_pointer: 0x10000,
                provider_driver: 59,
            },
        };
        let expected = ExpectedDisk {
            sector_count: 8192,
            volume_lba: 2048,
            sector_zero: [0xA5; 512],
            volume_sector: [0x5A; 512],
        };
        (dma, key, expected)
    }

    fn native_start(dma: &mut PciDmaHandoff, key: StorageHandoffKey) {
        let window = dma
            .reserve_window(key.controller, key.dma_root, 0x2000, 2)
            .unwrap();
        dma.begin_map(key.controller, key.dma_root, window).unwrap();
        dma.confirm_map(key.controller, key.dma_root, window)
            .unwrap();
        dma.begin_drain(key.controller, key.dma_root).unwrap();
        dma.begin_native_start(key.controller, key.dma_root)
            .unwrap();
    }

    #[test]
    fn rejects_storage_route_before_drained_native_start() {
        let (mut dma, key, expected) = fixture();
        let mut admissions = NativeStorageAdmissions::new();
        assert!(matches!(
            NativeStorageHandoff::new(&mut admissions, &dma, key, expected.clone()),
            Err(Error::WrongControllerPhase)
        ));
        native_start(&mut dma, key);
        assert!(NativeStorageHandoff::new(&mut admissions, &dma, key, expected).is_ok());
    }

    #[test]
    fn capacity_and_exact_sectors_gate_mount_and_publication() {
        let (mut dma, key, expected) = fixture();
        native_start(&mut dma, key);
        let mut admissions = NativeStorageAdmissions::new();
        let mut handoff =
            NativeStorageHandoff::new(&mut admissions, &dma, key, expected.clone()).unwrap();
        let capacity = handoff.enter_srb(&dma, key).unwrap();
        assert_eq!(capacity.step, ProofStep::Capacity);
        assert_eq!(
            handoff.enter_mount_commit(&dma, key),
            Err(Error::WrongPhase)
        );
        handoff
            .complete_capacity(capacity, 512, expected.sector_count)
            .unwrap();
        let first = handoff.enter_srb(&dma, key).unwrap();
        assert_eq!((first.step, first.lba), (ProofStep::SectorZero, 0));
        handoff
            .complete_sector(first, &expected.sector_zero)
            .unwrap();
        let volume = handoff.enter_srb(&dma, key).unwrap();
        assert_eq!(
            (volume.step, volume.lba),
            (ProofStep::VolumeSector, expected.volume_lba)
        );
        handoff
            .complete_sector(volume, &expected.volume_sector)
            .unwrap();
        let commit = handoff.enter_mount_commit(&dma, key).unwrap();
        assert_eq!(
            handoff.mark_relation_published(&dma, key),
            Err(Error::WrongPhase)
        );
        handoff.complete_mount_commit(&mut dma, commit).unwrap();
        handoff.mark_relation_published(&dma, key).unwrap();
        assert_eq!(handoff.phase(), HandoffPhase::RelationPublished);
    }

    #[test]
    fn stale_pdo_or_relation_cannot_complete_an_entered_srb() {
        let (mut dma, key, expected) = fixture();
        native_start(&mut dma, key);
        let mut admissions = NativeStorageAdmissions::new();
        let mut handoff = NativeStorageHandoff::new(&mut admissions, &dma, key, expected).unwrap();
        let request = handoff.enter_srb(&dma, key).unwrap();
        let mut stale = request;
        stale.key.relation.generation += 1;
        assert_eq!(
            handoff.complete_capacity(stale, 512, 8192),
            Err(Error::WrongOwner)
        );
        stale = request;
        stale.key.pdo.raw_pointer += 8;
        assert_eq!(
            handoff.complete_capacity(stale, 512, 8192),
            Err(Error::WrongOwner)
        );
        assert_eq!(handoff.pending_srb(), Some(request));
        handoff.complete_capacity(request, 512, 8192).unwrap();
    }

    #[test]
    fn uncertain_srb_and_mount_commit_resolve_only_their_exact_late_receipts() {
        let (mut dma, key, expected) = fixture();
        native_start(&mut dma, key);
        let mut admissions = NativeStorageAdmissions::new();
        let mut handoff =
            NativeStorageHandoff::new(&mut admissions, &dma, key, expected.clone()).unwrap();
        let request = handoff.enter_srb(&dma, key).unwrap();
        handoff.lose_srb(request).unwrap();
        assert_eq!(handoff.pending_srb(), Some(request));
        assert_eq!(handoff.enter_srb(&dma, key), Err(Error::Uncertain));
        let mut wrong = request;
        wrong.ticket += 1;
        assert_eq!(
            handoff.complete_capacity(wrong, 512, 8192),
            Err(Error::WrongTicket)
        );
        handoff.complete_capacity(request, 512, 8192).unwrap();
        assert_eq!(handoff.pending_srb(), None);
        assert_eq!(
            handoff.complete_capacity(request, 512, 8192),
            Err(Error::WrongPhase)
        );
        assert_eq!(
            handoff.enter_srb(&dma, key).unwrap().step,
            ProofStep::SectorZero
        );
        assert!(matches!(
            NativeStorageHandoff::new(&mut admissions, &dma, key, expected.clone()),
            Err(Error::ControllerClaimed)
        ));
        let (mut dma, key, expected) = fixture();
        native_start(&mut dma, key);
        let mut admissions = NativeStorageAdmissions::new();
        let mut second =
            NativeStorageHandoff::new(&mut admissions, &dma, key, expected.clone()).unwrap();
        let capacity = second.enter_srb(&dma, key).unwrap();
        second.complete_capacity(capacity, 512, 8192).unwrap();
        let first = second.enter_srb(&dma, key).unwrap();
        second
            .complete_sector(first, &expected.sector_zero)
            .unwrap();
        let volume = second.enter_srb(&dma, key).unwrap();
        second
            .complete_sector(volume, &expected.volume_sector)
            .unwrap();
        let commit = second.enter_mount_commit(&dma, key).unwrap();
        second.lose_mount_commit(commit).unwrap();
        assert_eq!(second.phase(), HandoffPhase::Uncertain);
        let mut wrong = commit;
        wrong.ticket += 1;
        assert_eq!(
            second.complete_mount_commit(&mut dma, wrong),
            Err(Error::WrongTicket)
        );
        second.complete_mount_commit(&mut dma, commit).unwrap();
        assert_eq!(second.phase(), HandoffPhase::NativeMounted);
        assert_eq!(
            second.complete_mount_commit(&mut dma, commit),
            Err(Error::WrongTicket)
        );
    }

    #[test]
    fn different_disk_bytes_or_geometry_refuse_storage_mount() {
        let (mut dma, key, expected) = fixture();
        native_start(&mut dma, key);
        let mut admissions = NativeStorageAdmissions::new();
        let mut handoff =
            NativeStorageHandoff::new(&mut admissions, &dma, key, expected.clone()).unwrap();
        let capacity = handoff.enter_srb(&dma, key).unwrap();
        assert_eq!(
            handoff.complete_capacity(capacity, 4096, 8192),
            Err(Error::GeometryMismatch)
        );
        assert_eq!(handoff.enter_srb(&dma, key), Err(Error::Refused));
        let (mut dma, key, _) = fixture();
        native_start(&mut dma, key);
        let mut admissions = NativeStorageAdmissions::new();
        let mut handoff = NativeStorageHandoff::new(&mut admissions, &dma, key, expected).unwrap();
        let capacity = handoff.enter_srb(&dma, key).unwrap();
        handoff.complete_capacity(capacity, 512, 8192).unwrap();
        let first = handoff.enter_srb(&dma, key).unwrap();
        assert_eq!(
            handoff.complete_sector(first, &[0; 512]),
            Err(Error::SectorMismatch)
        );
        assert_eq!(handoff.phase(), HandoffPhase::Refused);
    }
}
