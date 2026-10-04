//! Checked re-establishment of an exactly retained resident mapping after a nonpresent fault.
//!
//! This owner borrows existing cap authority; it never allocates, transfers, or retires resources.
//! Keep the descriptor and both cap owners retained until an acknowledged result is consumed.

use crate::private_page_installation::{InstallationCap, InstallationEffect};
use crate::STATUS_INVALID_HANDLE;

pub trait ResidentMappingRevalidationIo<D> {
    /// Validate the exact current process/VSpace, resident record, protection, and retained cap
    /// owners. Numeric cap equality or registry residency alone is not sufficient authority.
    fn validate_current(
        &mut self,
        descriptor: &D,
        mapped: InstallationCap,
        backing: InstallationCap,
    ) -> Result<(), u32>;
    /// Return the physical address only after checking the actual native query acknowledgement.
    fn frame_address(&mut self, cap: InstallationCap) -> Result<u64, u32>;
    /// Re-establish this existing cap at the exact descriptor's address, VSpace, and rights.
    /// Refused witnesses no effect; Uncertain permits neither replay nor resource retirement.
    fn map_existing(&mut self, descriptor: &D, mapped: InstallationCap) -> InstallationEffect;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResidentMappingRevalidationOutcome {
    Revalidated,
    Refused(u32),
    Quarantined(u32),
}

#[derive(Clone, Copy)]
enum Phase {
    Ready,
    MapPending,
    Revalidated,
    Quarantined(u32),
}

/// No Drop cleanup. Native backends must be exclusive and cannot pump or reenter this owner.
#[must_use = "retain the exact mapping and backing owners across pending or uncertain effects"]
pub struct ResidentMappingRevalidation<D> {
    descriptor: D,
    mapped: InstallationCap,
    backing: InstallationCap,
    phase: Phase,
}

impl<D: Copy + Eq> ResidentMappingRevalidation<D> {
    pub fn begin(
        descriptor: D,
        mapped: InstallationCap,
        backing: InstallationCap,
        nonpresent_fault: bool,
    ) -> Result<Self, u32> {
        if !nonpresent_fault || mapped.cap == 0 || backing.cap == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        Ok(Self {
            descriptor,
            mapped,
            backing,
            phase: Phase::Ready,
        })
    }

    pub fn descriptor(&self) -> D {
        self.descriptor
    }

    pub fn mapped(&self) -> InstallationCap {
        self.mapped
    }

    pub fn source(&self) -> InstallationCap {
        self.backing
    }

    pub fn is_revalidated(&self) -> bool {
        matches!(self.phase, Phase::Revalidated)
    }

    pub fn is_quarantined(&self) -> bool {
        matches!(self.phase, Phase::Quarantined(_))
    }

    /// A pending call interrupted before its result was recorded is also a retirement fence.
    pub fn blocks_retirement(&self) -> bool {
        matches!(self.phase, Phase::MapPending | Phase::Quarantined(_))
    }

    pub fn advance(
        &mut self,
        io: &mut impl ResidentMappingRevalidationIo<D>,
    ) -> ResidentMappingRevalidationOutcome {
        use ResidentMappingRevalidationOutcome as Outcome;
        match self.phase {
            Phase::Revalidated => return Outcome::Revalidated,
            Phase::Quarantined(status) => return Outcome::Quarantined(status),
            Phase::MapPending => {
                self.phase = Phase::Quarantined(STATUS_INVALID_HANDLE);
                return Outcome::Quarantined(STATUS_INVALID_HANDLE);
            }
            Phase::Ready => {}
        }
        if let Err(status) = io.validate_current(&self.descriptor, self.mapped, self.backing) {
            return Outcome::Refused(status);
        }
        let mapped_address = match io.frame_address(self.mapped) {
            Ok(address) => address,
            Err(status) => return Outcome::Refused(status),
        };
        let backing_address = match io.frame_address(self.backing) {
            Ok(address) => address,
            Err(status) => return Outcome::Refused(status),
        };
        if mapped_address == 0 || mapped_address & 0xfff != 0 || backing_address != mapped_address {
            return Outcome::Refused(STATUS_INVALID_HANDLE);
        }
        if let Err(status) = io.validate_current(&self.descriptor, self.mapped, self.backing) {
            return Outcome::Refused(status);
        }
        self.phase = Phase::MapPending;
        match io.map_existing(&self.descriptor, self.mapped) {
            InstallationEffect::Acknowledged => {
                self.phase = Phase::Revalidated;
                Outcome::Revalidated
            }
            InstallationEffect::Refused(status) => {
                self.phase = Phase::Ready;
                Outcome::Refused(status)
            }
            InstallationEffect::Uncertain(status) => {
                self.phase = Phase::Quarantined(status);
                Outcome::Quarantined(status)
            }
        }
    }
}
