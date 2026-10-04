//! One retained, unpublished private-page installation and its checked rollback.
//!
//! Store this owner before calling `advance`. Backend calls cannot reenter it. The descriptor
//! carries genuine retained process/VSpace identity; cap integers alone confer no authority.

const INVALID: u32 = crate::STATUS_INVALID_HANDLE;
use core::sync::atomic::{AtomicU64, Ordering};
static LAST_INSTALLATION: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Capability observation only. The containing installation is the exclusive owner; the native
/// backend validates live, retyped, nonfree allocator ownership rather than inferring a generation.
pub struct InstallationCap {
    pub cap: u64,
}

impl InstallationCap {
    fn valid(self) -> bool {
        self.cap != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallationEffect {
    Acknowledged,
    /// The backend witnessed no effect. Rejected cleanup may be retried.
    Refused(u32),
    /// An effect may have entered. Neither replay nor resource reuse is permitted.
    Uncertain(u32),
}

/// A snapshot supplied to the final registry publication, not a second resource owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrivatePagePublication<D> {
    pub operation: u64,
    pub descriptor: D,
    pub frame: InstallationCap,
    pub alias: Option<InstallationCap>,
}

pub trait PrivatePageInstallationIo<D> {
    /// Err transfers nothing; the acquisition backend must retain its partial owner on error.
    /// Success transfers exclusive zeroed UNMAPPED backing; it cannot enter any other reuse pool.
    fn acquire_frame(&mut self, descriptor: &D) -> Result<InstallationCap, u32>;
    /// Err reserves nothing. Return an owned EMPTY slot validated by the native allocator.
    fn reserve_alias(&mut self, descriptor: &D) -> Result<InstallationCap, u32>;
    fn copy_alias(&mut self, frame: InstallationCap, alias: InstallationCap) -> InstallationEffect;
    fn map_frame(&mut self, descriptor: &D, frame: InstallationCap) -> InstallationEffect;
    fn map_alias(&mut self, descriptor: &D, alias: InstallationCap) -> InstallationEffect;
    /// ACK transfers all captured resources into the exact canonical resident registry together.
    /// Refusal must leave that registry unchanged; it cannot publish a partial record.
    fn publish(&mut self, publication: PrivatePagePublication<D>) -> InstallationEffect;
    fn unmap(&mut self, cap: InstallationCap) -> InstallationEffect;
    fn delete_alias(&mut self, alias: InstallationCap) -> InstallationEffect;
    fn recycle_alias(&mut self, alias: InstallationCap) -> InstallationEffect;
    /// Called only after every mapping/alias retirement is acknowledged. ACK transfers backing.
    fn release_frame(&mut self, frame: InstallationCap) -> InstallationEffect;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Acquire,
    MapFrame,
    ReserveAlias,
    CopyAlias,
    MapAlias,
    Publish,
    Rollback,
    Quarantined,
}

struct Pending<D> {
    operation: u64,
    descriptor: D,
    wants_alias: bool,
    frame: Option<InstallationCap>,
    frame_mapped: bool,
    alias: Option<InstallationCap>,
    alias_populated: bool,
    alias_mapped: bool,
    phase: Phase,
    failure: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrivatePageInstallOutcome {
    Published,
    Failed(u32),
    CleanupPending(u32),
    Quarantined(u32),
}

/// No Drop cleanup: keep the containing scratch owner until it is idle or ownership transferred.
#[must_use = "retain this installation through every cleanup refusal or uncertain effect"]
pub struct PrivatePageInstallation<D> {
    pending: Option<Pending<D>>,
}

impl<D: Copy + Eq> PrivatePageInstallation<D> {
    pub const fn new() -> Self {
        Self { pending: None }
    }
    pub fn is_idle(&self) -> bool {
        self.pending.is_none()
    }
    pub fn descriptor(&self) -> Option<D> {
        self.pending.as_ref().map(|owner| owner.descriptor)
    }
    pub fn operation(&self) -> Option<u64> {
        self.pending.as_ref().map(|owner| owner.operation)
    }
    pub fn owns_cap(&self, cap: u64) -> bool {
        cap != 0
            && self.pending.as_ref().is_some_and(|owner| {
                owner.frame.is_some_and(|frame| frame.cap == cap)
                    || owner.alias.is_some_and(|alias| alias.cap == cap)
            })
    }
    pub fn begin(&mut self, descriptor: D, wants_alias: bool) -> Result<(), u32> {
        if self.pending.is_some() {
            return Err(INVALID);
        }
        let operation = LAST_INSTALLATION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| 0xc000009a_u32)?
            + 1;
        self.pending = Some(Pending {
            operation,
            descriptor,
            wants_alias,
            frame: None,
            frame_mapped: false,
            alias: None,
            alias_populated: false,
            alias_mapped: false,
            phase: Phase::Acquire,
            failure: 0,
        });
        Ok(())
    }

    fn reject(owner: &mut Pending<D>, effect: InstallationEffect) -> bool {
        match effect {
            InstallationEffect::Acknowledged => false,
            InstallationEffect::Refused(status) => {
                owner.failure = status;
                owner.phase = Phase::Rollback;
                true
            }
            InstallationEffect::Uncertain(status) => {
                owner.failure = status;
                owner.phase = Phase::Quarantined;
                true
            }
        }
    }

    pub fn advance(
        &mut self,
        io: &mut impl PrivatePageInstallationIo<D>,
    ) -> PrivatePageInstallOutcome {
        let Some(owner) = self.pending.as_mut() else {
            return PrivatePageInstallOutcome::Failed(INVALID);
        };
        loop {
            match owner.phase {
                Phase::Acquire => match io.acquire_frame(&owner.descriptor) {
                    Ok(frame) => {
                        owner.frame = Some(frame);
                        if !frame.valid() {
                            owner.failure = INVALID;
                            owner.phase = Phase::Quarantined;
                        } else {
                            owner.phase = Phase::MapFrame;
                        }
                    }
                    Err(status) => {
                        self.pending = None;
                        return PrivatePageInstallOutcome::Failed(status);
                    }
                },
                Phase::MapFrame => {
                    if Self::reject(owner, io.map_frame(&owner.descriptor, owner.frame.unwrap())) {
                        continue;
                    }
                    owner.frame_mapped = true;
                    owner.phase = if owner.wants_alias {
                        Phase::ReserveAlias
                    } else {
                        Phase::Publish
                    };
                }
                Phase::ReserveAlias => match io.reserve_alias(&owner.descriptor) {
                    Ok(alias) => {
                        owner.alias = Some(alias);
                        if !alias.valid() || alias.cap == owner.frame.unwrap().cap {
                            owner.failure = INVALID;
                            owner.phase = Phase::Quarantined;
                        } else {
                            owner.phase = Phase::CopyAlias;
                        }
                    }
                    Err(status) => {
                        owner.failure = status;
                        owner.phase = Phase::Rollback;
                    }
                },
                Phase::CopyAlias => {
                    if Self::reject(
                        owner,
                        io.copy_alias(owner.frame.unwrap(), owner.alias.unwrap()),
                    ) {
                        continue;
                    }
                    owner.alias_populated = true;
                    owner.phase = Phase::MapAlias;
                }
                Phase::MapAlias => {
                    if Self::reject(owner, io.map_alias(&owner.descriptor, owner.alias.unwrap())) {
                        continue;
                    }
                    owner.alias_mapped = true;
                    owner.phase = Phase::Publish;
                }
                Phase::Publish => {
                    let publication = PrivatePagePublication {
                        operation: owner.operation,
                        descriptor: owner.descriptor,
                        frame: owner.frame.unwrap(),
                        alias: owner.alias,
                    };
                    if Self::reject(owner, io.publish(publication)) {
                        continue;
                    }
                    self.pending = None;
                    return PrivatePageInstallOutcome::Published;
                }
                Phase::Quarantined => return PrivatePageInstallOutcome::Quarantined(owner.failure),
                Phase::Rollback => {
                    // Record each ACK before invoking another effect. Refusal retains this phase;
                    // uncertainty freezes the whole owner, including its previously accepted prefix.
                    let (effect, step) = if owner.alias_mapped {
                        (io.unmap(owner.alias.unwrap()), 0)
                    } else if owner.alias_populated {
                        (io.delete_alias(owner.alias.unwrap()), 1)
                    } else if let Some(alias) = owner.alias {
                        (io.recycle_alias(alias), 2)
                    } else if owner.frame_mapped {
                        (io.unmap(owner.frame.unwrap()), 3)
                    } else if let Some(frame) = owner.frame {
                        (io.release_frame(frame), 4)
                    } else {
                        let status = owner.failure;
                        self.pending = None;
                        return PrivatePageInstallOutcome::Failed(status);
                    };
                    match effect {
                        InstallationEffect::Acknowledged => match step {
                            0 => owner.alias_mapped = false,
                            1 => owner.alias_populated = false,
                            2 => owner.alias = None,
                            3 => owner.frame_mapped = false,
                            4 => owner.frame = None,
                            _ => unreachable!(),
                        },
                        InstallationEffect::Refused(status) => {
                            return PrivatePageInstallOutcome::CleanupPending(status)
                        }
                        InstallationEffect::Uncertain(status) => {
                            owner.failure = status;
                            owner.phase = Phase::Quarantined;
                        }
                    }
                }
            }
        }
    }
}

impl<D: Copy + Eq> Default for PrivatePageInstallation<D> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "private_page_installation_tests.rs"]
mod tests;
