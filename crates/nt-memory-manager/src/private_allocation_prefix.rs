//! The accepted native prefix of one private allocation and its retained, checked rollback.
//!
//! `NtAllocateVirtualMemory` maps or reprotects committed pages before it publishes the VAD and
//! commit charge. Each accepted page effect is recorded here before the next effect is invoked.
//! When a later page fails, the prefix is reversed through this owner. A refused reversal keeps the
//! exact remaining prefix for a later retry; an uncertain reversal quarantines it. Neither permits
//! replay, VAD publication or retirement of the process until the owner is idle again.
//!
//! While an owner is retained the VAD and commit charge remain those before the allocation: the
//! request failed, and the remaining native pages are owned only by this prefix until reversed.

use crate::private_page_installation::InstallationEffect;

const PAGE_SIZE: u64 = 0x1000;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
const INVALID: u32 = crate::STATUS_INVALID_HANDLE;
/// Distinct effect runs one allocation may accept. An allocation spanning more runs fails before
/// invoking the effect that could not be recorded.
pub const PREFIX_RUN_CAPACITY: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefixEffect {
    /// A newly committed page was mapped with fresh private backing.
    Mapped,
    /// A committed page's protection changed from `old` to `new`.
    Reprotected { old: u32, new: u32 },
}

pub trait PrivateAllocationPrefixIo<D> {
    /// Retire the private page mapped by this allocation.
    fn unmap(&mut self, descriptor: &D, page: u64) -> InstallationEffect;
    /// Restore a reprotected page from `current` to `restore`.
    fn reprotect(&mut self, descriptor: &D, page: u64, current: u32, restore: u32)
        -> InstallationEffect;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrefixRollbackOutcome {
    /// Every accepted effect has been reversed; the owner is idle and the failure is settled.
    RolledBack(u32),
    /// A reversal was refused. The exact remaining prefix is retained for retry.
    CleanupPending { status: u32, rollback_status: u32 },
    /// A reversal may have taken effect. The remaining prefix is frozen without replay.
    Quarantined { status: u32, rollback_status: u32 },
}

impl PrefixRollbackOutcome {
    /// The allocation's own failure status, whether or not its rollback has settled.
    pub fn status(self) -> u32 {
        match self {
            Self::RolledBack(status)
            | Self::CleanupPending { status, .. }
            | Self::Quarantined { status, .. } => status,
        }
    }
    pub fn is_settled(self) -> bool {
        matches!(self, Self::RolledBack(_))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Run {
    base: u64,
    pages: u64,
    effect: PrefixEffect,
}

impl Run {
    fn end(self) -> u64 {
        self.base + self.pages * PAGE_SIZE
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Recording,
    Rollback,
    Quarantined,
}

struct Owner<D> {
    descriptor: D,
    runs: [Option<Run>; PREFIX_RUN_CAPACITY],
    len: usize,
    phase: Phase,
    failure: u32,
    rollback_status: u32,
}

/// No Drop cleanup: keep the containing owner until it is idle.
#[must_use = "retain this prefix through every rollback refusal or uncertain effect"]
pub struct PrivateAllocationPrefix<D> {
    owner: Option<Owner<D>>,
}

impl<D: Copy + Eq> PrivateAllocationPrefix<D> {
    pub const fn new() -> Self {
        Self { owner: None }
    }
    pub fn is_idle(&self) -> bool {
        self.owner.is_none()
    }
    pub fn descriptor(&self) -> Option<D> {
        self.owner.as_ref().map(|owner| owner.descriptor)
    }
    pub fn is_quarantined(&self) -> bool {
        self.owner
            .as_ref()
            .is_some_and(|owner| owner.phase == Phase::Quarantined)
    }
    /// Pages whose effect is accepted and not yet reversed.
    pub fn retained_pages(&self) -> u64 {
        self.owner.as_ref().map_or(0, |owner| {
            owner.runs[..owner.len]
                .iter()
                .flatten()
                .map(|run| run.pages)
                .sum()
        })
    }
    /// Whether `page` is covered by an accepted effect that has not been reversed.
    pub fn covers(&self, page: u64) -> bool {
        self.owner.as_ref().is_some_and(|owner| {
            owner.runs[..owner.len]
                .iter()
                .flatten()
                .any(|run| run.base <= page && page < run.end())
        })
    }

    pub fn begin(&mut self, descriptor: D) -> Result<(), u32> {
        if self.owner.is_some() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        self.owner = Some(Owner {
            descriptor,
            runs: [None; PREFIX_RUN_CAPACITY],
            len: 0,
            phase: Phase::Recording,
            failure: 0,
            rollback_status: 0,
        });
        Ok(())
    }

    /// Invoke one page effect and record it if accepted. Pages must ascend. Capacity is checked
    /// before `effect` runs, so an unrecordable effect is never invoked. An `Err` from `effect`
    /// leaves that page to its own single-page owner; it never enters this prefix.
    pub fn apply(
        &mut self,
        page: u64,
        kind: PrefixEffect,
        effect: impl FnOnce() -> Result<(), u32>,
    ) -> Result<(), u32> {
        let owner = self.owner.as_mut().ok_or(INVALID)?;
        if owner.phase != Phase::Recording || page % PAGE_SIZE != 0 {
            return Err(INVALID);
        }
        let last = owner.len.checked_sub(1).and_then(|index| owner.runs[index]);
        if last.is_some_and(|run| page < run.end()) {
            return Err(INVALID);
        }
        let extends = last.is_some_and(|run| run.end() == page && run.effect == kind);
        if !extends && owner.len == PREFIX_RUN_CAPACITY {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        effect()?;
        if extends {
            owner.runs[owner.len - 1].as_mut().unwrap().pages += 1;
        } else {
            owner.runs[owner.len] = Some(Run {
                base: page,
                pages: 1,
                effect: kind,
            });
            owner.len += 1;
        }
        Ok(())
    }

    /// Every effect succeeded and the VAD/charge publication now owns the accepted pages.
    pub fn commit(&mut self) -> Result<(), u32> {
        match self.owner.as_ref() {
            Some(owner) if owner.phase == Phase::Recording => {
                self.owner = None;
                Ok(())
            }
            _ => Err(INVALID),
        }
    }

    /// The allocation failed with `status`; begin reversing its accepted prefix.
    pub fn fail(&mut self, io: &mut impl PrivateAllocationPrefixIo<D>, status: u32) -> PrefixRollbackOutcome {
        match self.owner.as_mut() {
            Some(owner) if owner.phase == Phase::Recording => {
                owner.failure = status;
                owner.phase = Phase::Rollback;
            }
            _ => return PrefixRollbackOutcome::Quarantined { status, rollback_status: INVALID },
        }
        self.advance(io)
    }

    /// Continue a retained rollback, last accepted page first. Each ACK is recorded before the
    /// next reversal; a refusal stops with the exact remainder retained.
    pub fn advance(&mut self, io: &mut impl PrivateAllocationPrefixIo<D>) -> PrefixRollbackOutcome {
        let Some(owner) = self.owner.as_mut() else {
            return PrefixRollbackOutcome::RolledBack(INVALID);
        };
        loop {
            match owner.phase {
                Phase::Recording => {
                    return PrefixRollbackOutcome::Quarantined {
                        status: owner.failure,
                        rollback_status: INVALID,
                    }
                }
                Phase::Quarantined => {
                    return PrefixRollbackOutcome::Quarantined {
                        status: owner.failure,
                        rollback_status: owner.rollback_status,
                    }
                }
                Phase::Rollback => {}
            }
            let Some(index) = owner.len.checked_sub(1) else {
                let status = owner.failure;
                self.owner = None;
                return PrefixRollbackOutcome::RolledBack(status);
            };
            let run = owner.runs[index].unwrap();
            let page = run.end() - PAGE_SIZE;
            let effect = match run.effect {
                PrefixEffect::Mapped => io.unmap(&owner.descriptor, page),
                PrefixEffect::Reprotected { old, new } => {
                    io.reprotect(&owner.descriptor, page, new, old)
                }
            };
            match effect {
                InstallationEffect::Acknowledged => {
                    if run.pages == 1 {
                        owner.runs[index] = None;
                        owner.len = index;
                    } else {
                        owner.runs[index].as_mut().unwrap().pages -= 1;
                    }
                }
                InstallationEffect::Refused(status) => {
                    owner.rollback_status = status;
                    return PrefixRollbackOutcome::CleanupPending {
                        status: owner.failure,
                        rollback_status: status,
                    };
                }
                InstallationEffect::Uncertain(status) => {
                    owner.rollback_status = status;
                    owner.phase = Phase::Quarantined;
                }
            }
        }
    }
}

impl<D: Copy + Eq> Default for PrivateAllocationPrefix<D> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "private_allocation_prefix_tests.rs"]
mod tests;
