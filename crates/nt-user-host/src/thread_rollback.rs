//! Checked ownership for a registered thread whose Ps/handle publication never committed.
use crate::process_identity::ProcessGeneration;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadRollbackIdentity {
    pub pi: usize,
    pub pid: u32,
    pub process_generation: ProcessGeneration,
    pub tid: u64,
}

/// Exact pending owner. Pooled TIDs can recur within the same process generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadRollbackId {
    identity: ThreadRollbackIdentity,
    attempt: RollbackAttempt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RollbackAttempt {
    Registered(u64),
    Construction(u64),
}

impl ThreadRollbackId {
    pub fn identity(self) -> ThreadRollbackIdentity {
        self.identity
    }
}

pub(crate) fn new_rollback_id(
    identity: ThreadRollbackIdentity,
) -> Result<ThreadRollbackId, ThreadRollbackError> {
    if identity.pid == 0 || identity.tid == 0 || !identity.process_generation.is_valid() {
        return Err(ThreadRollbackError::InvalidIdentity);
    }
    Ok(ThreadRollbackId {
        identity,
        attempt: RollbackAttempt::Registered(allocate_attempt(&NEXT_ATTEMPT)?),
    })
}

/// Reuse the already reserved publication attempt in a distinct identity domain. Failure handoff
/// must not need another counter reservation after construction has acquired resources.
pub(crate) fn construction_rollback_id<T>(
    identity: ThreadRollbackIdentity,
    ticket: &crate::thread_publication::PreparedThreadPublication<T>,
) -> Result<ThreadRollbackId, ThreadRollbackError> {
    if identity.pid == 0 || identity.tid == 0 || !identity.process_generation.is_valid() {
        return Err(ThreadRollbackError::InvalidIdentity);
    }
    Ok(ThreadRollbackId {
        identity,
        attempt: RollbackAttempt::Construction(ticket.attempt()),
    })
}

fn allocate_attempt(counter: &AtomicU64) -> Result<u64, ThreadRollbackError> {
    counter
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
            next.checked_add(1)
        })
        .map_err(|_| ThreadRollbackError::InsufficientResources)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadRollbackResourceKind {
    /// A target, mirror, scratch or registry cap. Delete it, never recycle its physical frame.
    Alias,
    /// The sole physical-frame owner. Recycle after alias and mechanism deletion is acknowledged.
    Frame,
    /// Scheduling context, CNode or other thread-private mechanism cap.
    Mechanism,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadRollbackResource {
    pub cap: u64,
    pub kind: ThreadRollbackResourceKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadRollbackStage {
    Suspend,
    DeleteTcb,
    RevokeMemoryAccess,
    Aliases,
    Mechanism,
    Frames,
    FinishMemoryTransfers,
    Commit,
    Complete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadRollbackError {
    InvalidIdentity,
    InvalidCapability,
    ConflictingOwnership,
    InsufficientResources,
    StaleOwner,
    AlreadyPrepared,
    NotPrepared,
    ConstructionPending,
    Backend {
        stage: ThreadRollbackStage,
        status: u32,
    },
}

pub trait ThreadRollbackIo {
    /// Validate the exact pending rollback owner on every attempt, including its held pool/window
    /// reservations. The runtime is retained but excluded from runnable/resume lookup. No effects.
    fn is_current(&self, id: ThreadRollbackId) -> bool;
    fn suspend_tcb(&mut self, tcb: u64) -> Result<(), u32>;
    /// Success must acknowledge deletion, not merely suspension. Failure retains the exact cap.
    fn delete_tcb(&mut self, tcb: u64) -> Result<(), u32>;
    /// Exclude refault/native-copy admission and revoke external mappings before recycling backing.
    /// Reserve any needed bookkeeping first. Partial failure must retain its mapping/registry
    /// journal under this exact attempt for retry. Exclusions must survive through commit and prevent
    /// other threads, refaults and native copies from introducing new aliases. This callback must
    /// not unmap/delete/recycle listed resources: later stages own those operations and their
    /// acknowledgements. External aliases require a disjoint, retry-owned cleanup journal.
    fn revoke_memory_access(&mut self, id: ThreadRollbackId) -> Result<(), u32>;
    /// Checked unmap of an Alias or Frame capability, including an already-unmapped cap. The
    /// rollback owner records acknowledgement separately from deletion/recycling so release retry
    /// never repeats a successful unmap. Mechanism resources do not pass through this callback.
    fn unmap_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32>;
    /// Delete an Alias or Mechanism capability only, never its allocator slot. Alias unmapping
    /// has already been acknowledged. Frame owners never enter this callback. Err must retain
    /// the populated capability; successful deletion is acknowledged before recycling is attempted.
    fn delete_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32>;
    /// Transfer an empty Alias/Mechanism slot or an unmapped Frame backing owner to its allocator.
    /// Frame cleanup must reserve free-list bookkeeping before losing ownership metadata. A
    /// successful transfer also clears every mutable registry/runtime release reference.
    /// Immutable terminal transfer snapshots keep their captured cap numbers until final transfer
    /// acknowledgement, but must expose neither ordinary access nor a second release authority.
    /// Failure retains exact input ownership. Do not repeat deletion here: it has already been
    /// acknowledged for Alias/Mechanism, and a Frame cap must remain populated in its frame pool.
    fn recycle_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32>;
    /// Finish exact terminal registry transfers after all resources have been released. Failure
    /// retains the transfer owners and their completed substeps for retry; it cannot restore access
    /// or authorize release of captured numeric capabilities again. No reservation/accounting
    /// release belongs here. Successful completion is acknowledged before the infallible commit.
    fn finish_memory_transfers(&mut self, id: ThreadRollbackId) -> Result<(), u32>;
    /// Release retained commitment and target pool/window reservations once, then retire the
    /// runtime. This is an allocation-free target-side commit: never write caller output pointers,
    /// repeat caller handle cancellation, or synthesize activation/termination of the unpublished
    /// ETHREAD. The outer owner must keep this rollback object alive through the callback's return.
    fn commit_rollback(&mut self, id: ThreadRollbackId);
}

/// Non-cloneable retry owner. Preparation is fallible and performs no cleanup; ownership transfers
/// only on success. Publish it with the retained runtime/reservations before driving it. Cancel the
/// caller's bound handle and failure outputs once in the original syscall context, separately from
/// this target-side lifetime. The caller must keep the owner until completion; Drop cannot clean up.
///
/// Repeated entries for the same capability/class are coalesced, but conflicting classes are
/// rejected. Different caps can refer to the same physical frame: the caller must designate exactly
/// one Frame owner and classify its copies as Alias. Numeric cap deduplication cannot infer physical
/// identity. In particular the hosted TEB registry's target cap is not a second physical-frame owner.
#[must_use = "retain the rollback owner and its reservations until cleanup completes"]
pub struct ThreadRollback {
    id: ThreadRollbackId,
    tcb: u64,
    stage: ThreadRollbackStage,
    resources: Vec<OwnedResource>,
}

struct OwnedResource {
    resource: ThreadRollbackResource,
    unmapped: bool,
    deleted: bool,
}

impl ThreadRollback {
    pub fn prepare(
        identity: ThreadRollbackIdentity,
        tcb: u64,
        resources: &[ThreadRollbackResource],
    ) -> Result<Self, ThreadRollbackError> {
        Self::prepare_with_id(new_rollback_id(identity)?, tcb, resources)
    }

    pub(crate) fn prepare_with_id(
        id: ThreadRollbackId,
        tcb: u64,
        resources: &[ThreadRollbackResource],
    ) -> Result<Self, ThreadRollbackError> {
        if tcb <= 1 {
            return Err(ThreadRollbackError::InvalidCapability);
        }
        Self::prepare_optional_tcb(id, Some(tcb), resources)
    }

    pub(crate) fn prepare_optional_tcb(
        id: ThreadRollbackId,
        tcb: Option<u64>,
        resources: &[ThreadRollbackResource],
    ) -> Result<Self, ThreadRollbackError> {
        if tcb.is_some_and(|cap| cap <= 1) {
            return Err(ThreadRollbackError::InvalidCapability);
        }
        let mut owned: Vec<OwnedResource> = Vec::new();
        owned
            .try_reserve(resources.len())
            .map_err(|_| ThreadRollbackError::InsufficientResources)?;
        for &resource in resources {
            // Zero is the existing runtime resource representation for an absent capability.
            if resource.cap == 0 {
                continue;
            }
            if Some(resource.cap) == tcb {
                return Err(ThreadRollbackError::ConflictingOwnership);
            }
            if let Some(existing) = owned
                .iter()
                .find(|entry| entry.resource.cap == resource.cap)
            {
                if existing.resource.kind != resource.kind {
                    return Err(ThreadRollbackError::ConflictingOwnership);
                }
            } else {
                owned.push(OwnedResource {
                    resource,
                    unmapped: false,
                    deleted: false,
                });
            }
        }
        Ok(Self {
            id,
            tcb: tcb.unwrap_or(0),
            stage: if tcb.is_some() {
                ThreadRollbackStage::Suspend
            } else {
                ThreadRollbackStage::RevokeMemoryAccess
            },
            resources: owned,
        })
    }

    pub fn identity(&self) -> ThreadRollbackIdentity {
        self.id.identity()
    }

    pub fn id(&self) -> ThreadRollbackId {
        self.id
    }

    pub fn stage(&self) -> ThreadRollbackStage {
        self.stage
    }

    pub fn pending_tcb(&self) -> Option<u64> {
        (self.tcb != 0).then_some(self.tcb)
    }

    pub fn pending_resources(&self) -> impl Iterator<Item = ThreadRollbackResource> + '_ {
        self.resources
            .iter()
            .map(|entry| entry.resource)
            .filter(|entry| entry.cap != 0)
    }

    /// Drive one serialized attempt. Every successful sub-operation is recorded before the next;
    /// a retry never suspends a deleted TCB, deletes a recycled cap slot or commits accounting twice.
    pub fn advance(&mut self, io: &mut impl ThreadRollbackIo) -> Result<(), ThreadRollbackError> {
        if self.stage == ThreadRollbackStage::Complete {
            return Ok(());
        }
        if !io.is_current(self.id) {
            return Err(ThreadRollbackError::StaleOwner);
        }
        loop {
            let stage = self.stage;
            let next = match stage {
                ThreadRollbackStage::Suspend => {
                    io.suspend_tcb(self.tcb)
                        .map_err(|status| ThreadRollbackError::Backend { stage, status })?;
                    ThreadRollbackStage::DeleteTcb
                }
                ThreadRollbackStage::DeleteTcb => {
                    io.delete_tcb(self.tcb)
                        .map_err(|status| ThreadRollbackError::Backend { stage, status })?;
                    self.tcb = 0;
                    ThreadRollbackStage::RevokeMemoryAccess
                }
                ThreadRollbackStage::RevokeMemoryAccess => {
                    io.revoke_memory_access(self.id)
                        .map_err(|status| ThreadRollbackError::Backend { stage, status })?;
                    ThreadRollbackStage::Aliases
                }
                ThreadRollbackStage::Aliases
                | ThreadRollbackStage::Frames
                | ThreadRollbackStage::Mechanism => {
                    let (kind, next) = match stage {
                        ThreadRollbackStage::Aliases => (
                            ThreadRollbackResourceKind::Alias,
                            ThreadRollbackStage::Mechanism,
                        ),
                        ThreadRollbackStage::Frames => (
                            ThreadRollbackResourceKind::Frame,
                            ThreadRollbackStage::FinishMemoryTransfers,
                        ),
                        _ => (
                            ThreadRollbackResourceKind::Mechanism,
                            ThreadRollbackStage::Frames,
                        ),
                    };
                    for entry in &mut self.resources {
                        let resource = entry.resource;
                        if resource.cap != 0 && resource.kind == kind {
                            if kind != ThreadRollbackResourceKind::Mechanism && !entry.unmapped {
                                io.unmap_resource(resource).map_err(|status| {
                                    ThreadRollbackError::Backend { stage, status }
                                })?;
                                entry.unmapped = true;
                            }
                            if kind != ThreadRollbackResourceKind::Frame && !entry.deleted {
                                io.delete_resource(resource).map_err(|status| {
                                    ThreadRollbackError::Backend { stage, status }
                                })?;
                                entry.deleted = true;
                            }
                            io.recycle_resource(resource)
                                .map_err(|status| ThreadRollbackError::Backend { stage, status })?;
                            entry.resource.cap = 0;
                        }
                    }
                    next
                }
                ThreadRollbackStage::FinishMemoryTransfers => {
                    io.finish_memory_transfers(self.id)
                        .map_err(|status| ThreadRollbackError::Backend { stage, status })?;
                    ThreadRollbackStage::Commit
                }
                ThreadRollbackStage::Commit => {
                    io.commit_rollback(self.id);
                    ThreadRollbackStage::Complete
                }
                ThreadRollbackStage::Complete => return Ok(()),
            };
            self.stage = next;
        }
    }
}

#[cfg(test)]
#[path = "thread_rollback_tests.rs"]
mod tests;
