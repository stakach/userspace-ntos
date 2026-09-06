//! Checked ownership for a registered thread whose Ps/handle publication never committed.
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadRollbackIdentity {
    pub pi: usize,
    pub pid: u32,
    pub process_generation: u64,
    pub tid: u64,
}

/// Exact pending owner. Pooled TIDs can recur within the same process generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadRollbackId {
    identity: ThreadRollbackIdentity,
    attempt: u64,
}

impl ThreadRollbackId {
    pub fn identity(self) -> ThreadRollbackIdentity {
        self.identity
    }
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
    /// other threads, refaults and native copies from introducing new aliases. This callback may
    /// unmap listed resources, but must never delete/recycle their slots: later stages own those
    /// releases. Any external aliases it releases require a disjoint, retry-owned journal.
    fn revoke_memory_access(&mut self, id: ThreadRollbackId) -> Result<(), u32>;
    /// Release exactly this capability. Alias and mechanism deletion precede frame recycling.
    /// Frame cleanup must checked-unmap the owner's own mapping before recycling physical memory,
    /// and reserve free-list bookkeeping before losing ownership metadata. A successful
    /// release also clears every mirrored registry/runtime reference to that capability atomically;
    /// failure retains the capability and any sub-operation progress in the backend's exact owner.
    fn release_resource(&mut self, resource: ThreadRollbackResource) -> Result<(), u32>;
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
    resources: Vec<ThreadRollbackResource>,
}

impl ThreadRollback {
    pub fn prepare(
        identity: ThreadRollbackIdentity,
        tcb: u64,
        resources: &[ThreadRollbackResource],
    ) -> Result<Self, ThreadRollbackError> {
        if identity.pid == 0 || identity.tid == 0 || identity.process_generation == 0 {
            return Err(ThreadRollbackError::InvalidIdentity);
        }
        if tcb <= 1 {
            return Err(ThreadRollbackError::InvalidCapability);
        }
        let mut owned: Vec<ThreadRollbackResource> = Vec::new();
        owned
            .try_reserve(resources.len())
            .map_err(|_| ThreadRollbackError::InsufficientResources)?;
        for &resource in resources {
            // Zero is the existing runtime resource representation for an absent capability.
            if resource.cap == 0 {
                continue;
            }
            if resource.cap == tcb {
                return Err(ThreadRollbackError::ConflictingOwnership);
            }
            if let Some(existing) = owned.iter().find(|entry| entry.cap == resource.cap) {
                if existing.kind != resource.kind {
                    return Err(ThreadRollbackError::ConflictingOwnership);
                }
            } else {
                owned.push(resource);
            }
        }
        Ok(Self {
            id: ThreadRollbackId {
                identity,
                attempt: allocate_attempt(&NEXT_ATTEMPT)?,
            },
            tcb,
            stage: ThreadRollbackStage::Suspend,
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
            .copied()
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
                            ThreadRollbackStage::Commit,
                        ),
                        _ => (
                            ThreadRollbackResourceKind::Mechanism,
                            ThreadRollbackStage::Frames,
                        ),
                    };
                    for resource in &mut self.resources {
                        if resource.cap != 0 && resource.kind == kind {
                            io.release_resource(*resource)
                                .map_err(|status| ThreadRollbackError::Backend { stage, status })?;
                            resource.cap = 0;
                        }
                    }
                    next
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
