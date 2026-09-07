//! Retained runtime ownership before fallible rollback-journal construction.
use crate::thread_binding::ThreadRuntimeReservations;
use crate::thread_rollback::{
    new_rollback_id, ThreadRollback, ThreadRollbackError, ThreadRollbackId, ThreadRollbackIdentity,
    ThreadRollbackIo, ThreadRollbackResource, ThreadRollbackStage,
};

/// Non-cloneable pending owner. Admission allocates no journal, and every preparation/cleanup
/// failure retains the runtime payload and exact reservation identity. Keep it in durable storage
/// until completion; dropping it is not a backend cleanup operation or reservation release.
///
/// The native adapter must keep its identity visible to ownership/collision/retirement checks,
/// while refusing runnable/control/badge dispatch and ordinary release. Those table guards and
/// memory-access exclusions are not implemented by storing this host-side object alone.
#[must_use = "retain the pending runtime and its reservations until checked cleanup completes"]
pub struct PendingThreadRuntime<R> {
    id: ThreadRollbackId,
    tcb: Option<u64>,
    runtime: R,
    reservations: ThreadRuntimeReservations,
    rollback: Option<ThreadRollback>,
}

impl<R> PendingThreadRuntime<R> {
    /// Identity failure returns the original payload; no TCB/capability/commitment effect occurs.
    pub fn retain(
        identity: ThreadRollbackIdentity,
        tcb: u64,
        reservations: ThreadRuntimeReservations,
        runtime: R,
    ) -> Result<Self, (ThreadRollbackError, R)> {
        if tcb <= 1 {
            return Err((ThreadRollbackError::InvalidCapability, runtime));
        }
        let id = match new_rollback_id(identity) {
            Ok(id) => id,
            Err(error) => return Err((error, runtime)),
        };
        Ok(Self {
            id,
            tcb: Some(tcb),
            runtime,
            reservations,
            rollback: None,
        })
    }

    /// The slot has validated and consumed this exact publication attempt. Keep the original
    /// runtime and its attached partial construction in-place before any journal allocation.
    pub(crate) fn retain_construction(
        id: ThreadRollbackId,
        tcb: Option<u64>,
        reservations: ThreadRuntimeReservations,
        runtime: R,
    ) -> Self {
        Self {
            id,
            tcb,
            runtime,
            reservations,
            rollback: None,
        }
    }

    pub fn id(&self) -> ThreadRollbackId {
        self.id
    }

    pub fn runtime(&self) -> &R {
        &self.runtime
    }

    pub fn reservations(&self) -> ThreadRuntimeReservations {
        self.reservations
    }

    pub fn cleanup(&self) -> Option<&ThreadRollback> {
        self.rollback.as_ref()
    }

    /// Only one journal may attach to this attempt. Failed inventory validation/allocation may
    /// retry on this same pending owner, without recreating its identity or releasing any holds.
    pub fn prepare_journal(
        &mut self,
        resources: &[ThreadRollbackResource],
    ) -> Result<(), ThreadRollbackError> {
        self.prepare_journal_with(resources, ThreadRollback::prepare_optional_tcb)
    }

    fn prepare_journal_with(
        &mut self,
        resources: &[ThreadRollbackResource],
        prepare: impl FnOnce(
            ThreadRollbackId,
            Option<u64>,
            &[ThreadRollbackResource],
        ) -> Result<ThreadRollback, ThreadRollbackError>,
    ) -> Result<(), ThreadRollbackError> {
        if self.rollback.is_some() {
            return Err(ThreadRollbackError::AlreadyPrepared);
        }
        let rollback = prepare(self.id, self.tcb, resources)?;
        self.rollback = Some(rollback);
        Ok(())
    }

    pub fn advance(&mut self, io: &mut impl ThreadRollbackIo) -> Result<(), ThreadRollbackError> {
        self.rollback
            .as_mut()
            .ok_or(ThreadRollbackError::NotPrepared)?
            .advance(io)
    }

    /// Extract retirement bookkeeping only after the backend acknowledges final target commit.
    /// The original payload is not a runnable/reusable runtime: it may still describe released
    /// capabilities. The adapter must clear any mirrored references during checked release and
    /// must not republish this payload. Rejection returns the complete pending owner intact.
    pub fn try_into_retired_payload(self) -> Result<R, Self> {
        if self.rollback.as_ref().map(ThreadRollback::stage) != Some(ThreadRollbackStage::Complete)
        {
            return Err(self);
        }
        Ok(self.runtime)
    }
}

#[cfg(test)]
#[path = "thread_pending_tests.rs"]
mod tests;
