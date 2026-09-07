//! In-place ownership for published runtimes and retry-retained unpublished cleanup.
use crate::thread_binding::{admit_thread_binding, ThreadBinding};
use crate::thread_pending::PendingThreadRuntime;
use crate::thread_publication::{PreparedThreadPublication, ThreadPublicationSlot};
use crate::thread_rollback::{
    ThreadRollbackError, ThreadRollbackId, ThreadRollbackIdentity, ThreadRollbackIo,
    ThreadRollbackResource,
};

pub trait RuntimeIdentity {
    type Role: Copy + Eq;
    fn binding(&self) -> ThreadBinding<Self::Role>;
    fn publication(&self) -> &ThreadPublicationSlot;
}

enum State<R> {
    Vacant,
    Published(R),
    Pending(PendingThreadRuntime<R>),
}

/// The slot is allocated with the runtime table before construction. It has no mutable owner
/// projection or replace/take operation for pending state. Native dispatch and memory exclusions
/// still need to consult this state; storing it alone cannot establish those external guards.
pub struct ThreadRuntimeSlot<R> {
    state: State<R>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotError {
    Vacant,
    Busy,
    AlreadyPending,
    NotPending,
    MissingReservations,
    OwnerChanged,
    InvalidBinding,
    Cleanup(ThreadRollbackError),
}

impl<R: RuntimeIdentity> ThreadRuntimeSlot<R> {
    pub const fn empty() -> Self {
        Self {
            state: State::Vacant,
        }
    }

    pub fn is_empty(&self) -> bool {
        matches!(self.state, State::Vacant)
    }
    pub fn is_pending(&self) -> bool {
        matches!(self.state, State::Pending(_))
    }

    /// Ownership remains visible throughout pending cleanup, including after TCB deletion.
    pub fn owner(&self) -> Option<&R> {
        match &self.state {
            State::Vacant => None,
            State::Published(runtime) => Some(runtime),
            State::Pending(owner) => Some(owner.runtime()),
        }
    }

    pub fn is_protected(&self) -> bool {
        self.is_pending()
            || self
                .owner()
                .is_some_and(|runtime| runtime.publication().is_busy())
    }

    pub fn executable(&self) -> Option<&R> {
        match &self.state {
            State::Published(runtime)
                if runtime.binding().tcb > 1 && !runtime.publication().is_busy() =>
            {
                Some(runtime)
            }
            _ => None,
        }
    }

    pub fn ordinary_mut(&mut self) -> Option<&mut R> {
        match &mut self.state {
            State::Published(runtime) if !runtime.publication().is_busy() => Some(runtime),
            _ => None,
        }
    }

    /// Only the construction ticket may access a busy published row. The caller must finish that
    /// exact ticket before changing its binding, just as in ThreadPublicationSlot's contract.
    pub fn publishing_mut(
        &mut self,
        ticket: &PreparedThreadPublication<ThreadBinding<R::Role>>,
    ) -> Option<&mut R> {
        match &mut self.state {
            State::Published(runtime) => {
                runtime
                    .publication()
                    .validate(ticket, &runtime.binding())
                    .ok()?;
                Some(runtime)
            }
            _ => None,
        }
    }

    pub fn insert(&mut self, runtime: R) -> Result<(), R> {
        if !self.is_empty()
            || admit_thread_binding(runtime.binding(), []).is_err()
            || runtime.publication().is_busy()
        {
            return Err(runtime);
        }
        self.state = State::Published(runtime);
        Ok(())
    }

    pub fn release_published(&mut self) -> Option<R> {
        if self.is_protected() {
            return None;
        }
        match core::mem::replace(&mut self.state, State::Vacant) {
            State::Published(runtime) => Some(runtime),
            State::Vacant => None,
            State::Pending(_) => unreachable!("pending slot release is guarded"),
        }
    }

    /// Derive cleanup identity from the retained payload, never independent caller metadata.
    /// No journal/allocation or backend effect occurs. Failure restores the original published row.
    pub fn begin_pending(
        &mut self,
        expected: ThreadBinding<R::Role>,
    ) -> Result<ThreadRollbackId, SlotError> {
        if self.is_pending() {
            return Err(SlotError::AlreadyPending);
        }
        let runtime = self.owner().ok_or(SlotError::Vacant)?;
        if runtime.publication().is_busy() {
            return Err(SlotError::Busy);
        }
        let binding = runtime.binding();
        if binding != expected {
            return Err(SlotError::OwnerChanged);
        }
        if admit_thread_binding(binding, []).is_err() {
            return Err(SlotError::InvalidBinding);
        }
        let reservations = binding.reservations.ok_or(SlotError::MissingReservations)?;
        let identity = ThreadRollbackIdentity {
            pi: binding.pi,
            pid: binding.process.pid,
            process_generation: binding.process.generation,
            tid: binding.tid,
        };
        let runtime = self.release_published().expect("validated published owner");
        match PendingThreadRuntime::retain(identity, binding.tcb, reservations, runtime) {
            Ok(owner) => {
                let id = owner.id();
                self.state = State::Pending(owner);
                Ok(id)
            }
            Err((error, runtime)) => {
                self.state = State::Published(runtime);
                Err(SlotError::Cleanup(error))
            }
        }
    }

    pub fn pending(&self) -> Option<&PendingThreadRuntime<R>> {
        match &self.state {
            State::Pending(owner) => Some(owner),
            _ => None,
        }
    }

    pub fn prepare_cleanup(
        &mut self,
        expected: ThreadRollbackId,
        resources: &[ThreadRollbackResource],
    ) -> Result<(), SlotError> {
        self.pending_mut_exact(expected)?
            .prepare_journal(resources)
            .map_err(SlotError::Cleanup)
    }

    pub fn advance_cleanup(
        &mut self,
        expected: ThreadRollbackId,
        io: &mut impl ThreadRollbackIo,
    ) -> Result<(), SlotError> {
        self.pending_mut_exact(expected)?
            .advance(io)
            .map_err(SlotError::Cleanup)
    }

    fn pending_mut_exact(
        &mut self,
        expected: ThreadRollbackId,
    ) -> Result<&mut PendingThreadRuntime<R>, SlotError> {
        match &mut self.state {
            State::Pending(owner) if owner.id() == expected => Ok(owner),
            State::Pending(_) => Err(SlotError::OwnerChanged),
            _ => Err(SlotError::NotPending),
        }
    }

    /// Final bookkeeping extraction only; the payload must not be republished after its caps die.
    pub fn take_retired_payload(&mut self, expected: ThreadRollbackId) -> Option<R> {
        if self.pending().is_none_or(|owner| owner.id() != expected) {
            return None;
        }
        let State::Pending(owner) = core::mem::replace(&mut self.state, State::Vacant) else {
            unreachable!("pending state checked");
        };
        match owner.try_into_retired_payload() {
            Ok(runtime) => Some(runtime),
            Err(owner) => {
                self.state = State::Pending(owner);
                None
            }
        }
    }
}

#[cfg(test)]
#[path = "thread_slot_tests.rs"]
mod tests;
