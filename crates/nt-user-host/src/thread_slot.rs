//! In-place ownership for published runtimes and retry-retained unpublished cleanup.
use crate::thread_binding::{admit_thread_binding, ThreadBinding};
use crate::thread_pending::PendingThreadRuntime;
use crate::thread_publication::{PreparedThreadPublication, ThreadPublicationSlot};
use crate::thread_rollback::{
    construction_rollback_id, ThreadRollbackError, ThreadRollbackId, ThreadRollbackIdentity,
    ThreadRollbackIo, ThreadRollbackResource,
};

pub trait RuntimeIdentity {
    type Role: Copy + Eq;
    fn binding(&self) -> ThreadBinding<Self::Role>;
    fn publication(&self) -> &ThreadPublicationSlot;
}

/// Adapter for moving a constructor's complete partial inventory into its original reservation.
/// Partial payloads must retain all allocated slots, object caps and memory/alias owners, including
/// failed allocations. Journal reconciliation is a separate, later, fallible operation.
pub trait RuntimeConstruction: RuntimeIdentity {
    type Partial;
    /// Original reservation captured before construction, not a replacement runtime identity.
    fn construction_binding(partial: &Self::Partial) -> ThreadBinding<Self::Role>;
    /// None means no TCB object exists. An allocated empty slot belongs in the partial inventory,
    /// not here. Some must name a real TCB, even if it has not yet been configured or resumed.
    fn construction_tcb(partial: &Self::Partial) -> Option<u64>;
    /// Read-only, allocation-free validation of failed-memory slot versus retained live owners.
    fn validate_construction(partial: &Self::Partial) -> Result<(), ThreadRollbackError>;
    fn publication_mut(&mut self) -> &mut ThreadPublicationSlot;
    /// Clear only the copied TCB projection after the sealed actor acknowledges its deletion,
    /// before the empty slot is recycled. Accept the exact expected cap or the already-cleared
    /// reservation sentinel (1), and leave identity, reservations and memory untouched. Rejection
    /// must not mutate anything; retries after a failed recycle must be idempotent. No allocation,
    /// backend operation or reentry is allowed here.
    fn clear_retired_tcb_projection(&mut self, expected_cap: u64) -> Result<(), u32>;
    /// Infallible, allocation-free ownership move with no backend calls or reentrancy. Preserve
    /// identity, reservations and the publication slot; update binding.tcb to the partial TCB, or
    /// keep the unbuilt reservation sentinel when absent. Preserve any resource inventory already
    /// owned by the original row as well. Do not destroy/release any resources.
    /// Return the mechanism inventory and failed-memory slot to the same pending row's sealed
    /// retirement actor. Retain immutable coverage, not a second mutable slot owner, in the payload.
    fn retain_partial(
        &mut self,
        partial: Self::Partial,
    ) -> (
        crate::thread_construction::ThreadConstructionInventory,
        Option<crate::thread_construction::FailedMemorySlot>,
    );
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
    Publication(crate::thread_publication::PublicationError),
    Cleanup(ThreadRollbackError),
    Retirement(crate::thread_retirement::RetirementError),
    MemoryHandoff(crate::thread_pending::MemoryHandoffError),
}

impl<R: RuntimeConstruction> ThreadRuntimeSlot<R> {
    /// Consume the exact construction ticket and partial inventory into this pre-reserved row.
    /// All rejection happens before mutation and returns both owners intact. Success allocates
    /// nothing, reserves no new attempt ID, and immediately enables the existing pending guards.
    pub fn retain_failed_construction(
        &mut self,
        ticket: PreparedThreadPublication<ThreadBinding<R::Role>>,
        partial: R::Partial,
    ) -> Result<
        ThreadRollbackId,
        (
            SlotError,
            PreparedThreadPublication<ThreadBinding<R::Role>>,
            R::Partial,
        ),
    > {
        let validate = || {
            if self.is_pending() {
                return Err(SlotError::AlreadyPending);
            }
            let runtime = self.owner().ok_or(SlotError::Vacant)?;
            let binding = runtime.binding();
            runtime
                .publication()
                .validate(&ticket, &binding)
                .map_err(SlotError::Publication)?;
            if binding.tcb != 1 || admit_thread_binding(binding, []).is_err() {
                return Err(SlotError::InvalidBinding);
            }
            if R::construction_binding(&partial) != binding {
                return Err(SlotError::OwnerChanged);
            }
            let reservations = binding.reservations.ok_or(SlotError::MissingReservations)?;
            let tcb = R::construction_tcb(&partial);
            if tcb.is_some_and(|cap| cap <= 1) {
                return Err(SlotError::Cleanup(ThreadRollbackError::InvalidCapability));
            }
            R::validate_construction(&partial).map_err(SlotError::Cleanup)?;
            let id = construction_rollback_id(
                ThreadRollbackIdentity {
                    pi: binding.pi,
                    pid: binding.process.pid,
                    process_generation: binding.process.generation,
                    tid: binding.tid,
                },
                &ticket,
            )
            .map_err(SlotError::Cleanup)?;
            Ok((binding, reservations, tcb, id))
        };
        let (binding, reservations, tcb, id) = match validate() {
            Ok(validated) => validated,
            Err(error) => return Err((error, ticket, partial)),
        };
        let State::Published(mut runtime) = core::mem::replace(&mut self.state, State::Vacant)
        else {
            unreachable!("construction ticket validated its published reservation");
        };
        if runtime.publication_mut().finish(ticket, &binding).is_err() {
            unreachable!("validated exclusive construction ticket");
        }
        let (inventory, memory_slot) = runtime.retain_partial(partial);
        assert_eq!(
            inventory.live_tcb(),
            tcb,
            "handoff preserves the validated construction TCB"
        );
        self.state = State::Pending(PendingThreadRuntime::retain_construction(
            id,
            inventory,
            memory_slot,
            reservations,
            runtime,
        ));
        Ok(id)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadIngressError {
    UnknownBadge,
    Pending,
    Publishing,
    Unbuilt,
    ProcessChanged,
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

    /// Admit only the exact published caller under its current process authority. Ownership
    /// visibility must never provide an alternate dispatch route for a pending runtime.
    pub fn admit_ingress(
        &self,
        badge: u64,
        current_process: Option<crate::process_identity::ProcessIdentity>,
    ) -> Result<&R, ThreadIngressError> {
        let runtime = self.owner().ok_or(ThreadIngressError::UnknownBadge)?;
        let binding = runtime.binding();
        if binding.badge != badge {
            return Err(ThreadIngressError::UnknownBadge);
        }
        if self.is_pending() {
            return Err(ThreadIngressError::Pending);
        }
        if runtime.publication().is_busy() {
            return Err(ThreadIngressError::Publishing);
        }
        if binding.tcb <= 1 {
            return Err(ThreadIngressError::Unbuilt);
        }
        if current_process != Some(binding.process) {
            return Err(ThreadIngressError::ProcessChanged);
        }
        Ok(runtime)
    }

    pub fn ordinary_mut(&mut self) -> Option<&mut R> {
        match &mut self.state {
            State::Published(runtime) if !runtime.publication().is_busy() => Some(runtime),
            _ => None,
        }
    }

    /// Read-only eligibility for ordinary extraction. Callers deciding whether to release an
    /// empty reservation must consult the slot, not a copied runtime that hides pending state.
    pub fn releasable(&self) -> Option<&R> {
        match &self.state {
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

    pub fn commit_memory_handoff(&mut self, expected: ThreadRollbackId) -> Result<(), SlotError>
    where
        R: crate::thread_pending::RuntimeMemoryHandoff,
    {
        self.pending_mut_exact(expected)?
            .commit_memory_handoff(expected)
            .map_err(SlotError::MemoryHandoff)
    }

    pub fn advance_cleanup_with<'a, T: ThreadRollbackIo>(
        &'a mut self,
        expected: ThreadRollbackId,
        factory: impl FnOnce(&'a R) -> T,
    ) -> Result<(), SlotError> {
        self.pending_mut_exact(expected)?
            .advance_with(factory)
            .map_err(SlotError::Cleanup)
    }

    /// The adapter must prepare complete external journals/exclusions before invoking this actor.
    /// This does not free thread memory or release reservations, even when all mechanisms retire.
    pub fn advance_construction_retirement(
        &mut self,
        expected: ThreadRollbackId,
        io: &mut impl crate::thread_retirement::ThreadRetirementIo,
    ) -> Result<(), SlotError>
    where
        R: RuntimeConstruction,
    {
        self.pending_mut_exact(expected)?
            .advance_construction_retirement(io)
            .map_err(SlotError::Retirement)
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
