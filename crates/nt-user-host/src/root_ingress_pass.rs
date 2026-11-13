//! One ordinary root event may run while a component's exact receive parent is held.
//! Physical Reply parking and parent restoration remain native-owned effects.

use crate::thread_binding::ThreadBinding;
use nt_component_suspension::{
    ExternalAdmissionKey, ExternalIngress, ExternalSettlement, LaneDispatchIdentity,
    NestedExecutionIdentity, NestedExecutionScope, RootIngressCheckpoint,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassError {
    WrongChild,
    WrongParent,
    AlreadyBound,
    Unbound,
    InvalidPhase,
    Unsettled,
    Consumed,
}

/// Where a positively acknowledged and freed child Reply belongs at this exact phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootIngressSettlementDisposition {
    /// The parent has not begun restoration; this receipt may become its checkpoint.
    Checkpoint,
    /// A positive park checkpoint already entered restoration; retain for the result owner.
    RetainForResult,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Prepared,
    Bound,
    /// Native may have entered Reply-pool import. No refusal can authorize a second attempt.
    ImportEnteredUnknown,
    Delivered,
    /// Native may have entered the park effect. Only the exact move-only pre-effect refusal
    /// receipt can reopen this attempt; a timeout or uncertain result cannot.
    ParkEnteredUnknown,
    Checkpointed,
    RestoreEntered,
    /// A route refusal sealed this prepared Call before any root child delivery.
    UndeliveredUnwindEntered,
}

/// Exact one-event checkpoint. It never owns the child Reply or the physical parent hold.
/// Native retains both and supplies positive observations after their corresponding effects.
#[must_use = "retain the exact parent and child until a checkpoint permits restoration"]
#[derive(Debug)]
pub struct RootIngressPass<R> {
    child: ThreadBinding<R>,
    admission: ExternalAdmissionKey,
    parent: Option<NestedExecutionIdentity>,
    phase: Phase,
    settlement: Option<ExternalSettlement>,
    parked: bool,
    import_attempt_generation: u64,
    park_attempt_generation: u64,
}

/// One selected Reply import attempt. An uncertain effect leaves the pass sealed.
#[must_use = "retain until the native import has a positive or certified no-effect outcome"]
#[derive(Debug)]
pub struct RootIngressImportAttempt<R> {
    child: ThreadBinding<R>,
    admission: ExternalAdmissionKey,
    parent: NestedExecutionIdentity,
    generation: u64,
}

#[must_use = "consume only to abort the matching pre-effect import attempt"]
#[derive(Debug)]
pub struct RootReplyImportNoEffect<R>(RootIngressImportAttempt<R>);

impl<R> RootIngressImportAttempt<R> {
    /// # Safety
    /// Native must have received an exact no-effect import refusal, including completed
    /// rollback of any inserted Reply-pool cap, before issuing this receipt.
    pub unsafe fn after_no_effect_native_refusal(self) -> RootReplyImportNoEffect<R> {
        RootReplyImportNoEffect(self)
    }
}

/// The one physical park attempt authorized by this pass. Its generation prevents an older
/// refusal from reopening a later attempt for the same retained Call.
#[must_use = "transfer this attempt to the exact native park or retain it on uncertainty"]
#[derive(Debug)]
pub struct RootIngressParkAttempt<R> {
    child: ThreadBinding<R>,
    admission: ExternalAdmissionKey,
    parent: NestedExecutionIdentity,
    generation: u64,
}

#[must_use = "consume only to abort the matching pre-effect park attempt"]
#[derive(Debug)]
pub struct RootReplyParkNoEffect<R>(RootIngressParkAttempt<R>);

#[must_use = "consume only to acknowledge the matching positive native park"]
#[derive(Debug)]
pub struct RootReplyParkCommitted<R>(RootIngressParkAttempt<R>);

impl<R: Copy> RootIngressParkAttempt<R> {
    pub fn reply(&self) -> u64 { self.admission.reply() }

    /// # Safety
    /// Native must have observed `Ok(())` from RootReplyPark::try_commit for this attempt.
    pub unsafe fn after_positive_native_park(self) -> RootReplyParkCommitted<R> {
        RootReplyParkCommitted(self)
    }

    /// # Safety
    /// Native must have either rejected a prepared park whose active Reply differs from this
    /// attempt before calling `try_commit`, or received `Err` from `try_commit` before any pool
    /// or main-selector mutation. A later attempt's refusal cannot certify this one.
    pub unsafe fn after_no_effect_native_refusal(self) -> RootReplyParkNoEffect<R> {
        RootReplyParkNoEffect(self)
    }
}

/// One untouched child Call sealed against later binding or delivery. Native retains this in
/// the exact physical parent row until restoration acknowledges or remains uncertain.
#[must_use = "retain until the exact parent restoration positively completes"]
#[derive(Debug)]
pub struct UndeliveredRootIngress<R> {
    child: ThreadBinding<R>,
    admission: ExternalAdmissionKey,
}

/// One restoration attempt. A parked child remains independently owned by its ingress row.
#[must_use = "retain this permit through the physical parent restoration attempt"]
#[derive(Debug)]
pub struct RootIngressRestorePermit<R> {
    child: ThreadBinding<R>,
    admission: ExternalAdmissionKey,
    parent: NestedExecutionIdentity,
    settlement: Option<ExternalSettlement>,
    checkpoint: RootIngressCheckpoint,
}

/// Native-issued positive observation after the exact parent restoration completed. The pure
/// contract cannot observe the physical effect; only the retained native parent owner may issue
/// this token after `restore_or_retain` acknowledges success.
#[must_use = "retain this receipt until the parked child's result is delivered"]
#[derive(Debug)]
pub struct RootIngressRestored<R> {
    child: ThreadBinding<R>,
    admission: ExternalAdmissionKey,
    parent: NestedExecutionIdentity,
    parked_child: bool,
    settlement: Option<ExternalSettlement>,
}

impl<R: Copy + Eq> RootIngressPass<R> {
    pub fn prepare<M>(
        call: &ExternalIngress<M>,
        child: ThreadBinding<R>,
    ) -> Result<Self, PassError> {
        if child.tcb <= 1
            || child.tid == 0
            || !child.process.is_valid()
            || call.executor() != child.tcb
            || !call.can_park()
        {
            return Err(PassError::WrongChild);
        }
        Ok(Self {
            child,
            admission: call.admission_key(),
            parent: None,
            phase: Phase::Prepared,
            settlement: None,
            parked: false,
            import_attempt_generation: 0,
            park_attempt_generation: 0,
        })
    }

    pub fn admission_key(&self) -> ExternalAdmissionKey {
        self.admission
    }

    pub fn child(&self) -> ThreadBinding<R> {
        self.child
    }

    /// Seal a prepared ordinary Call before its dependent route was admitted. This does not
    /// restore its physical parent or grant cancellation of the retained Call.
    pub fn begin_undelivered_unwind<M>(
        &mut self, child: ThreadBinding<R>, call: &ExternalIngress<M>,
    ) -> Result<UndeliveredRootIngress<R>, PassError> {
        self.exact_child(child, call)?;
        if self.phase == Phase::UndeliveredUnwindEntered {
            return Err(PassError::Consumed);
        }
        if self.phase != Phase::Prepared || !call.can_park() {
            return Err(PassError::InvalidPhase);
        }
        self.phase = Phase::UndeliveredUnwindEntered;
        Ok(UndeliveredRootIngress { child, admission: self.admission })
    }

    pub fn is_undelivered_unwind(&self, token: &UndeliveredRootIngress<R>) -> bool {
        self.phase == Phase::UndeliveredUnwindEntered
            && self.child == token.child && self.admission == token.admission
    }

    pub fn bind_parent(
        &mut self,
        scope: &NestedExecutionScope,
        dispatch: LaneDispatchIdentity,
    ) -> Result<(), PassError> {
        if self.phase != Phase::Prepared {
            return Err(PassError::AlreadyBound);
        }
        if scope.is_consumed() || scope.dispatch() != dispatch {
            return Err(PassError::WrongParent);
        }
        self.parent = Some(scope.identity());
        self.phase = Phase::Bound;
        Ok(())
    }

    fn exact_child<M>(
        &self,
        child: ThreadBinding<R>,
        call: &ExternalIngress<M>,
    ) -> Result<(), PassError> {
        if child != self.child || call.admission_key() != self.admission {
            return Err(PassError::WrongChild);
        }
        Ok(())
    }

    /// Record one import attempt before the native Reply-pool effect. If the effect is refused
    /// or uncertain, the pass remains sealed unless an exact no-effect receipt reopens it.
    pub fn begin_import<M>(
        &mut self,
        child: ThreadBinding<R>,
        call: &ExternalIngress<M>,
    ) -> Result<RootIngressImportAttempt<R>, PassError> {
        self.exact_child(child, call)?;
        if matches!(self.phase, Phase::ImportEnteredUnknown | Phase::Delivered) {
            return Err(PassError::Consumed);
        }
        if self.phase != Phase::Bound || !call.can_park() {
            return Err(PassError::InvalidPhase);
        }
        let generation = self.import_attempt_generation.checked_add(1)
            .ok_or(PassError::Consumed)?;
        let parent = self.parent.ok_or(PassError::Unbound)?;
        self.import_attempt_generation = generation;
        self.phase = Phase::ImportEnteredUnknown;
        Ok(RootIngressImportAttempt {
            child, admission: self.admission, parent, generation,
        })
    }

    /// Reopen only the exact selected attempt whose native import was proved to have no effect.
    /// Wrong identity returns the receipt so the native owner cannot accidentally lose it.
    pub fn abort_import_before_effect<M>(
        &mut self,
        child: ThreadBinding<R>,
        call: &ExternalIngress<M>,
        parent: NestedExecutionIdentity,
        no_effect: RootReplyImportNoEffect<R>,
    ) -> Result<(), (PassError, RootReplyImportNoEffect<R>)> {
        let attempt = &no_effect.0;
        let error = if child != self.child || call.admission_key() != self.admission
            || attempt.child != child || attempt.admission != self.admission
        {
            Some(PassError::WrongChild)
        } else if self.parent != Some(parent) || attempt.parent != parent {
            Some(PassError::WrongParent)
        } else if self.phase != Phase::ImportEnteredUnknown
            || self.import_attempt_generation != attempt.generation || !call.can_park()
        {
            Some(PassError::InvalidPhase)
        } else {
            None
        };
        if let Some(error) = error { return Err((error, no_effect)); }
        self.phase = Phase::Bound;
        Ok(())
    }

    /// Positive observation after the exact retained Call became the root delivery.
    ///
    /// # Safety
    /// Native must have positively imported the child's physical Reply into the root owner.
    /// A false or uncertain import callback cannot issue this observation.
    pub unsafe fn deliver<M>(
        &mut self,
        child: ThreadBinding<R>,
        call: &ExternalIngress<M>,
    ) -> Result<(), PassError> {
        self.exact_child(child, call)?;
        if self.phase != Phase::ImportEnteredUnknown || !call.can_park() {
            return Err(PassError::InvalidPhase);
        }
        self.phase = Phase::Delivered;
        Ok(())
    }

    /// Classify an exact positive Reply settlement before native send or checked Free.
    pub fn settlement_disposition(
        &self,
        child: ThreadBinding<R>,
        admission: ExternalAdmissionKey,
    ) -> Result<(NestedExecutionIdentity, RootIngressSettlementDisposition), PassError> {
        if child != self.child || admission != self.admission {
            return Err(PassError::WrongChild);
        }
        let parent = self.parent.ok_or(PassError::Unbound)?;
        let disposition = match self.phase {
            Phase::Delivered | Phase::ParkEnteredUnknown => {
                RootIngressSettlementDisposition::Checkpoint
            }
            Phase::Checkpointed if self.parked && self.settlement.is_none() => {
                RootIngressSettlementDisposition::Checkpoint
            }
            Phase::RestoreEntered if self.parked && self.settlement.is_none() => {
                RootIngressSettlementDisposition::RetainForResult
            }
            _ => return Err(PassError::InvalidPhase),
        };
        Ok((parent, disposition))
    }

    /// A positive Reply acknowledgement and checked Free can supersede an earlier positive
    /// park checkpoint until parent restoration begins. A receipt after that stays native-owned.
    pub fn acknowledge_settlement(
        &mut self,
        child: ThreadBinding<R>,
        settlement: ExternalSettlement,
    ) -> Result<(), (PassError, ExternalSettlement)> {
        match self.settlement_disposition(child, settlement.admission_key()) {
            Ok((_, RootIngressSettlementDisposition::Checkpoint)) => {}
            Ok((_, RootIngressSettlementDisposition::RetainForResult)) => {
                return Err((PassError::InvalidPhase, settlement));
            }
            Err(error) => return Err((error, settlement)),
        }
        self.settlement = Some(settlement);
        self.phase = Phase::Checkpointed;
        Ok(())
    }

    /// Record entry before native RootReplyPark::try_commit. An unknown effect leaves this phase
    /// sealed; only a certified no-effect refusal may authorize a new attempt.
    pub fn begin_park<M>(
        &mut self,
        child: ThreadBinding<R>,
        call: &ExternalIngress<M>,
    ) -> Result<RootIngressParkAttempt<R>, PassError> {
        self.exact_child(child, call)?;
        if self.phase != Phase::Delivered || !call.can_park() {
            return Err(PassError::InvalidPhase);
        }
        let generation = self.park_attempt_generation.checked_add(1).ok_or(PassError::Consumed)?;
        let parent = self.parent.ok_or(PassError::Unbound)?;
        self.park_attempt_generation = generation;
        self.phase = Phase::ParkEnteredUnknown;
        Ok(RootIngressParkAttempt {
            child, admission: self.admission, parent, generation,
        })
    }

    /// Reopen only the exact attempt for which native returned a pre-effect refusal receipt.
    /// A wrong receipt is returned to its owner unchanged.
    pub fn abort_park_before_effect<M>(
        &mut self,
        child: ThreadBinding<R>,
        call: &ExternalIngress<M>,
        no_effect: RootReplyParkNoEffect<R>,
    ) -> Result<(), (PassError, RootReplyParkNoEffect<R>)> {
        let attempt = &no_effect.0;
        let error = if child != self.child || call.admission_key() != self.admission
            || attempt.child != self.child || attempt.admission != self.admission {
            Some(PassError::WrongChild)
        } else if self.parent != Some(attempt.parent) {
            Some(PassError::WrongParent)
        } else if self.phase != Phase::ParkEnteredUnknown
            || attempt.generation != self.park_attempt_generation
            || self.settlement.is_some() || self.parked || !call.can_park() {
            Some(PassError::InvalidPhase)
        } else { None };
        if let Some(error) = error { return Err((error, no_effect)); }
        self.phase = Phase::Delivered;
        Ok(())
    }

    /// Native supplies this observation only after its exact RootReplyPark commit succeeded.
    /// This is not a physical receipt: the native owner still holds and verifies the Reply.
    ///
    /// # Safety
    /// The exact RootReplyPark must have positively committed. An uncertain effect cannot be
    /// promoted to a checkpoint, even if the Reply capability still appears to be present.
    pub unsafe fn acknowledge_park<M>(
        &mut self,
        child: ThreadBinding<R>,
        call: &ExternalIngress<M>,
        committed: RootReplyParkCommitted<R>,
    ) -> Result<(), (PassError, RootReplyParkCommitted<R>)> {
        let attempt = &committed.0;
        let error = if child != self.child || call.admission_key() != self.admission
            || attempt.child != self.child || attempt.admission != self.admission {
            Some(PassError::WrongChild)
        } else if self.parent != Some(attempt.parent) {
            Some(PassError::WrongParent)
        } else if self.phase != Phase::ParkEnteredUnknown
            || attempt.generation != self.park_attempt_generation || !call.can_park() {
            Some(PassError::InvalidPhase)
        } else { None };
        if let Some(error) = error { return Err((error, committed)); }
        self.parked = true;
        self.phase = Phase::Checkpointed;
        Ok(())
    }

    /// A checkpoint grants one restoration attempt; it does not settle a parked child.
    pub fn begin_restore(
        &mut self,
        scope: &NestedExecutionScope,
    ) -> Result<RootIngressRestorePermit<R>, PassError> {
        let parent = self.parent.ok_or(PassError::Unbound)?;
        if scope.is_consumed() || parent != scope.identity() {
            return Err(PassError::WrongParent);
        }
        if self.phase == Phase::RestoreEntered {
            return Err(PassError::Consumed);
        }
        if self.phase != Phase::Checkpointed {
            return Err(PassError::Unsettled);
        }
        let checkpoint = if let Some(settlement) = self.settlement.as_ref() {
            RootIngressCheckpoint::from_settlement(scope, settlement)
        } else if self.parked {
            // The only transition to `parked` is the native-only positive observation above.
            unsafe { RootIngressCheckpoint::after_park(scope, self.admission) }
        } else {
            return Err(PassError::Unsettled);
        };
        self.phase = Phase::RestoreEntered;
        Ok(RootIngressRestorePermit {
            child: self.child,
            admission: self.admission,
            parent,
            settlement: self.settlement.take(),
            checkpoint,
        })
    }
}

impl<R: Copy> UndeliveredRootIngress<R> {
    pub fn child(&self) -> ThreadBinding<R> { self.child }
    pub fn admission_key(&self) -> ExternalAdmissionKey { self.admission }
}

impl<R: Copy> RootIngressRestorePermit<R> {
    pub fn child(&self) -> ThreadBinding<R> {
        self.child
    }
    pub fn admission_key(&self) -> ExternalAdmissionKey {
        self.admission
    }
    pub fn parent(&self) -> NestedExecutionIdentity {
        self.parent
    }
    pub fn settlement(&self) -> Option<&ExternalSettlement> {
        self.settlement.as_ref()
    }
    pub fn checkpoint(&self) -> &RootIngressCheckpoint { &self.checkpoint }

    /// # Safety
    /// The native owner must first positively complete the exact physical parent restoration.
    /// A refused or uncertain restoration keeps this permit in its retained parent row.
    pub unsafe fn acknowledge_restore(self) -> RootIngressRestored<R> {
        RootIngressRestored {
            child: self.child,
            admission: self.admission,
            parent: self.parent,
            parked_child: self.settlement.is_none(),
            settlement: self.settlement,
        }
    }
}

impl<R: Copy> RootIngressRestored<R> {
    pub fn child(&self) -> ThreadBinding<R> { self.child }
    pub fn admission_key(&self) -> ExternalAdmissionKey { self.admission }
    pub fn parent(&self) -> NestedExecutionIdentity { self.parent }
    pub fn parked_child(&self) -> bool { self.parked_child }
    pub fn settlement(&self) -> Option<&ExternalSettlement> { self.settlement.as_ref() }
    pub fn take_settlement(&mut self) -> Option<ExternalSettlement> {
        self.settlement.take()
    }
}

#[cfg(test)]
#[path = "root_ingress_pass_tests.rs"]
mod tests;
