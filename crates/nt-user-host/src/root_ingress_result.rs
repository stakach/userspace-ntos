//! Exact one-shot result retained before an ordinary root Reply is parked.
//! Physical Reply parking and send/Free settlement stay with the native ingress owner.

use crate::root_ingress_pass::RootIngressRestored;
use crate::thread_binding::ThreadBinding;
use nt_component_suspension::{
    ExternalAdmissionKey, ExternalIngress, ExternalSettlement, NestedExecutionIdentity,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultError {
    WrongChild,
    WrongParent,
    AlreadyEntered,
    InvalidPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Prepared,
    /// Native may have entered the physical send. The result may not be replayed.
    SendEnteredUnknown,
    Settled,
}

/// A result payload bound to one retained hosted Call. Native stores it in the Call row before
/// parking the Reply, and retains it through any uncertain send or Free observation.
#[must_use = "retain this exact result until its physical Reply settles"]
#[derive(Debug)]
pub struct RootIngressResult<R> {
    binding: ThreadBinding<R>,
    admission: ExternalAdmissionKey,
    parent: NestedExecutionIdentity,
    info: u64,
    words: [u64; 4],
    phase: Phase,
    settlement: Option<ExternalSettlement>,
}

impl<R: Copy + Eq> RootIngressResult<R> {
    pub fn prepare<M>(
        call: &ExternalIngress<M>,
        binding: ThreadBinding<R>,
        parent: NestedExecutionIdentity,
        info: u64,
        words: [u64; 4],
    ) -> Result<Self, ResultError> {
        if binding.tcb <= 1 || binding.tid == 0 || !binding.process.is_valid()
            || call.executor() != binding.tcb || !call.can_park()
        {
            return Err(ResultError::WrongChild);
        }
        Ok(Self {
            binding,
            admission: call.admission_key(),
            parent,
            info,
            words,
            phase: Phase::Prepared,
            settlement: None,
        })
    }

    pub fn binding(&self) -> ThreadBinding<R> { self.binding }
    pub fn admission_key(&self) -> ExternalAdmissionKey { self.admission }
    pub fn parent(&self) -> NestedExecutionIdentity { self.parent }
    pub fn reply(&self) -> u64 { self.admission.reply() }
    pub fn payload(&self) -> (u64, [u64; 4]) { (self.info, self.words) }
    pub fn is_settled(&self) -> bool { self.phase == Phase::Settled }

    fn exact_child<M>(
        &self,
        binding: ThreadBinding<R>,
        call: &ExternalIngress<M>,
    ) -> Result<(), ResultError> {
        if binding != self.binding || call.admission_key() != self.admission {
            return Err(ResultError::WrongChild);
        }
        Ok(())
    }

    fn exact_checkpoint(
        &self,
        restored: &RootIngressRestored<R>,
    ) -> Result<(), ResultError> {
        if restored.child() != self.binding || restored.admission_key() != self.admission {
            return Err(ResultError::WrongChild);
        }
        if restored.parent() != self.parent { return Err(ResultError::WrongParent); }
        if !restored.parked_child() { return Err(ResultError::InvalidPhase); }
        Ok(())
    }

    /// A later durability failure changes only RAX before physical delivery has entered.
    pub fn update_status<M>(
        &mut self,
        binding: ThreadBinding<R>,
        call: &ExternalIngress<M>,
        restored: &RootIngressRestored<R>,
        status: u64,
    ) -> Result<(), ResultError> {
        self.exact_child(binding, call)?;
        self.exact_checkpoint(restored)?;
        if self.phase != Phase::Prepared || !call.can_park() {
            return Err(ResultError::InvalidPhase);
        }
        self.words[0] = status;
        Ok(())
    }

    /// Claim one delivery attempt before invoking `reply_hosted`. The payload stays retained
    /// here; an uncertain physical send cannot produce another attempt.
    pub fn begin_delivery<M>(
        &mut self,
        binding: ThreadBinding<R>,
        call: &ExternalIngress<M>,
        restored: &RootIngressRestored<R>,
    ) -> Result<(u64, [u64; 4]), ResultError> {
        self.exact_child(binding, call)?;
        self.exact_checkpoint(restored)?;
        if self.phase == Phase::SendEnteredUnknown || self.phase == Phase::Settled {
            return Err(ResultError::AlreadyEntered);
        }
        if self.phase != Phase::Prepared || !call.can_park() {
            return Err(ResultError::InvalidPhase);
        }
        self.phase = Phase::SendEnteredUnknown;
        Ok(self.payload())
    }

    /// A positive native send followed by checked Free supplies the non-forgeable settlement.
    /// A rejected receipt returns to its owner for retention.
    pub fn acknowledge_settlement(
        &mut self,
        binding: ThreadBinding<R>,
        settlement: ExternalSettlement,
    ) -> Result<(), (ResultError, ExternalSettlement)> {
        if binding != self.binding || settlement.admission_key() != self.admission {
            return Err((ResultError::WrongChild, settlement));
        }
        if self.phase != Phase::SendEnteredUnknown {
            return Err((ResultError::InvalidPhase, settlement));
        }
        self.settlement = Some(settlement);
        self.phase = Phase::Settled;
        Ok(())
    }

    /// Transfer the receipt to the native ingress row after it has retired this payload.
    pub fn take_settlement(&mut self) -> Option<ExternalSettlement> {
        if self.phase == Phase::Settled { self.settlement.take() } else { None }
    }
}

#[cfg(test)]
#[path = "root_ingress_result_tests.rs"]
mod tests;
