//! Delivery ordering for a retained provider-originated CREATE.
//!
//! This owner records irreversible boundaries. A caller may retry observation of an
//! uncertain effect, but never dispatch, publish, Reply, or backend-ACK it twice.

use crate::{FileId, IrpId};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateIdentity {
    pub file: FileId,
    pub requestor_tid: u64,
    pub major: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateTerminal {
    pub irp: Option<IrpId>,
    pub identity: CreateIdentity,
    pub status: u32,
    pub information: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Prepared,
    DispatchEntered,
    AwaitTerminal,
    Terminal,
    HandleBound,
    HandlePublished,
    ReplyEntered,
    ReplyAcknowledged,
    BackendAckEntered,
    BackendAcknowledged,
    Aborted,
    Finished,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryError {
    WrongPhase,
    WrongIdentity,
    InvalidHandle,
    Cancelled,
}

/// Supplied only when the transport has proved that a dispatched request never entered a
/// provider. An indeterminate return cannot be represented by this receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DispatchNotEnteredProof {
    ProviderNotEntered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderCreateDelivery {
    identity: CreateIdentity,
    phase: Phase,
    irp: Option<IrpId>,
    terminal: Option<CreateTerminal>,
    handle: Option<u64>,
    cancelled: bool,
    stop_acknowledged: bool,
}

impl ProviderCreateDelivery {
    pub const fn new(identity: CreateIdentity) -> Self {
        Self {
            identity,
            phase: Phase::Prepared,
            irp: None,
            terminal: None,
            handle: None,
            cancelled: false,
            stop_acknowledged: false,
        }
    }

    pub const fn phase(&self) -> Phase {
        self.phase
    }

    pub const fn identity(&self) -> CreateIdentity {
        self.identity
    }

    pub const fn irp(&self) -> Option<IrpId> {
        self.irp
    }

    pub const fn terminal(&self) -> Option<CreateTerminal> {
        self.terminal
    }

    pub const fn handle(&self) -> Option<u64> {
        self.handle
    }

    pub const fn cancelled(&self) -> bool {
        self.cancelled
    }

    /// Call before invoking a provider. There is no transition back to Prepared.
    pub fn enter_dispatch(&mut self) -> Result<(), DeliveryError> {
        if self.phase != Phase::Prepared || self.cancelled {
            return Err(DeliveryError::WrongPhase);
        }
        self.phase = Phase::DispatchEntered;
        Ok(())
    }

    pub fn abort_prepared(&mut self) -> Result<(), DeliveryError> {
        if self.phase != Phase::Prepared {
            return Err(DeliveryError::WrongPhase);
        }
        self.phase = Phase::Aborted;
        Ok(())
    }

    /// A post-dispatch abort requires an explicit transport non-entry receipt.
    pub fn abort_not_entered(
        &mut self,
        _proof: DispatchNotEnteredProof,
    ) -> Result<(), DeliveryError> {
        if self.phase != Phase::DispatchEntered {
            return Err(DeliveryError::WrongPhase);
        }
        self.phase = Phase::Aborted;
        Ok(())
    }

    /// An indeterminate dispatch without an IRP identity remains in DispatchEntered.
    pub fn retain_irp(&mut self, irp: IrpId) -> Result<(), DeliveryError> {
        if self.phase != Phase::DispatchEntered || irp.raw() == 0 {
            return Err(DeliveryError::WrongPhase);
        }
        self.irp = Some(irp);
        self.phase = Phase::AwaitTerminal;
        Ok(())
    }

    /// Repeated terminal queries are allowed; only the exact first result commits.
    pub fn observe_terminal(&mut self, terminal: CreateTerminal) -> Result<(), DeliveryError> {
        if self.phase != Phase::AwaitTerminal {
            return Err(DeliveryError::WrongPhase);
        }
        if terminal.irp != self.irp || terminal.identity != self.identity {
            return Err(DeliveryError::WrongIdentity);
        }
        self.terminal = Some(terminal);
        self.phase = Phase::Terminal;
        Ok(())
    }

    /// A synchronous CREATE returned its terminal result in the dispatch invocation. There
    /// is no retained backend completion to acknowledge after the provider Reply.
    pub fn observe_inline_terminal(
        &mut self,
        status: u32,
        information: u64,
    ) -> Result<(), DeliveryError> {
        if self.phase != Phase::DispatchEntered {
            return Err(DeliveryError::WrongPhase);
        }
        self.terminal = Some(CreateTerminal {
            irp: None,
            identity: self.identity,
            status,
            information,
        });
        self.phase = Phase::Terminal;
        Ok(())
    }

    pub fn bind_handle(&mut self, handle: u64) -> Result<(), DeliveryError> {
        if self.cancelled {
            return Err(DeliveryError::Cancelled);
        }
        if self.phase != Phase::Terminal
            || !matches!(self.terminal, Some(terminal) if (terminal.status as i32) >= 0)
        {
            return Err(DeliveryError::WrongPhase);
        }
        if handle == 0 {
            return Err(DeliveryError::InvalidHandle);
        }
        self.handle = Some(handle);
        self.phase = Phase::HandleBound;
        Ok(())
    }

    pub fn publish_handle(&mut self, handle: u64) -> Result<(), DeliveryError> {
        if self.cancelled {
            return Err(DeliveryError::Cancelled);
        }
        if self.phase != Phase::HandleBound {
            return Err(DeliveryError::WrongPhase);
        }
        if self.handle != Some(handle) {
            return Err(DeliveryError::WrongIdentity);
        }
        self.phase = Phase::HandlePublished;
        Ok(())
    }

    /// A failed CREATE has no handle; a successful CREATE must have a published one.
    pub fn enter_reply(&mut self) -> Result<(), DeliveryError> {
        if self.cancelled {
            return Err(DeliveryError::Cancelled);
        }
        let terminal = self.terminal.ok_or(DeliveryError::WrongPhase)?;
        let ready = if (terminal.status as i32) < 0 {
            self.phase == Phase::Terminal && self.handle.is_none()
        } else {
            self.phase == Phase::HandlePublished && self.handle.is_some()
        };
        if !ready {
            return Err(DeliveryError::WrongPhase);
        }
        self.phase = Phase::ReplyEntered;
        Ok(())
    }

    /// This is a physical acknowledgement or a reconciliation of an uncertain send.
    pub fn acknowledge_reply(&mut self) -> Result<(), DeliveryError> {
        if self.phase != Phase::ReplyEntered {
            return Err(DeliveryError::WrongPhase);
        }
        self.phase = Phase::ReplyAcknowledged;
        Ok(())
    }

    /// Cancellation suppresses new publication, but an entered IRP still needs its terminal
    /// result and backend acknowledgement. An entered Reply must first be reconciled.
    pub fn cancel(&mut self) -> Result<(), DeliveryError> {
        match self.phase {
            Phase::Prepared => {
                self.cancelled = true;
                self.phase = Phase::Aborted;
            }
            Phase::DispatchEntered | Phase::AwaitTerminal | Phase::Terminal
            | Phase::HandleBound | Phase::HandlePublished => self.cancelled = true,
            Phase::ReplyEntered => return Err(DeliveryError::WrongPhase),
            Phase::ReplyAcknowledged | Phase::BackendAckEntered
            | Phase::BackendAcknowledged | Phase::Aborted | Phase::Finished => {
                return Err(DeliveryError::WrongPhase);
            }
        }
        Ok(())
    }

    /// Only a sealed retained-service stop receipt authorizes cancelled backend retirement.
    pub fn acknowledge_stop(&mut self) -> Result<(), DeliveryError> {
        if !self.cancelled || self.stop_acknowledged {
            return Err(DeliveryError::WrongPhase);
        }
        self.stop_acknowledged = true;
        Ok(())
    }

    /// Called only after the external handle reservation/publication has been revoked.
    pub fn rollback_cancelled_handle(&mut self, handle: u64) -> Result<(), DeliveryError> {
        if !self.cancelled || !matches!(self.phase, Phase::HandleBound | Phase::HandlePublished) {
            return Err(DeliveryError::WrongPhase);
        }
        if self.handle != Some(handle) {
            return Err(DeliveryError::WrongIdentity);
        }
        self.handle = None;
        self.phase = Phase::Terminal;
        Ok(())
    }

    /// A cancellation receipt or Reply ACK must precede backend ACK. The caller owns any
    /// bound/published handle rollback before entering this transition on cancellation.
    pub fn enter_backend_ack(&mut self) -> Result<(), DeliveryError> {
        let ready = self.phase == Phase::ReplyAcknowledged
            || (self.cancelled
                && self.stop_acknowledged
                && self.phase == Phase::Terminal
                && self.handle.is_none());
        if !ready || self.irp.is_none() || self.terminal.is_none() {
            return Err(DeliveryError::WrongPhase);
        }
        self.phase = Phase::BackendAckEntered;
        Ok(())
    }

    /// An uncertain backend ACK remains entered; the caller must reconcile it, not resend it.
    pub fn acknowledge_backend(&mut self) -> Result<(), DeliveryError> {
        if self.phase != Phase::BackendAckEntered {
            return Err(DeliveryError::WrongPhase);
        }
        self.phase = Phase::BackendAcknowledged;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), DeliveryError> {
        let inline = self.terminal.is_some_and(|terminal| terminal.irp.is_none());
        let ready = self.phase == Phase::BackendAcknowledged
            || (inline && self.phase == Phase::ReplyAcknowledged)
            || (inline
                && self.cancelled
                && self.stop_acknowledged
                && self.phase == Phase::Terminal
                && self.handle.is_none());
        if !ready {
            return Err(DeliveryError::WrongPhase);
        }
        self.phase = Phase::Finished;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> CreateIdentity {
        CreateIdentity { file: FileId(7), requestor_tid: 19, major: 0 }
    }

    fn terminal(irp: IrpId, status: u32) -> CreateTerminal {
        CreateTerminal { irp: Some(irp), identity: identity(), status, information: 3 }
    }

    #[test]
    fn dispatch_and_reply_cannot_be_replayed() {
        let mut owner = ProviderCreateDelivery::new(identity());
        owner.enter_dispatch().unwrap();
        assert_eq!(owner.enter_dispatch(), Err(DeliveryError::WrongPhase));
        owner.retain_irp(IrpId(11)).unwrap();
        assert_eq!(owner.retain_irp(IrpId(12)), Err(DeliveryError::WrongPhase));
        owner.observe_terminal(terminal(IrpId(11), 0)).unwrap();
        assert_eq!(owner.enter_reply(), Err(DeliveryError::WrongPhase));
        owner.bind_handle(0x44).unwrap();
        assert_eq!(owner.publish_handle(0x45), Err(DeliveryError::WrongIdentity));
        owner.publish_handle(0x44).unwrap();
        owner.enter_reply().unwrap();
        assert_eq!(owner.enter_reply(), Err(DeliveryError::WrongPhase));
        owner.acknowledge_reply().unwrap();
        owner.enter_backend_ack().unwrap();
        assert_eq!(owner.enter_backend_ack(), Err(DeliveryError::WrongPhase));
        owner.acknowledge_backend().unwrap();
        owner.finish().unwrap();
    }

    #[test]
    fn terminal_requires_exact_irp_file_thread_and_major() {
        let mut owner = ProviderCreateDelivery::new(identity());
        owner.enter_dispatch().unwrap();
        owner.retain_irp(IrpId(11)).unwrap();
        assert_eq!(owner.observe_terminal(terminal(IrpId(12), 0)), Err(DeliveryError::WrongIdentity));
        for wrong in [
            CreateIdentity { file: FileId(8), ..identity() },
            CreateIdentity { requestor_tid: 20, ..identity() },
            CreateIdentity { major: 1, ..identity() },
        ] {
            let mut result = terminal(IrpId(11), 0);
            result.identity = wrong;
            assert_eq!(owner.observe_terminal(result), Err(DeliveryError::WrongIdentity));
        }
        assert_eq!(owner.phase(), Phase::AwaitTerminal);
        owner.observe_terminal(terminal(IrpId(11), 0xc000_0034)).unwrap();
        owner.enter_reply().unwrap();
        owner.acknowledge_reply().unwrap();
        owner.enter_backend_ack().unwrap();
        owner.acknowledge_backend().unwrap();
        owner.finish().unwrap();
    }

    #[test]
    fn cancellation_does_not_replay_or_skip_entered_irp_ack() {
        let mut owner = ProviderCreateDelivery::new(identity());
        owner.enter_dispatch().unwrap();
        owner.retain_irp(IrpId(11)).unwrap();
        owner.cancel().unwrap();
        assert_eq!(owner.enter_dispatch(), Err(DeliveryError::WrongPhase));
        assert_eq!(owner.enter_backend_ack(), Err(DeliveryError::WrongPhase));
        owner.observe_terminal(terminal(IrpId(11), 0)).unwrap();
        assert_eq!(owner.bind_handle(0x44), Err(DeliveryError::Cancelled));
        assert_eq!(owner.enter_backend_ack(), Err(DeliveryError::WrongPhase));
        owner.acknowledge_stop().unwrap();
        owner.enter_backend_ack().unwrap();
        owner.acknowledge_backend().unwrap();
        owner.finish().unwrap();
    }

    #[test]
    fn uncertain_dispatch_and_reply_remain_owned() {
        let mut owner = ProviderCreateDelivery::new(identity());
        owner.enter_dispatch().unwrap();
        assert_eq!(owner.phase(), Phase::DispatchEntered);
        assert_eq!(owner.enter_dispatch(), Err(DeliveryError::WrongPhase));
        owner.retain_irp(IrpId(11)).unwrap();
        owner.observe_terminal(terminal(IrpId(11), 0xc000_0034)).unwrap();
        owner.enter_reply().unwrap();
        assert_eq!(owner.cancel(), Err(DeliveryError::WrongPhase));
        assert_eq!(owner.enter_backend_ack(), Err(DeliveryError::WrongPhase));
        owner.acknowledge_reply().unwrap();
    }

    #[test]
    fn cancelled_publication_requires_exact_rollback() {
        let mut owner = ProviderCreateDelivery::new(identity());
        owner.enter_dispatch().unwrap();
        owner.retain_irp(IrpId(11)).unwrap();
        owner.observe_terminal(terminal(IrpId(11), 0)).unwrap();
        owner.bind_handle(0x44).unwrap();
        owner.publish_handle(0x44).unwrap();
        owner.cancel().unwrap();
        assert_eq!(owner.enter_backend_ack(), Err(DeliveryError::WrongPhase));
        assert_eq!(owner.rollback_cancelled_handle(0x45), Err(DeliveryError::WrongIdentity));
        owner.rollback_cancelled_handle(0x44).unwrap();
        assert_eq!(owner.enter_backend_ack(), Err(DeliveryError::WrongPhase));
        owner.acknowledge_stop().unwrap();
        owner.enter_backend_ack().unwrap();
    }

    #[test]
    fn inline_terminal_finishes_after_reply_ack_without_backend_ack() {
        let mut owner = ProviderCreateDelivery::new(identity());
        owner.enter_dispatch().unwrap();
        owner.observe_inline_terminal(0, 7).unwrap();
        assert_eq!(owner.irp(), None);
        owner.bind_handle(0x44).unwrap();
        owner.publish_handle(0x44).unwrap();
        owner.enter_reply().unwrap();
        assert_eq!(owner.finish(), Err(DeliveryError::WrongPhase));
        owner.acknowledge_reply().unwrap();
        assert_eq!(owner.enter_backend_ack(), Err(DeliveryError::WrongPhase));
        owner.finish().unwrap();
    }

    #[test]
    fn cancelled_inline_terminal_needs_sealed_stop_receipt() {
        let mut owner = ProviderCreateDelivery::new(identity());
        owner.enter_dispatch().unwrap();
        owner.observe_inline_terminal(0xc000_0034, 0).unwrap();
        owner.cancel().unwrap();
        assert_eq!(owner.finish(), Err(DeliveryError::WrongPhase));
        owner.acknowledge_stop().unwrap();
        owner.finish().unwrap();
    }

    #[test]
    fn post_dispatch_abort_requires_explicit_non_entry_proof() {
        let mut owner = ProviderCreateDelivery::new(identity());
        assert_eq!(owner.abort_not_entered(DispatchNotEnteredProof::ProviderNotEntered),
            Err(DeliveryError::WrongPhase));
        owner.enter_dispatch().unwrap();
        owner.abort_not_entered(DispatchNotEnteredProof::ProviderNotEntered).unwrap();
        assert_eq!(owner.enter_dispatch(), Err(DeliveryError::WrongPhase));
    }
}
