//! Delivery ordering for an asynchronous hosted kernel File read.
//!
//! The caller owns and authenticates `T` (for example, an exact pinned provider stack lane).
//! This owner never treats a numeric address as authority. Each `begin_*` claims one external
//! effect; an uncertain effect remains claimed and cannot be replayed or retired. The caller
//! confirms only after the corresponding native effect is known to have completed.

use crate::retained_read_forward::ReadCompletion;

const STATUS_PENDING: u32 = 0x0000_0103;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostedReadDeliveryError {
    WrongTarget,
    WrongPhase,
    PendingTerminal,
    ExcessInformation,
    OutputLengthMismatch,
    InlineErrorOutput,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dispatch {
    Admitted,
    Submitted,
    Pending,
    Inline,
    InlineError,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingReply {
    NotNeeded,
    Ready,
    InFlight,
    Published,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Delivery {
    Waiting,
    OutputInFlight,
    OutputPublished,
    IosbInFlight,
    IosbPublished,
    EventInFlight,
    EventPublished,
    AckInFlight,
    Acked,
}

/// Owned terminal bytes remain live until the exact source IRP is acknowledged.
#[derive(Debug)]
#[must_use = "retain through terminal publication and IRP acknowledgement"]
pub struct HostedKernelReadDelivery<T> {
    target: T,
    output_capacity: u32,
    dispatch: Dispatch,
    pending_reply: PendingReply,
    delivery: Delivery,
    terminal: Option<ReadCompletion>,
    cancel_requested: bool,
}

impl<T: Eq> HostedKernelReadDelivery<T> {
    pub fn admit(target: T, output_capacity: u32) -> Self {
        Self {
            target,
            output_capacity,
            dispatch: Dispatch::Admitted,
            pending_reply: PendingReply::NotNeeded,
            delivery: Delivery::Waiting,
            terminal: None,
            cancel_requested: false,
        }
    }

    pub fn target(&self) -> &T {
        &self.target
    }

    pub fn cancel_requested(&self) -> bool {
        self.cancel_requested
    }

    fn check_target(&self, observed: &T) -> Result<(), HostedReadDeliveryError> {
        if observed == &self.target {
            Ok(())
        } else {
            Err(HostedReadDeliveryError::WrongTarget)
        }
    }

    pub fn submitted(&mut self, observed: &T) -> Result<(), HostedReadDeliveryError> {
        self.check_target(observed)?;
        if self.dispatch != Dispatch::Admitted {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.dispatch = Dispatch::Submitted;
        Ok(())
    }

    /// A pending backend retains the IRP independently of the early service Reply.
    pub fn returned_pending(&mut self, observed: &T) -> Result<(), HostedReadDeliveryError> {
        self.check_target(observed)?;
        if self.dispatch != Dispatch::Submitted {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.dispatch = Dispatch::Pending;
        self.pending_reply = PendingReply::Ready;
        Ok(())
    }

    /// Claims the early `STATUS_PENDING` Reply. Unknown delivery leaves it in flight.
    pub fn begin_pending_reply(&mut self, observed: &T) -> Result<u32, HostedReadDeliveryError> {
        self.check_target(observed)?;
        if self.pending_reply != PendingReply::Ready {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.pending_reply = PendingReply::InFlight;
        Ok(STATUS_PENDING)
    }

    pub fn confirm_pending_reply(&mut self, observed: &T) -> Result<(), HostedReadDeliveryError> {
        self.check_target(observed)?;
        if self.pending_reply != PendingReply::InFlight {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.pending_reply = PendingReply::Published;
        Ok(())
    }

    fn validate_terminal(
        &self,
        completion: &ReadCompletion,
    ) -> Result<(), HostedReadDeliveryError> {
        if completion.status() == STATUS_PENDING {
            return Err(HostedReadDeliveryError::PendingTerminal);
        }
        if completion.information() > u64::from(self.output_capacity) {
            return Err(HostedReadDeliveryError::ExcessInformation);
        }
        if completion.bytes().len() as u64 != completion.information() {
            return Err(HostedReadDeliveryError::OutputLengthMismatch);
        }
        Ok(())
    }

    /// Used when dispatch completes inline, without an early pending Reply.
    pub fn returned_inline(
        &mut self,
        observed: &T,
        completion: ReadCompletion,
    ) -> Result<(), HostedReadDeliveryError> {
        self.check_target(observed)?;
        if self.dispatch != Dispatch::Submitted {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.validate_terminal(&completion)?;
        let publishes = nt_io_completion::file_io_status_publishes_completion(
            completion.status(), true,
        );
        if !publishes && completion.information() != 0 {
            return Err(HostedReadDeliveryError::InlineErrorOutput);
        }
        self.dispatch = if publishes { Dispatch::Inline } else { Dispatch::InlineError };
        self.terminal = Some(completion);
        Ok(())
    }

    /// A cancellation request never supplies terminal status or authorizes delivery.
    pub fn request_cancel(&mut self, observed: &T) -> Result<(), HostedReadDeliveryError> {
        self.check_target(observed)?;
        if !matches!(self.dispatch, Dispatch::Submitted | Dispatch::Pending)
            || self.terminal.is_some()
        {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.cancel_requested = true;
        Ok(())
    }

    /// Capture the exact provider terminal, even if the early Reply is still in flight.
    pub fn capture_terminal(
        &mut self,
        observed: &T,
        completion: ReadCompletion,
    ) -> Result<(), HostedReadDeliveryError> {
        self.check_target(observed)?;
        if self.dispatch != Dispatch::Pending || self.terminal.is_some() {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.validate_terminal(&completion)?;
        self.terminal = Some(completion);
        Ok(())
    }

    fn ready_for_delivery(&self) -> bool {
        self.terminal.is_some()
            && (self.dispatch == Dispatch::Inline || self.pending_reply == PendingReply::Published)
    }

    /// The returned bytes are owned by this state machine until acknowledgement.
    pub fn begin_output(&mut self, observed: &T) -> Result<&[u8], HostedReadDeliveryError> {
        self.check_target(observed)?;
        if !self.ready_for_delivery() || self.delivery != Delivery::Waiting {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.delivery = Delivery::OutputInFlight;
        Ok(self.terminal.as_ref().unwrap().bytes())
    }

    pub fn confirm_output(&mut self, observed: &T) -> Result<(), HostedReadDeliveryError> {
        self.check_target(observed)?;
        if self.delivery != Delivery::OutputInFlight {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.delivery = Delivery::OutputPublished;
        Ok(())
    }

    pub fn begin_iosb(&mut self, observed: &T) -> Result<(u32, u64), HostedReadDeliveryError> {
        self.check_target(observed)?;
        if self.delivery != Delivery::OutputPublished {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.delivery = Delivery::IosbInFlight;
        let terminal = self.terminal.as_ref().unwrap();
        Ok((terminal.status(), terminal.information()))
    }

    pub fn confirm_iosb(&mut self, observed: &T) -> Result<(), HostedReadDeliveryError> {
        self.check_target(observed)?;
        if self.delivery != Delivery::IosbInFlight {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.delivery = Delivery::IosbPublished;
        Ok(())
    }

    pub fn begin_file_event(&mut self, observed: &T) -> Result<(), HostedReadDeliveryError> {
        self.check_target(observed)?;
        if self.delivery != Delivery::IosbPublished {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.delivery = Delivery::EventInFlight;
        Ok(())
    }

    pub fn confirm_file_event(&mut self, observed: &T) -> Result<(), HostedReadDeliveryError> {
        self.check_target(observed)?;
        if self.delivery != Delivery::EventInFlight {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.delivery = Delivery::EventPublished;
        Ok(())
    }

    pub fn begin_irp_ack(&mut self, observed: &T) -> Result<(), HostedReadDeliveryError> {
        self.check_target(observed)?;
        if self.delivery != Delivery::EventPublished {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.delivery = Delivery::AckInFlight;
        Ok(())
    }

    pub fn confirm_irp_ack(&mut self, observed: &T) -> Result<(), HostedReadDeliveryError> {
        self.check_target(observed)?;
        if self.delivery != Delivery::AckInFlight {
            return Err(HostedReadDeliveryError::WrongPhase);
        }
        self.delivery = Delivery::Acked;
        Ok(())
    }

    pub fn retire(self, observed: &T) -> Result<ReadCompletion, (HostedReadDeliveryError, Self)> {
        if let Err(error) = self.check_target(observed) {
            return Err((error, self));
        }
        if !(self.dispatch == Dispatch::InlineError && self.delivery == Delivery::Waiting)
            && self.delivery != Delivery::Acked
        {
            return Err((HostedReadDeliveryError::WrongPhase, self));
        }
        Ok(self.terminal.unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completion(status: u32, bytes: &[u8]) -> ReadCompletion {
        ReadCompletion::capture(status, bytes.len() as u64, bytes).unwrap()
    }

    #[test]
    fn pending_read_requires_reply_then_output_iosb_event_ack() {
        let mut read = HostedKernelReadDelivery::admit(17u64, 3);
        let exact = 17;
        assert_eq!(
            read.begin_output(&exact),
            Err(HostedReadDeliveryError::WrongPhase)
        );
        read.submitted(&exact).unwrap();
        read.returned_pending(&exact).unwrap();
        read.capture_terminal(&exact, completion(0, &[1, 2]))
            .unwrap();
        assert_eq!(
            read.begin_output(&exact),
            Err(HostedReadDeliveryError::WrongPhase)
        );
        assert_eq!(read.begin_pending_reply(&exact), Ok(STATUS_PENDING));
        assert_eq!(
            read.begin_pending_reply(&exact),
            Err(HostedReadDeliveryError::WrongPhase)
        );
        read.confirm_pending_reply(&exact).unwrap();
        assert_eq!(read.begin_output(&exact), Ok(&[1, 2][..]));
        assert_eq!(
            read.begin_iosb(&exact),
            Err(HostedReadDeliveryError::WrongPhase)
        );
        read.confirm_output(&exact).unwrap();
        assert_eq!(read.begin_iosb(&exact), Ok((0, 2)));
        assert_eq!(
            read.begin_file_event(&exact),
            Err(HostedReadDeliveryError::WrongPhase)
        );
        read.confirm_iosb(&exact).unwrap();
        read.begin_file_event(&exact).unwrap();
        assert_eq!(
            read.begin_irp_ack(&exact),
            Err(HostedReadDeliveryError::WrongPhase)
        );
        read.confirm_file_event(&exact).unwrap();
        read.begin_irp_ack(&exact).unwrap();
        assert_eq!(
            read.begin_irp_ack(&exact),
            Err(HostedReadDeliveryError::WrongPhase)
        );
        read.confirm_irp_ack(&exact).unwrap();
        assert_eq!(read.retire(&exact).unwrap().bytes(), &[1, 2]);
    }

    #[test]
    fn cancellation_does_not_complete_or_release_a_read() {
        let mut read = HostedKernelReadDelivery::admit(17u64, 3);
        read.submitted(&17).unwrap();
        read.returned_pending(&17).unwrap();
        read.request_cancel(&17).unwrap();
        assert!(read.cancel_requested());
        assert_eq!(
            read.begin_file_event(&17),
            Err(HostedReadDeliveryError::WrongPhase)
        );
        assert_eq!(
            read.begin_irp_ack(&17),
            Err(HostedReadDeliveryError::WrongPhase)
        );
        assert_eq!(read.begin_pending_reply(&17), Ok(STATUS_PENDING));
        read.confirm_pending_reply(&17).unwrap();
        read.capture_terminal(&17, completion(0xc000_0120, &[]))
            .unwrap();
        assert_eq!(read.begin_output(&17), Ok(&[][..]));
        read.confirm_output(&17).unwrap();
        assert_eq!(read.begin_iosb(&17), Ok((0xc000_0120, 0)));
        read.confirm_iosb(&17).unwrap();
        read.begin_file_event(&17).unwrap();
        read.confirm_file_event(&17).unwrap();
        read.begin_irp_ack(&17).unwrap();
        read.confirm_irp_ack(&17).unwrap();
        assert_eq!(read.retire(&17).unwrap().status(), 0xc000_0120);
    }

    #[test]
    fn inline_completion_skips_pending_reply_but_requires_publication() {
        let mut read = HostedKernelReadDelivery::admit(17u64, 3);
        read.submitted(&17).unwrap();
        read.returned_inline(&17, completion(0, &[4])).unwrap();
        assert_eq!(
            read.begin_pending_reply(&17),
            Err(HostedReadDeliveryError::WrongPhase)
        );
        assert_eq!(read.begin_output(&17), Ok(&[4][..]));
        read.confirm_output(&17).unwrap();
        assert_eq!(read.begin_iosb(&17), Ok((0, 1)));
        read.confirm_iosb(&17).unwrap();
        read.begin_file_event(&17).unwrap();
        read.confirm_file_event(&17).unwrap();
        read.begin_irp_ack(&17).unwrap();
        read.confirm_irp_ack(&17).unwrap();
        assert_eq!(read.retire(&17).unwrap().information(), 1);
    }

    #[test]
    fn inline_error_leaves_iosb_and_file_event_untouched() {
        let mut read = HostedKernelReadDelivery::admit(17u64, 3);
        read.submitted(&17).unwrap();
        assert_eq!(
            read.returned_inline(&17, completion(0xc000_000d, &[1])),
            Err(HostedReadDeliveryError::InlineErrorOutput)
        );
        read.returned_inline(&17, completion(0xc000_000d, &[]))
            .unwrap();
        assert_eq!(read.begin_output(&17), Err(HostedReadDeliveryError::WrongPhase));
        assert_eq!(read.begin_iosb(&17), Err(HostedReadDeliveryError::WrongPhase));
        assert_eq!(read.begin_file_event(&17), Err(HostedReadDeliveryError::WrongPhase));
        assert_eq!(read.begin_irp_ack(&17), Err(HostedReadDeliveryError::WrongPhase));
        assert_eq!(read.retire(&17).unwrap().status(), 0xc000_000d);
    }

    #[test]
    fn exact_target_and_terminal_shape_are_required() {
        let mut read = HostedKernelReadDelivery::admit(17u64, 2);
        assert_eq!(
            read.submitted(&18),
            Err(HostedReadDeliveryError::WrongTarget)
        );
        read.submitted(&17).unwrap();
        read.returned_pending(&17).unwrap();
        assert_eq!(
            read.capture_terminal(&18, completion(0, &[1])),
            Err(HostedReadDeliveryError::WrongTarget)
        );
        assert_eq!(
            read.capture_terminal(&17, completion(STATUS_PENDING, &[])),
            Err(HostedReadDeliveryError::PendingTerminal)
        );
        assert_eq!(
            read.capture_terminal(&17, completion(0, &[1, 2, 3])),
            Err(HostedReadDeliveryError::ExcessInformation)
        );
        assert_eq!(
            read.capture_terminal(&17, ReadCompletion::from_owned(0, 2, alloc::vec![1])),
            Err(HostedReadDeliveryError::OutputLengthMismatch)
        );
        read.capture_terminal(&17, completion(0, &[1])).unwrap();
        assert_eq!(
            read.capture_terminal(&17, completion(0, &[1])),
            Err(HostedReadDeliveryError::WrongPhase)
        );
    }

    #[test]
    fn uncertain_output_publication_cannot_be_replayed_or_acknowledged() {
        let mut read = HostedKernelReadDelivery::admit(17u64, 2);
        read.submitted(&17).unwrap();
        read.returned_inline(&17, completion(0, &[1])).unwrap();
        assert_eq!(read.begin_output(&17), Ok(&[1][..]));
        assert_eq!(
            read.begin_output(&17),
            Err(HostedReadDeliveryError::WrongPhase)
        );
        assert_eq!(
            read.begin_iosb(&17),
            Err(HostedReadDeliveryError::WrongPhase)
        );
        assert_eq!(
            read.begin_irp_ack(&17),
            Err(HostedReadDeliveryError::WrongPhase)
        );
        assert!(matches!(
            read.retire(&17),
            Err((HostedReadDeliveryError::WrongPhase, _))
        ));
    }
}
