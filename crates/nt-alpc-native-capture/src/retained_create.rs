//! Exact caller and request ownership across an uncertain ALPC create exchange.

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CreateOwner {
    pub process_id: u64,
    pub thread_id: u64,
    pub process_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TerminalCreate {
    pub status: i32,
    pub handle: u64,
    pub service_effect_possible: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedCreateError {
    InvalidIdentity,
    InvalidResult,
    CleanupFailed,
    WrongPhase,
    WrongRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Prepared,
    Submitted(u64),
    Terminal(TerminalCreate),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Delivery {
    NotRequired,
    NeedsCopyout,
    NeedsPublication,
    Published,
    NeedsClose(u64),
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessSlot { Reserved, Published, Aborted }

/// Holds the original Reply capability and checked wire bytes until the exact
/// CQE is known and a terminal reply is acknowledged. This is a state owner,
/// not a transport: the executive must park the Reply before submitting.
#[must_use = "retain the caller Reply and wire request until exact completion"]
pub struct RetainedCreate {
    owner: CreateOwner,
    token: (u64, u64),
    reply_cap: u64,
    process_handle: u64,
    request: Vec<u8>,
    phase: Phase,
    delivery: Delivery,
    process_slot: ProcessSlot,
}

impl RetainedCreate {
    pub fn new(
        owner: CreateOwner,
        token: (u64, u64),
        reply_cap: u64,
        process_handle: u64,
        request: Vec<u8>,
    ) -> Result<Self, RetainedCreateError> {
        if owner.process_id == 0 || owner.thread_id == 0 || owner.process_generation == 0
            || token == (0, 0) || reply_cap == 0 || process_handle == 0 || request.is_empty()
        {
            return Err(RetainedCreateError::InvalidIdentity);
        }
        Ok(Self { owner, token, reply_cap, process_handle, request,
            phase: Phase::Prepared, delivery: Delivery::NotRequired,
            process_slot: ProcessSlot::Reserved })
    }

    pub fn owner(&self) -> CreateOwner { self.owner }
    pub fn token(&self) -> (u64, u64) { self.token }
    pub fn reply_cap(&self) -> u64 { self.reply_cap }
    pub fn process_handle(&self) -> u64 { self.process_handle }
    pub fn request(&self) -> &[u8] { &self.request }

    /// Call before offering the SQE; the same ID must be used by the ring.
    pub fn begin(&mut self, request_id: u64) -> Result<(), RetainedCreateError> {
        if request_id == 0 { return Err(RetainedCreateError::InvalidIdentity); }
        if self.phase != Phase::Prepared { return Err(RetainedCreateError::WrongPhase); }
        self.phase = Phase::Submitted(request_id);
        Ok(())
    }

    /// The ring rejected the request before publishing an SQE.
    pub fn no_effect(&mut self, status: i32) -> Result<(), RetainedCreateError> {
        if !matches!(self.phase, Phase::Submitted(_)) {
            return Err(RetainedCreateError::WrongPhase);
        }
        self.phase = Phase::Terminal(TerminalCreate {
            status, handle: 0, service_effect_possible: false,
        });
        Ok(())
    }

    /// A timeout is observation only; it never frees the request, Reply, or
    /// shared frame and never permits a fresh create with another token.
    pub fn uncertain(&self, request_id: u64) -> Result<(), RetainedCreateError> {
        match self.phase {
            Phase::Submitted(expected) if expected == request_id => Ok(()),
            Phase::Submitted(_) => Err(RetainedCreateError::WrongRequest),
            _ => Err(RetainedCreateError::WrongPhase),
        }
    }

    /// Only the exact terminal CQE can complete the submitted operation.
    pub fn complete(
        &mut self,
        request_id: u64,
        status: i32,
        handle: u64,
    ) -> Result<(), RetainedCreateError> {
        self.uncertain(request_id)?;
        if (status == 0) != (handle != 0) {
            return Err(RetainedCreateError::InvalidResult);
        }
        self.phase = Phase::Terminal(TerminalCreate {
            status, handle, service_effect_possible: true,
        });
        self.delivery = if status == 0 { Delivery::NeedsCopyout } else { Delivery::NotRequired };
        Ok(())
    }

    /// Record the checked write to the original caller's output address. A
    /// failed write leaves the exact service handle owned until close succeeds.
    pub fn copyout(&mut self, handle: u64, written: bool) -> Result<(), RetainedCreateError> {
        if self.delivery != Delivery::NeedsCopyout || self.process_slot != ProcessSlot::Reserved {
            return Err(RetainedCreateError::WrongPhase);
        }
        if handle != self.process_handle { return Err(RetainedCreateError::WrongRequest); }
        let Some(result) = self.terminal() else { return Err(RetainedCreateError::WrongPhase) };
        self.delivery = if written { Delivery::NeedsPublication } else { Delivery::NeedsClose(result.handle) };
        Ok(())
    }

    /// The exact hidden process-table slot became visible after copyout.
    pub fn process_handle_published(&mut self, handle: u64) -> Result<(), RetainedCreateError> {
        if self.delivery != Delivery::NeedsPublication || self.process_slot != ProcessSlot::Reserved {
            return Err(RetainedCreateError::WrongPhase);
        }
        if handle != self.process_handle { return Err(RetainedCreateError::WrongRequest); }
        self.process_slot = ProcessSlot::Published;
        self.delivery = Delivery::Published;
        Ok(())
    }

    /// The exact invisible slot was canceled. If copyout had succeeded but
    /// publication failed, the service handle still needs checked close.
    pub fn process_handle_aborted(&mut self, handle: u64) -> Result<(), RetainedCreateError> {
        if self.process_slot != ProcessSlot::Reserved { return Err(RetainedCreateError::WrongPhase); }
        if handle != self.process_handle { return Err(RetainedCreateError::WrongRequest); }
        if matches!(self.delivery, Delivery::NeedsCopyout | Delivery::NeedsPublication) {
            let Some(result) = self.terminal() else { return Err(RetainedCreateError::WrongPhase) };
            self.delivery = Delivery::NeedsClose(result.handle);
        }
        self.process_slot = ProcessSlot::Aborted;
        Ok(())
    }

    pub fn cleanup_handle(&self) -> Option<u64> {
        match self.delivery { Delivery::NeedsClose(handle) => Some(handle), _ => None }
    }

    /// Only an acknowledged close of the same service handle retires a failed
    /// copyout. A timeout or failed close leaves the original Reply retained.
    pub fn cleanup_complete(&mut self, handle: u64, status: i32) -> Result<(), RetainedCreateError> {
        if self.delivery != Delivery::NeedsClose(handle) {
            return Err(RetainedCreateError::WrongRequest);
        }
        if status != 0 {
            return Err(RetainedCreateError::CleanupFailed);
        }
        self.delivery = Delivery::Closed;
        Ok(())
    }

    /// None means the original Reply is still owned by copyout or cleanup.
    pub fn reply_status(&self) -> Option<i32> {
        let result = self.terminal()?;
        match (self.delivery, self.process_slot) {
            (Delivery::NotRequired, ProcessSlot::Aborted) => Some(result.status),
            (Delivery::Published, ProcessSlot::Published) => Some(result.status),
            (Delivery::Closed, ProcessSlot::Aborted) => Some(0xC000_0005u32 as i32),
            _ => None,
        }
    }

    pub fn terminal(&self) -> Option<TerminalCreate> {
        match self.phase { Phase::Terminal(result) => Some(result), _ => None }
    }

    /// A failed Reply send returns the whole owner unchanged for retry.
    pub fn finish_after_reply(self, acknowledged: bool) -> Result<(), Self> {
        if acknowledged && self.reply_status().is_some() { Ok(()) } else { Err(self) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call() -> RetainedCreate {
        RetainedCreate::new(
            CreateOwner { process_id: 4, thread_id: 8, process_generation: 12 },
            (12, 99), 300, 4, alloc::vec![1, 2, 3],
        ).unwrap()
    }

    #[test]
    fn timeout_and_wrong_cqe_keep_exact_reply_and_request_owned() {
        let mut call = call();
        call.begin(41).unwrap();
        assert_eq!(call.uncertain(41), Ok(()));
        assert_eq!(call.complete(42, 0, 0xabc), Err(RetainedCreateError::WrongRequest));
        assert_eq!(call.reply_cap(), 300);
        assert_eq!(call.request(), &[1, 2, 3]);
        assert_eq!(call.terminal(), None);
        let mut call = call.finish_after_reply(true).err().unwrap();
        call.complete(41, 0, 0xabc).unwrap();
        assert_eq!(call.terminal().unwrap().handle, 0xabc);
        call.copyout(4, true).unwrap();
        call.process_handle_published(4).unwrap();
        assert!(call.finish_after_reply(true).is_ok());
    }

    #[test]
    fn known_pre_submit_rejection_cannot_publish_handle() {
        let mut call = call();
        call.begin(41).unwrap();
        call.no_effect(0xC000_00A3u32 as i32).unwrap();
        assert_eq!(call.terminal().unwrap(), TerminalCreate {
            status: 0xC000_00A3u32 as i32,
            handle: 0,
            service_effect_possible: false,
        });
        assert_eq!(call.complete(41, 0, 5), Err(RetainedCreateError::WrongPhase));
    }

    #[test]
    fn failed_reply_ack_keeps_caller_and_completed_request() {
        let mut call = call();
        call.begin(41).unwrap();
        call.complete(41, 0, 55).unwrap();
        call.copyout(4, true).unwrap();
        call.process_handle_published(4).unwrap();
        let call = call.finish_after_reply(false).err().unwrap();
        assert_eq!(call.reply_cap(), 300);
        assert_eq!(call.request(), &[1, 2, 3]);
        assert!(call.finish_after_reply(true).is_ok());
    }

    #[test]
    fn successful_create_requires_copyout_or_exact_close_before_reply() {
        let mut call = call();
        call.begin(41).unwrap();
        call.complete(41, 0, 55).unwrap();
        // The service has published handle 55, but the caller has not received
        // it. Acknowledging STATUS_SUCCESS here would orphan that handle.
        let call = call.finish_after_reply(true).err().expect("unpublished handle retained");
        assert_eq!(call.reply_cap(), 300);
        assert_eq!(call.terminal().unwrap().handle, 55);
        assert_eq!(call.reply_status(), None);
    }

    #[test]
    fn failed_copyout_retains_exact_handle_until_checked_close() {
        let mut call = call();
        call.begin(41).unwrap();
        call.complete(41, 0, 55).unwrap();
        call.copyout(4, false).unwrap();
        call.process_handle_aborted(4).unwrap();
        assert_eq!(call.cleanup_handle(), Some(55));
        assert_eq!(call.cleanup_complete(56, 0), Err(RetainedCreateError::WrongRequest));
        assert_eq!(call.cleanup_complete(55, 0xC000_0001u32 as i32),
            Err(RetainedCreateError::CleanupFailed));
        assert_eq!(call.reply_status(), None);
        assert!(call.cleanup_complete(55, 0).is_ok());
        assert_eq!(call.reply_status(), Some(0xC000_0005u32 as i32));
        assert!(call.finish_after_reply(true).is_ok());
    }

    #[test]
    fn copied_process_handle_must_be_published_before_success_reply() {
        let mut call = call();
        call.begin(41).unwrap();
        call.complete(41, 0, 55).unwrap();
        // Service handle 55 is owned by the port service. The value copied to
        // the caller is a reserved process-table handle, still invisible here.
        call.copyout(4, true).unwrap();
        let call = call.finish_after_reply(true).err()
            .expect("copyout alone cannot publish a process handle");
        assert_eq!(call.reply_cap(), 300);
        assert_eq!(call.terminal().unwrap().handle, 55);
    }

    #[test]
    fn wrong_or_unpublished_process_handle_never_completes_success() {
        let mut call = call();
        call.begin(41).unwrap();
        call.complete(41, 0, 55).unwrap();
        assert_eq!(call.copyout(8, true), Err(RetainedCreateError::WrongRequest));
        call.copyout(4, true).unwrap();
        assert_eq!(call.process_handle_published(8), Err(RetainedCreateError::WrongRequest));
        assert_eq!(call.reply_status(), None);
        call.process_handle_published(4).unwrap();
        assert_eq!(call.reply_status(), Some(0));
    }

    #[test]
    fn failed_service_create_requires_releasing_reserved_process_handle() {
        let mut call = call();
        call.begin(41).unwrap();
        call.complete(41, 0xC000_0035u32 as i32, 0).unwrap();
        assert_eq!(call.reply_status(), None);
        call.process_handle_aborted(4).unwrap();
        assert_eq!(call.reply_status(), Some(0xC000_0035u32 as i32));
    }

    #[test]
    fn failed_process_binding_keeps_service_handle_for_checked_close() {
        let mut call = call();
        call.begin(41).unwrap();
        call.complete(41, 0, 55).unwrap();
        call.process_handle_aborted(4).unwrap();
        assert_eq!(call.cleanup_handle(), Some(55));
        assert_eq!(call.reply_status(), None);
        call.cleanup_complete(55, 0).unwrap();
        assert_eq!(call.reply_status(), Some(0xC000_0005u32 as i32));
    }
}
