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
    WrongPhase,
    WrongRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Prepared,
    Submitted(u64),
    Terminal(TerminalCreate),
}

/// Holds the original Reply capability and checked wire bytes until the exact
/// CQE is known and a terminal reply is acknowledged. This is a state owner,
/// not a transport: the executive must park the Reply before submitting.
#[must_use = "retain the caller Reply and wire request until exact completion"]
pub struct RetainedCreate {
    owner: CreateOwner,
    token: (u64, u64),
    reply_cap: u64,
    request: Vec<u8>,
    phase: Phase,
}

impl RetainedCreate {
    pub fn new(
        owner: CreateOwner,
        token: (u64, u64),
        reply_cap: u64,
        request: Vec<u8>,
    ) -> Result<Self, RetainedCreateError> {
        if owner.process_id == 0 || owner.thread_id == 0 || owner.process_generation == 0
            || token == (0, 0) || reply_cap == 0 || request.is_empty()
        {
            return Err(RetainedCreateError::InvalidIdentity);
        }
        Ok(Self { owner, token, reply_cap, request, phase: Phase::Prepared })
    }

    pub fn owner(&self) -> CreateOwner { self.owner }
    pub fn token(&self) -> (u64, u64) { self.token }
    pub fn reply_cap(&self) -> u64 { self.reply_cap }
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
        self.phase = Phase::Terminal(TerminalCreate {
            status, handle, service_effect_possible: true,
        });
        Ok(())
    }

    pub fn terminal(&self) -> Option<TerminalCreate> {
        match self.phase { Phase::Terminal(result) => Some(result), _ => None }
    }

    /// A failed Reply send returns the whole owner unchanged for retry.
    pub fn finish_after_reply(self, acknowledged: bool) -> Result<(), Self> {
        if acknowledged && self.terminal().is_some() { Ok(()) } else { Err(self) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn call() -> RetainedCreate {
        RetainedCreate::new(
            CreateOwner { process_id: 4, thread_id: 8, process_generation: 12 },
            (12, 99), 300, alloc::vec![1, 2, 3],
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
        let call = call.finish_after_reply(false).err().unwrap();
        assert_eq!(call.reply_cap(), 300);
        assert_eq!(call.request(), &[1, 2, 3]);
        assert!(call.finish_after_reply(true).is_ok());
    }
}
