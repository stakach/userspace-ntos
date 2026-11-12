//! Exact callback frame ownership across an entered Win32k callback resume.

use nt_component_suspension::LaneHandle;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallbackResumeKey {
    pub lane: LaneHandle,
    pub dispatch_id: u64,
    pub callback_token: u64,
}

impl CallbackResumeKey {
    pub const fn is_valid(self) -> bool {
        self.lane.is_valid() && self.dispatch_id != 0 && self.callback_token != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackResumePhase { Reserved, Popped, Refused }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallbackResumeError {
    InvalidKey, InvalidReply, AlreadyAttached, Busy, Vacant, WrongKey, WrongFrame, WrongPhase,
}

/// A slot holds the popped callback frame even when the returned physical pump is refused.
pub struct CallbackResumeOwner<F, C, P> {
    key: CallbackResumeKey,
    frame: F,
    phase: CallbackResumePhase,
    channel: Option<C>,
    pump: Option<P>,
    reply: u64,
    outer_reply: Option<u64>,
}

impl<F, C, P> CallbackResumeOwner<F, C, P> {
    pub const fn key(&self) -> CallbackResumeKey { self.key }
    pub const fn phase(&self) -> CallbackResumePhase { self.phase }
    pub fn frame(&self) -> &F { &self.frame }
    pub fn channel(&self) -> Option<&C> { self.channel.as_ref() }
    pub fn pump(&self) -> Option<&P> { self.pump.as_ref() }
    pub const fn reply(&self) -> u64 { self.reply }
    pub const fn outer_reply(&self) -> Option<u64> { self.outer_reply }
}

/// Physical ordinals index independent callback owners; a refusal on one lane cannot occupy
/// another lane's slot. The native adapter authenticates the ordinal before calling this bank.
pub struct CallbackResumeBank<F, C, P, const N: usize> {
    slots: [Option<CallbackResumeOwner<F, C, P>>; N],
}

impl<F: Eq, C, P, const N: usize> CallbackResumeBank<F, C, P, N> {
    pub const fn new() -> Self { Self { slots: [const { None }; N] } }

    pub fn get(&self, ordinal: usize) -> Option<&CallbackResumeOwner<F, C, P>> {
        self.slots.get(ordinal)?.as_ref()
    }

    pub fn reserve(&mut self, ordinal: usize, key: CallbackResumeKey, frame: F)
        -> Result<(), (CallbackResumeError, F)>
    {
        if !key.is_valid() || ordinal >= N { return Err((CallbackResumeError::InvalidKey, frame)); }
        let slot = &mut self.slots[ordinal];
        if slot.is_some() { return Err((CallbackResumeError::Busy, frame)); }
        *slot = Some(CallbackResumeOwner {
            key, frame, phase: CallbackResumePhase::Reserved,
            channel: None, pump: None, reply: 0, outer_reply: None,
        });
        Ok(())
    }

    pub fn accept_pop(&mut self, ordinal: usize, key: CallbackResumeKey, frame: F)
        -> Result<(), (CallbackResumeError, F)>
    {
        let Some(owner) = self.slots.get_mut(ordinal).and_then(Option::as_mut) else {
            return Err((CallbackResumeError::Vacant, frame));
        };
        if owner.key != key { return Err((CallbackResumeError::WrongKey, frame)); }
        if owner.phase != CallbackResumePhase::Reserved {
            return Err((CallbackResumeError::WrongPhase, frame));
        }
        if owner.frame != frame { return Err((CallbackResumeError::WrongFrame, frame)); }
        owner.frame = frame;
        owner.phase = CallbackResumePhase::Popped;
        Ok(())
    }

    /// Retain the complete physical return even when its Reply is uncertain. A zero Reply is
    /// stored as evidence, never treated as permission to complete or reuse the lane.
    pub fn retain_refusal(
        &mut self, ordinal: usize, key: CallbackResumeKey, channel: C, pump: P, reply: u64,
    ) -> Result<(), (CallbackResumeError, C, P)> {
        let Some(owner) = self.slots.get_mut(ordinal).and_then(Option::as_mut) else {
            return Err((CallbackResumeError::Vacant, channel, pump));
        };
        if owner.key != key { return Err((CallbackResumeError::WrongKey, channel, pump)); }
        if owner.phase != CallbackResumePhase::Popped {
            return Err((CallbackResumeError::WrongPhase, channel, pump));
        }
        owner.channel = Some(channel);
        owner.pump = Some(pump);
        owner.reply = reply;
        owner.phase = CallbackResumePhase::Refused;
        Ok(())
    }

    /// Attach the service loop's distinct NtCallbackReturn Reply exactly once. The provider
    /// Reply and this outer Reply have separate lifetimes and both remain in the refused row.
    pub fn attach_outer_reply(
        &mut self, ordinal: usize, key: CallbackResumeKey, outer_reply: u64,
    ) -> Result<(), CallbackResumeError> {
        if outer_reply == 0 { return Err(CallbackResumeError::InvalidReply); }
        let owner = self.slots.get_mut(ordinal).and_then(Option::as_mut)
            .ok_or(CallbackResumeError::Vacant)?;
        if owner.key != key { return Err(CallbackResumeError::WrongKey); }
        if owner.phase != CallbackResumePhase::Refused {
            return Err(CallbackResumeError::WrongPhase);
        }
        if owner.outer_reply.is_some() { return Err(CallbackResumeError::AlreadyAttached); }
        owner.outer_reply = Some(outer_reply);
        Ok(())
    }

    /// Normal returns transfer the frame back to the callback classifier. Refused rows cannot
    /// be released by this path, even if a caller holds the exact key.
    pub fn release_normal(&mut self, ordinal: usize, key: CallbackResumeKey)
        -> Result<F, CallbackResumeError>
    {
        let Some(owner) = self.slots.get(ordinal).and_then(Option::as_ref) else {
            return Err(CallbackResumeError::Vacant);
        };
        if owner.key != key { return Err(CallbackResumeError::WrongKey); }
        if owner.phase != CallbackResumePhase::Popped { return Err(CallbackResumeError::WrongPhase); }
        self.slots[ordinal].take().map(|owner| owner.frame)
            .ok_or(CallbackResumeError::Vacant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(index: u32, token: u64) -> CallbackResumeKey {
        CallbackResumeKey { lane: LaneHandle { index, generation: 4 },
            dispatch_id: token + 100, callback_token: token }
    }

    #[test]
    fn refused_lane_retains_frame_pump_and_reply_while_other_lane_completes() {
        let mut bank = CallbackResumeBank::<u64, u64, u64, 2>::new();
        let a = key(1, 10);
        let b = key(2, 20);
        bank.reserve(0, a, 101).unwrap();
        bank.reserve(1, b, 202).unwrap();
        bank.accept_pop(0, a, 101).unwrap();
        bank.accept_pop(1, b, 202).unwrap();
        bank.retain_refusal(0, a, 303, 404, 505).unwrap();

        let refused = bank.get(0).unwrap();
        assert_eq!(refused.phase(), CallbackResumePhase::Refused);
        assert_eq!((*refused.frame(), refused.channel().copied(), refused.pump().copied(), refused.reply()),
            (101, Some(303), Some(404), 505));
        bank.attach_outer_reply(0, a, 606).unwrap();
        assert_eq!(bank.get(0).unwrap().outer_reply(), Some(606));
        assert_eq!(bank.attach_outer_reply(0, a, 607), Err(CallbackResumeError::AlreadyAttached));
        assert_eq!(bank.release_normal(0, a), Err(CallbackResumeError::WrongPhase));
        assert_eq!(bank.release_normal(1, b), Ok(202));
        assert!(bank.get(1).is_none());
        bank.reserve(1, key(3, 30), 303).unwrap();
        assert_eq!(bank.get(0).unwrap().pump().copied(), Some(404));
        assert_eq!(bank.reserve(0, key(4, 40), 404),
            Err((CallbackResumeError::Busy, 404)));
    }
}
