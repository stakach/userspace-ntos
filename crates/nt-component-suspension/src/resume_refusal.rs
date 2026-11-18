//! A provider resume refused before its continuation re-entered the provider.
//!
//! The resume's authority check can fail after `begin_resume` (for example the retained
//! continuation no longer names the lane's current Reply). Nothing has been sent to the
//! provider, so no effect is uncertain, but neither the provider's parked Call nor the
//! continuation may be reused. Retaining the frame as `Resuming` would fence every fresh
//! dispatch on every lane (`fresh_dispatch_busy`). This transition instead quarantines only
//! the refused lane: its frame keeps its owner, continuation and completion, it is never
//! selected or resumed again, and its client is failed exactly once with the refusal status.

use super::*;

/// Delivery of the refusal status to the refused frame's own client. Ownership is recorded
/// before the native effect, and an uncertain effect is never retried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RefusedClientDelivery {
    Pending,
    Invoking,
    Delivered,
    Indeterminate(u32),
}

impl<C, R: Clone, T> ComponentSuspensionLanes<C, R, T> {
    /// Quarantine the running lane's exact top frame after a no-effects resume refusal.
    /// The lane leaves the execution fence and returns to `Suspended`; it is not idle, so it
    /// is never reused for a fresh dispatch, and its frame is never selected again.
    pub fn refuse_resume_no_effects(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        key: SuspensionKey,
        owner: SuspensionOwner,
        status: u32,
    ) -> Result<(), LaneError> {
        if status == 0 || (status as i32) >= 0 {
            return Err(LaneError::InvalidIdentity);
        }
        self.validate_running(handle, reply_object)?;
        let lane = self.lane_mut(handle)?;
        if lane.terminal.is_some() {
            return Err(LaneError::InvalidPhase);
        }
        let frame = lane.suspensions.frames.last_mut()
            .ok_or(LaneError::Suspension(SuspensionError::NotFound))?;
        if frame.key != key {
            return Err(LaneError::Suspension(SuspensionError::NotTop));
        }
        if frame.owner != owner {
            return Err(LaneError::Suspension(SuspensionError::InvalidIdentity));
        }
        let SuspensionPhase::Resuming { completion, cancelled } = &frame.phase else {
            return Err(LaneError::Suspension(SuspensionError::InvalidPhase));
        };
        frame.phase = SuspensionPhase::ResumeRefused {
            completion: completion.clone(),
            cancelled: *cancelled,
            status,
            client: RefusedClientDelivery::Pending,
        };
        lane.phase = LanePhase::Suspended;
        self.running = None;
        Ok(())
    }

    /// Claim the single delivery of the refusal status to the frame's client.
    pub fn begin_refused_client_delivery(
        &mut self,
        handle: LaneHandle,
        key: SuspensionKey,
    ) -> Result<u32, LaneError> {
        let frame = self.refused_frame_mut(handle, key)?;
        match &mut frame.phase {
            SuspensionPhase::ResumeRefused { status, client, .. }
                if *client == RefusedClientDelivery::Pending =>
            {
                *client = RefusedClientDelivery::Invoking;
                Ok(*status)
            }
            _ => Err(LaneError::Suspension(SuspensionError::InvalidPhase)),
        }
    }

    /// Record the entered delivery. A failure is retained as indeterminate, never retried.
    pub fn record_refused_client_delivery(
        &mut self,
        handle: LaneHandle,
        key: SuspensionKey,
        outcome: Result<(), u32>,
    ) -> Result<(), LaneError> {
        let frame = self.refused_frame_mut(handle, key)?;
        match &mut frame.phase {
            SuspensionPhase::ResumeRefused { client, .. }
                if *client == RefusedClientDelivery::Invoking =>
            {
                *client = match outcome {
                    Ok(()) => RefusedClientDelivery::Delivered,
                    Err(status) => RefusedClientDelivery::Indeterminate(status),
                };
                Ok(())
            }
            _ => Err(LaneError::Suspension(SuspensionError::InvalidPhase)),
        }
    }

    fn refused_frame_mut(
        &mut self,
        handle: LaneHandle,
        key: SuspensionKey,
    ) -> Result<&mut SuspensionFrame<C, R>, LaneError> {
        let lane = self.lane_mut(handle)?;
        let frame = lane.suspensions.frames.last_mut()
            .ok_or(LaneError::Suspension(SuspensionError::NotFound))?;
        if frame.key != key || !matches!(frame.phase, SuspensionPhase::ResumeRefused { .. }) {
            return Err(LaneError::Suspension(SuspensionError::InvalidPhase));
        }
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Lanes = ComponentSuspensionLanes<u64, u32, u64>;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;

    fn owner(client_tid: u64, dispatch_id: u64) -> SuspensionOwner {
        SuspensionOwner {
            provider_domain: 1,
            provider_generation: 2,
            caller: SuspensionCaller::Hosted(SuspensionHostedClient {
                client_pi: 20,
                client_generation: 4,
                client_tid,
                client_badge: 6,
            }),
            dispatch_id,
        }
    }

    fn binding(id: u64) -> LaneBinding {
        LaneBinding { executor_id: id * 10 + 1, receive_endpoint: id * 10 + 2, reply_object: id * 10 + 3 }
    }

    /// One client's wait parked on its own lane, selected and entered for resume.
    fn resuming(lanes: &mut Lanes, id: u64, tid: u64) -> (LaneHandle, SuspensionKey) {
        let bind = binding(id);
        let lane = lanes.allocate(bind).unwrap();
        let key = SuspensionKey::provider_wait(id);
        lanes.begin_dispatch(lane, bind.reply_object).unwrap();
        lanes.admit_running(lane, bind.reply_object, key, id, owner(tid, id), id * 100).unwrap();
        lanes.select(key, 0).unwrap();
        lanes.begin_resume(lane, bind.reply_object, key).unwrap();
        (lane, key)
    }

    /// Boot 44235934294: Explorer's resume was refused before re-entry. Retained as an
    /// uncertain `Resuming` terminal, it fenced every other client's fresh dispatch.
    #[test]
    fn an_uncertain_resuming_terminal_fences_every_client() {
        let mut lanes = Lanes::new(4, 4);
        let (lane, key) = resuming(&mut lanes, 1, 672);
        let reply = binding(1).reply_object;
        let identity = lanes.retain_terminal_running(lane, reply, key, owner(672, 1), 0).unwrap();
        let mut attempt = lanes.begin_terminal_stage(identity, reply, TerminalStage::Output).unwrap();
        lanes.record_terminal_stage(&mut attempt, reply,
            TerminalStageOutcome::Indeterminate(STATUS_INVALID_PARAMETER)).unwrap();
        assert!(lanes.fresh_dispatch_busy(), "the old retention fences all clients");
    }

    #[test]
    fn a_refused_resume_quarantines_only_its_own_lane() {
        let mut lanes = Lanes::new(4, 4);
        let (refused, key) = resuming(&mut lanes, 1, 672);
        lanes.refuse_resume_no_effects(refused, binding(1).reply_object, key, owner(672, 1),
            STATUS_INVALID_PARAMETER).unwrap();

        // The other client's work still enters and completes.
        assert!(!lanes.fresh_dispatch_busy());
        let other = lanes.allocate(binding(2)).unwrap();
        let other_reply = binding(2).reply_object;
        lanes.begin_dispatch(other, other_reply).unwrap();
        let other_key = SuspensionKey::provider_wait(2);
        lanes.admit_running(other, other_reply, other_key, 2, owner(100, 2), 200).unwrap();
        lanes.select(other_key, 0).unwrap();
        assert_eq!(lanes.next_resumable().map(|resume| resume.lane), Some(other),
            "only the other client's selected wait is resumable");
        lanes.begin_resume(other, other_reply, other_key).unwrap();
        let identity = lanes.retain_terminal_running(other, other_reply, other_key,
            owner(100, 2), 7).unwrap();
        for stage in [TerminalStage::Output, TerminalStage::Context,
            TerminalStage::Publication, TerminalStage::Reply]
        {
            let mut attempt = lanes.begin_terminal_stage(identity, other_reply, stage).unwrap();
            lanes.record_terminal_stage(&mut attempt, other_reply,
                TerminalStageOutcome::Acknowledged).unwrap();
        }
        lanes.finish_terminal(identity, other_reply, Ok(())).unwrap();
        assert!(!lanes.fresh_dispatch_busy());

        // The refused lane keeps its exact owner and continuation and is never reused.
        let frame = lanes.frame(refused, key).unwrap().unwrap();
        assert_eq!(frame.owner, owner(672, 1));
        assert_eq!(frame.continuation, 100);
        assert!(matches!(frame.phase, SuspensionPhase::ResumeRefused {
            status: STATUS_INVALID_PARAMETER, client: RefusedClientDelivery::Pending, .. }));
        assert!(lanes.begin_resume(refused, binding(1).reply_object, key).is_err());
        assert_eq!(lanes.begin_dispatch(refused, binding(1).reply_object), Err(LaneError::InvalidPhase));
    }

    #[test]
    fn the_refused_client_is_failed_exactly_once() {
        let mut lanes = Lanes::new(2, 4);
        let (lane, key) = resuming(&mut lanes, 1, 672);
        lanes.refuse_resume_no_effects(lane, binding(1).reply_object, key, owner(672, 1),
            STATUS_INVALID_PARAMETER).unwrap();
        assert_eq!(lanes.begin_refused_client_delivery(lane, key), Ok(STATUS_INVALID_PARAMETER));
        assert!(lanes.begin_refused_client_delivery(lane, key).is_err());
        lanes.record_refused_client_delivery(lane, key, Ok(())).unwrap();
        assert!(lanes.record_refused_client_delivery(lane, key, Ok(())).is_err());
        assert!(matches!(lanes.frame(lane, key).unwrap().unwrap().phase,
            SuspensionPhase::ResumeRefused { client: RefusedClientDelivery::Delivered, .. }));
    }

    #[test]
    fn only_an_entered_resume_with_an_error_status_can_be_refused() {
        let mut lanes = Lanes::new(2, 4);
        let (lane, key) = resuming(&mut lanes, 1, 672);
        let reply = binding(1).reply_object;
        assert!(lanes.refuse_resume_no_effects(lane, reply, key, owner(672, 1), 0).is_err());
        assert!(lanes.refuse_resume_no_effects(lane, reply, key, owner(673, 1),
            STATUS_INVALID_PARAMETER).is_err());
        assert!(lanes.refuse_resume_no_effects(lane, reply + 1, key, owner(672, 1),
            STATUS_INVALID_PARAMETER).is_err());
        lanes.refuse_resume_no_effects(lane, reply, key, owner(672, 1),
            STATUS_INVALID_PARAMETER).unwrap();
        assert!(lanes.refuse_resume_no_effects(lane, reply, key, owner(672, 1),
            STATUS_INVALID_PARAMETER).is_err(), "a refused lane is no longer running");
    }
}
