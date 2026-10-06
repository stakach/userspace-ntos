//! A parent Receive remains fenced until its exact retained child Call has settled.

use crate::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ReceiveAdmission {
    scope: NestedExecutionIdentity,
    child: ExternalAdmissionKey,
    pub(crate) restored: bool,
}

impl<C, R, T> ComponentSuspensionLanes<C, R, T> {
    /// Reuse the restored Receive's frame slot; reserve terminal handoff before the next hold.
    pub fn reserve_receive_rearm_capacity(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        completed_key: SuspensionKey,
        owner: SuspensionOwner,
    ) -> Result<(), LaneError> {
        self.validate_running(handle, reply_object)?;
        self.validate_dispatch_owner(handle, owner)?;
        let max_depth = self.max_depth_per_lane;
        let lane = self.lane_mut(handle)?;
        let frame = lane
            .suspensions
            .top()
            .ok_or(LaneError::Suspension(SuspensionError::NotFound))?;
        if frame.key != completed_key {
            return Err(LaneError::Suspension(SuspensionError::NotTop));
        }
        if completed_key.kind != SuspensionKind::Receive
            || frame.owner != owner
            || !frame.receive.is_some_and(|admission| admission.restored)
            || !matches!(frame.phase, SuspensionPhase::Resuming { .. })
        {
            return Err(LaneError::InvalidPhase);
        }
        lane.resume_epoch
            .checked_add(1)
            .ok_or(LaneError::NoCapacity)?;
        if lane.external_tokens.len() >= max_depth {
            return Err(LaneError::Suspension(SuspensionError::Overflow));
        }
        lane.external_tokens
            .try_reserve(1)
            .map_err(|_| LaneError::NoCapacity)
    }

    /// Replace one settled Receive with a freshly held child, without allocating or running it.
    /// Every rejection preserves the current frame and returns the offered continuation.
    pub fn rearm_receive_owned(
        &mut self,
        scope: &NestedExecutionScope,
        completed_key: SuspensionKey,
        next_key: SuspensionKey,
        admission_sequence: u64,
        owner: SuspensionOwner,
        child: ExternalAdmissionKey,
        continuation: C,
    ) -> Result<C, (LaneError, C)> {
        let handle = scope.dispatch().lane();
        let validation = self
            .validate_receive_scope(scope)
            .and_then(|()| self.validate_dispatch_owner(handle, owner));
        if let Err(error) = validation {
            return Err((error, continuation));
        }
        if next_key.kind != SuspensionKind::Receive
            || completed_key.kind != SuspensionKind::Receive
            || next_key.id != child.admission_sequence()
            || admission_sequence == 0
        {
            return Err((LaneError::InvalidIdentity, continuation));
        }
        if self.slots.iter().any(|slot| {
            slot.lane.as_ref().is_some_and(|lane| {
                lane.suspensions
                    .frames()
                    .iter()
                    .any(|frame| frame.key == next_key)
            })
        }) {
            return Err((
                LaneError::Suspension(SuspensionError::DuplicateIdentity),
                continuation,
            ));
        }
        let lane = self.lane_mut(handle).expect("validated receive rearm lane");
        let Some(frame) = lane.suspensions.frames.last_mut() else {
            return Err((
                LaneError::Suspension(SuspensionError::NotFound),
                continuation,
            ));
        };
        if frame.key != completed_key {
            return Err((LaneError::Suspension(SuspensionError::NotTop), continuation));
        }
        let Some(previous) = frame.receive else {
            return Err((LaneError::InvalidPhase, continuation));
        };
        if frame.owner != owner
            || !previous.restored
            || !matches!(frame.phase, SuspensionPhase::Resuming { .. })
            || previous.scope.dispatch() != scope.dispatch()
            || previous.scope.route() != scope.route()
            || previous.scope.sequence() >= scope.identity().sequence()
            || previous.child == child
            || admission_sequence <= frame.admission_sequence
        {
            return Err((LaneError::WrongBinding, continuation));
        }
        if lane.external_tokens.len() >= lane.external_tokens.capacity() {
            return Err((LaneError::NoCapacity, continuation));
        }
        frame.key = next_key;
        frame.admission_sequence = admission_sequence;
        frame.phase = SuspensionPhase::Waiting;
        frame.receive = Some(ReceiveAdmission {
            scope: scope.identity(),
            child,
            restored: false,
        });
        Ok(core::mem::replace(&mut frame.continuation, continuation))
    }

    /// Reserve before the adapter parks the physical parent. This changes no execution owner.
    pub fn reserve_receive_capacity(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        owner: SuspensionOwner,
    ) -> Result<(), LaneError> {
        self.validate_running(handle, reply_object)?;
        self.validate_dispatch_owner(handle, owner)?;
        let max_depth = self.max_depth_per_lane;
        let lane = self.lane_mut(handle)?;
        lane.resume_epoch
            .checked_add(1)
            .ok_or(LaneError::NoCapacity)?;
        if lane.suspensions.len() >= max_depth || lane.external_tokens.len() >= max_depth {
            return Err(LaneError::Suspension(SuspensionError::Overflow));
        }
        lane.suspensions
            .frames
            .try_reserve(1)
            .map_err(|_| LaneError::NoCapacity)?;
        lane.external_tokens
            .try_reserve(1)
            .map_err(|_| LaneError::NoCapacity)
    }

    fn validate_receive_scope(&self, scope: &NestedExecutionScope) -> Result<(), LaneError> {
        if scope.is_consumed() {
            return Err(LaneError::InvalidPhase);
        }
        let dispatch = scope.dispatch();
        let lane = self.lane(dispatch.lane())?;
        if lane.phase != LanePhase::NestedExecution(scope.identity().sequence())
            || lane.dispatch != Some(dispatch)
            || lane.shared_peer != Some(scope.route())
            || lane.terminal.is_some()
        {
            return Err(LaneError::WrongBinding);
        }
        Ok(())
    }

    /// Publish only into pre-reserved capacity; rejection returns the original continuation.
    pub fn admit_receive_owned(
        &mut self,
        scope: &NestedExecutionScope,
        key: SuspensionKey,
        admission_sequence: u64,
        owner: SuspensionOwner,
        child: ExternalAdmissionKey,
        continuation: C,
    ) -> Result<(), (LaneError, C)> {
        let handle = scope.dispatch().lane();
        let check = self
            .validate_receive_scope(scope)
            .and_then(|()| self.validate_dispatch_owner(handle, owner));
        if let Err(error) = check {
            return Err((error, continuation));
        }
        if key.kind != SuspensionKind::Receive {
            return Err((LaneError::InvalidIdentity, continuation));
        }
        if self.slots.iter().any(|slot| {
            slot.lane.as_ref().is_some_and(|lane| {
                lane.suspensions
                    .frames()
                    .iter()
                    .any(|frame| frame.key == key || frame.owner.same_dispatch(owner))
            })
        }) {
            return Err((
                LaneError::Suspension(SuspensionError::DuplicateIdentity),
                continuation,
            ));
        }
        let lane = self.lane_mut(handle).expect("validated receive lane");
        if lane.external_tokens.len() >= lane.external_tokens.capacity()
            || lane.external_tokens.len() >= lane.suspensions.max_depth
        {
            return Err((LaneError::NoCapacity, continuation));
        }
        lane.suspensions
            .admit_owned_with_capacity(key, admission_sequence, owner, continuation, |frames| {
                if frames.len() < frames.capacity() {
                    Ok(())
                } else {
                    Err(SuspensionError::NoCapacity)
                }
            })
            .map_err(|(error, continuation)| (LaneError::Suspension(error), continuation))?;
        lane.suspensions
            .get_mut_internal(key)
            .expect("admitted receive")
            .receive = Some(ReceiveAdmission {
            scope: scope.identity(),
            child,
            restored: false,
        });
        Ok(())
    }

    pub(crate) fn receive_scope_restorable(&self, scope: &NestedExecutionScope) -> bool {
        let Ok(lane) = self.lane(scope.dispatch().lane()) else {
            return false;
        };
        lane.suspensions.frames().iter().all(|frame| {
            (frame.key.kind != SuspensionKind::Receive && frame.receive.is_none())
                || (frame.key.kind == SuspensionKind::Receive
                    && frame.receive.is_some_and(|admission| {
                        admission.scope == scope.identity() && admission.restored
                    })
                    && matches!(frame.phase, SuspensionPhase::Resuming { .. }))
        })
    }
}

impl<C, R: Clone, T> ComponentSuspensionLanes<C, R, T> {
    /// The adapter retains its non-copy child permit through physical parent restoration.
    /// This consumes only the frame's Waiting phase, not the child receipt or nested scope.
    pub fn begin_receive_restore(
        &mut self,
        scope: &NestedExecutionScope,
        key: SuspensionKey,
        owner: SuspensionOwner,
        settlement: &ExternalSettlement,
        completion: R,
    ) -> Result<SuspensionResume<R>, LaneError> {
        self.validate_receive_scope(scope)?;
        if self.execution_busy()
            || self.slots.iter().any(|slot| {
                slot.lane.as_ref().is_some_and(|lane| {
                    matches!(lane.phase, LanePhase::NestedExecution(sequence)
                if sequence > scope.identity().sequence())
                })
            })
        {
            return Err(LaneError::Busy);
        }
        let lane = self.lane_mut(scope.dispatch().lane())?;
        let frame = lane
            .suspensions
            .frames
            .last_mut()
            .ok_or(LaneError::Suspension(SuspensionError::NotFound))?;
        if frame.key != key {
            return Err(LaneError::Suspension(SuspensionError::NotTop));
        }
        if key.kind != SuspensionKind::Receive
            || frame.owner != owner
            || frame.receive
                != Some(ReceiveAdmission {
                    scope: scope.identity(),
                    child: settlement.admission_key(),
                    restored: false,
                })
        {
            return Err(LaneError::WrongBinding);
        }
        if !matches!(frame.phase, SuspensionPhase::Waiting) {
            return Err(LaneError::InvalidPhase);
        }
        let epoch = lane
            .resume_epoch
            .checked_add(1)
            .ok_or(LaneError::NoCapacity)?;
        frame.phase = SuspensionPhase::Resuming {
            completion: completion.clone(),
            cancelled: false,
        };
        frame
            .receive
            .as_mut()
            .expect("validated receive admission")
            .restored = true;
        lane.resume_epoch = epoch;
        Ok(SuspensionResume {
            key,
            completion,
            cancelled: false,
        })
    }
}
