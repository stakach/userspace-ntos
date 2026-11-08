//! Pure equality and effect-order checkpoint for a local child of a resuming provider.

use crate::{peer_registry::PeerRoute, ComponentSuspensionLanes, LaneDispatchIdentity,
    LanePhase, NestedExecutionIdentity, NestedExecutionScope, SuspensionKey, SuspensionOwner,
    SuspensionPhase};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedPreEntryPhase {
    ResumingCandidate, Parked, ChildReserved, ChildActive, ChildAcknowledged,
    Restoring, ParentActive, Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedPreEntryError { WrongParent, WrongChild, InvalidPhase, Uncertain }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedPreEntryRestoreEffect { NoEffect, Uncertain }

/// Implement only for a move-only native witness issued after the exact parent Reply,
/// continuation and complete shared page have been durably parked. A scope alone is not proof.
pub unsafe trait NestedPreEntryParentParkReceipt {
    fn scope_identity(&self) -> NestedExecutionIdentity;
}

/// Implement only for a move-only native witness issued after the exact parked publication
/// has been physically restored and acknowledged by the global page authority.
pub unsafe trait NestedPreEntryParentRestoreReceipt {
    fn scope_identity(&self) -> NestedExecutionIdentity;
}

/// Implement only for a move-only source-owner receipt following exact terminal completion or
/// durable yield. A packet address, status, or transport ACK is insufficient evidence.
pub unsafe trait NestedPreEntryChildReceipt<K> {
    fn child_key(&self) -> K;
}

#[must_use = "retain until exact child acknowledgement and parent restoration"]
pub struct NestedPreEntryCheckpoint<K> {
    route: PeerRoute,
    dispatch: LaneDispatchIdentity,
    reply_object: u64,
    key: SuspensionKey,
    admission_sequence: u64,
    owner: SuspensionOwner,
    child: K,
    scope: Option<NestedExecutionIdentity>,
    phase: NestedPreEntryPhase,
}

impl<K: Copy + Eq> NestedPreEntryCheckpoint<K> {
    pub fn from_resuming<C, R, T>(
        lanes: &ComponentSuspensionLanes<C, R, T>, route: PeerRoute,
        dispatch: LaneDispatchIdentity, reply_object: u64,
        key: SuspensionKey, owner: SuspensionOwner, child: K,
    ) -> Result<Self, NestedPreEntryError> {
        let lane = dispatch.lane();
        if !owner.is_valid() || !key.is_valid() || reply_object == 0
            || route.identity().lane != lane
            || lanes.phase(lane) != Ok(LanePhase::Running)
            || lanes.active_dispatch_identity(lane) != Ok(Some(dispatch))
            || lanes.peer_route(lane) != Ok(Some(route))
            || lanes.binding(lane).map(|binding| binding.reply_object) != Ok(reply_object)
        {
            return Err(NestedPreEntryError::WrongParent);
        }
        let frame = lanes.top(lane).map_err(|_| NestedPreEntryError::WrongParent)?
            .ok_or(NestedPreEntryError::WrongParent)?;
        if frame.key != key || frame.owner != owner || frame.admission_sequence == 0
            || frame.nested_child.is_some()
            || !matches!(frame.phase, SuspensionPhase::Resuming { .. })
        {
            return Err(NestedPreEntryError::WrongParent);
        }
        Ok(Self {
            route, dispatch, reply_object, key, admission_sequence: frame.admission_sequence,
            owner, child, scope: None, phase: NestedPreEntryPhase::ResumingCandidate,
        })
    }

    pub const fn phase(&self) -> NestedPreEntryPhase { self.phase }
    pub const fn parent_dispatch(&self) -> LaneDispatchIdentity { self.dispatch }
    pub const fn parent_route(&self) -> PeerRoute { self.route }
    pub const fn parent_reply_object(&self) -> u64 { self.reply_object }
    pub const fn parent_key(&self) -> SuspensionKey { self.key }
    pub const fn parent_admission_sequence(&self) -> u64 { self.admission_sequence }
    pub const fn parent_owner(&self) -> SuspensionOwner { self.owner }

    fn expect_phase(&self, expected: NestedPreEntryPhase) -> Result<(), NestedPreEntryError> {
        if self.phase == NestedPreEntryPhase::Uncertain { Err(NestedPreEntryError::Uncertain) }
        else if self.phase == expected { Ok(()) }
        else { Err(NestedPreEntryError::InvalidPhase) }
    }

    /// The native owner obtains `receipt` only after the physical hold and complete page park.
    /// This transition moves the top Resuming frame out of the global fresh-publication fence.
    pub fn park<C, R: Clone, T, P: NestedPreEntryParentParkReceipt>(
        &mut self, lanes: &mut ComponentSuspensionLanes<C, R, T>,
        scope: &NestedExecutionScope, receipt: P,
    ) -> Result<(), (NestedPreEntryError, P)> {
        if let Err(error) = self.expect_phase(NestedPreEntryPhase::ResumingCandidate) {
            return Err((error, receipt));
        }
        if scope.is_consumed() || scope.route() != self.route || scope.dispatch() != self.dispatch
            || receipt.scope_identity() != scope.identity()
            || lanes.validate_receive_scope(scope).is_err()
        {
            return Err((NestedPreEntryError::WrongParent, receipt));
        }
        let frame = match lanes.top(self.dispatch.lane()) {
            Ok(Some(frame)) if frame.key == self.key && frame.owner == self.owner
                && frame.admission_sequence == self.admission_sequence
                && frame.nested_child.is_none() => frame,
            _ => return Err((NestedPreEntryError::WrongParent, receipt)),
        };
        let (completion, cancelled) = match &frame.phase {
            SuspensionPhase::Resuming { completion, cancelled } => (completion.clone(), *cancelled),
            _ => return Err((NestedPreEntryError::WrongParent, receipt)),
        };
        lanes.lane_mut(self.dispatch.lane()).expect("validated scope").suspensions
            .frames.last_mut().expect("validated top").phase =
            SuspensionPhase::ResumingChildParked { completion, cancelled, scope: scope.identity() };
        self.scope = Some(scope.identity());
        self.phase = NestedPreEntryPhase::Parked;
        Ok(())
    }
    pub fn park_no_effect(&mut self) -> Result<(), NestedPreEntryError> {
        self.expect_phase(NestedPreEntryPhase::ResumingCandidate)
    }
    pub fn park_uncertain(&mut self) -> Result<(), NestedPreEntryError> {
        self.expect_phase(NestedPreEntryPhase::ResumingCandidate)?;
        self.phase = NestedPreEntryPhase::Uncertain;
        Ok(())
    }
    /// Return the offered non-Copy Reply unchanged on every refusal.
    pub fn reserve_child<R>(&mut self, child: K, reply: R) -> Result<R, (NestedPreEntryError, R)> {
        if let Err(error) = self.expect_phase(NestedPreEntryPhase::Parked) {
            return Err((error, reply));
        }
        if child != self.child { return Err((NestedPreEntryError::WrongChild, reply)); }
        self.phase = NestedPreEntryPhase::ChildReserved;
        Ok(reply)
    }
    pub fn child_started(&mut self, child: K) -> Result<(), NestedPreEntryError> {
        self.expect_phase(NestedPreEntryPhase::ChildReserved)?;
        if child != self.child { return Err(NestedPreEntryError::WrongChild); }
        self.phase = NestedPreEntryPhase::ChildActive;
        Ok(())
    }
    /// A certified no-entry child remains reserved for the same exact attempt.
    pub fn child_no_effect(&mut self, child: K) -> Result<(), NestedPreEntryError> {
        self.expect_phase(NestedPreEntryPhase::ChildReserved)?;
        if child != self.child { return Err(NestedPreEntryError::WrongChild); }
        Ok(())
    }
    /// A possibly entered child cannot be retried or treated as acknowledged.
    pub fn child_uncertain<C, R: Clone, T>(
        &mut self, lanes: &mut ComponentSuspensionLanes<C, R, T>, child: K,
    ) -> Result<(), NestedPreEntryError> {
        if self.phase == NestedPreEntryPhase::Uncertain {
            return Err(NestedPreEntryError::Uncertain);
        }
        if !matches!(self.phase, NestedPreEntryPhase::ChildReserved
            | NestedPreEntryPhase::ChildActive)
        {
            return Err(NestedPreEntryError::InvalidPhase);
        }
        if child != self.child { return Err(NestedPreEntryError::WrongChild); }
        self.quarantine_parent(lanes)?;
        self.phase = NestedPreEntryPhase::Uncertain;
        Ok(())
    }
    pub fn acknowledge_child<R: NestedPreEntryChildReceipt<K>>(
        &mut self, receipt: R,
    ) -> Result<(), (NestedPreEntryError, R)> {
        if let Err(error) = self.expect_phase(NestedPreEntryPhase::ChildActive) {
            return Err((error, receipt));
        }
        if receipt.child_key() != self.child {
            return Err((NestedPreEntryError::WrongChild, receipt));
        }
        self.phase = NestedPreEntryPhase::ChildAcknowledged;
        Ok(())
    }
    pub fn begin_restore<C, R, T>(
        &mut self, lanes: &ComponentSuspensionLanes<C, R, T>, scope: &NestedExecutionScope,
    ) -> Result<(), NestedPreEntryError> {
        self.expect_phase(NestedPreEntryPhase::ChildAcknowledged)?;
        if !self.parked_parent_matches(lanes, scope) || lanes.execution_busy() {
            return Err(NestedPreEntryError::WrongParent);
        }
        self.phase = NestedPreEntryPhase::Restoring;
        Ok(())
    }
    /// A certified no-effect restore remains owned for retry. Uncertainty permanently fences
    /// the parent frame, including future fresh publication attempts.
    pub fn finish_restore<C, R: Clone, T>(
        &mut self, lanes: &mut ComponentSuspensionLanes<C, R, T>,
        effect: NestedPreEntryRestoreEffect,
    ) -> Result<(), NestedPreEntryError> {
        self.expect_phase(NestedPreEntryPhase::Restoring)?;
        match effect {
            NestedPreEntryRestoreEffect::NoEffect => Ok(()),
            NestedPreEntryRestoreEffect::Uncertain => {
                self.quarantine_parent(lanes)?;
                self.phase = NestedPreEntryPhase::Uncertain;
                Err(NestedPreEntryError::Uncertain)
            }
        }
    }

    /// Consume a physical restore witness before the ordinary nested scope may resume.
    pub fn restore_applied<C, R: Clone, T, P: NestedPreEntryParentRestoreReceipt>(
        &mut self, lanes: &mut ComponentSuspensionLanes<C, R, T>,
        scope: &NestedExecutionScope, receipt: P,
    ) -> Result<(), (NestedPreEntryError, P)> {
        if let Err(error) = self.expect_phase(NestedPreEntryPhase::Restoring) {
            return Err((error, receipt));
        }
        if receipt.scope_identity() != scope.identity()
            || !self.parked_parent_matches(lanes, scope)
            || lanes.execution_busy()
        {
            return Err((NestedPreEntryError::WrongParent, receipt));
        }
        let frame = lanes.lane_mut(self.dispatch.lane()).expect("validated scope")
            .suspensions.frames.last_mut().expect("validated top");
        let (completion, cancelled) = match &frame.phase {
            SuspensionPhase::ResumingChildParked { completion, cancelled, .. } =>
                (completion.clone(), *cancelled),
            _ => return Err((NestedPreEntryError::WrongParent, receipt)),
        };
        frame.phase = SuspensionPhase::Resuming { completion, cancelled };
        self.phase = NestedPreEntryPhase::ParentActive;
        Ok(())
    }

    fn parked_parent_matches<C, R, T>(
        &self, lanes: &ComponentSuspensionLanes<C, R, T>, scope: &NestedExecutionScope,
    ) -> bool {
        if scope.is_consumed() || self.scope != Some(scope.identity())
            || lanes.validate_receive_scope(scope).is_err() { return false; }
        lanes.top(self.dispatch.lane()).ok().flatten().is_some_and(|frame|
            frame.key == self.key && frame.owner == self.owner
                && frame.admission_sequence == self.admission_sequence
                && matches!(frame.phase, SuspensionPhase::ResumingChildParked { scope: parked, .. }
                    if parked == scope.identity()))
    }

    fn quarantine_parent<C, R: Clone, T>(
        &self, lanes: &mut ComponentSuspensionLanes<C, R, T>,
    ) -> Result<(), NestedPreEntryError> {
        let identity = self.scope.ok_or(NestedPreEntryError::WrongParent)?;
        let lane = lanes.lane_mut(self.dispatch.lane())
            .map_err(|_| NestedPreEntryError::WrongParent)?;
        let frame = lane.suspensions.frames.last_mut()
            .ok_or(NestedPreEntryError::WrongParent)?;
        if frame.key != self.key || frame.owner != self.owner
            || frame.admission_sequence != self.admission_sequence { return Err(NestedPreEntryError::WrongParent); }
        let (completion, cancelled) = match &frame.phase {
            SuspensionPhase::ResumingChildParked { completion, cancelled, scope }
                if *scope == identity => (completion.clone(), *cancelled),
            _ => return Err(NestedPreEntryError::WrongParent),
        };
        frame.phase = SuspensionPhase::ResumingChildQuarantined {
            completion, cancelled, scope: identity,
        };
        Ok(())
    }
}
