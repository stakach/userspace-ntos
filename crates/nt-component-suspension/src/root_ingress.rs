//! One ordinary hosted Call checkpoints a nested component parent independently of child Reply.

use crate::*;

/// Sealed equality witness for a positive child checkpoint. It owns neither Reply nor scope.
/// A park observation is native-issued only after the exact root Reply park committed.
#[must_use = "retain until the exact nested parent begins restoration"]
#[derive(Debug)]
pub struct RootIngressCheckpoint {
    parent: NestedExecutionIdentity,
    child: ExternalAdmissionKey,
}

impl RootIngressCheckpoint {
    pub fn from_settlement(scope: &NestedExecutionScope, settlement: &ExternalSettlement) -> Self {
        Self { parent: scope.identity(), child: settlement.admission_key() }
    }

    /// # Safety
    /// Native must have positively committed the exact child RootReplyPark and retained its
    /// original Call/Reply before issuing this observation. Uncertain effects cannot use it.
    pub unsafe fn after_park(scope: &NestedExecutionScope, child: ExternalAdmissionKey) -> Self {
        Self { parent: scope.identity(), child }
    }

    pub const fn parent(&self) -> NestedExecutionIdentity { self.parent }
    pub const fn child(&self) -> ExternalAdmissionKey { self.child }
}

impl<C, R, T> ComponentSuspensionLanes<C, R, T> {
    /// Reserve the same nested lane and external-token capacity as a Receive child before the
    /// physical parent is held. This does not change the current callback depth.
    pub fn reserve_root_ingress_capacity(
        &mut self, handle: LaneHandle, reply_object: u64, owner: SuspensionOwner,
    ) -> Result<(), LaneError> {
        self.reserve_receive_capacity(handle, reply_object, owner)
    }

    /// Publish the exact ordinary child into a pre-reserved nested scope. Rejection returns its
    /// continuation and leaves the parent scope owned by the caller.
    pub fn admit_root_ingress_owned(
        &mut self, scope: &NestedExecutionScope, key: SuspensionKey,
        admission_sequence: u64, owner: SuspensionOwner, child: ExternalAdmissionKey,
        continuation: C,
    ) -> Result<(), (LaneError, C)> {
        let handle = scope.dispatch().lane();
        if let Err(error) = self.validate_receive_scope(scope)
            .and_then(|()| self.validate_dispatch_owner(handle, owner))
        {
            return Err((error, continuation));
        }
        if key.kind != SuspensionKind::RootIngress
            || key.id != child.admission_sequence() || admission_sequence == 0
        {
            return Err((LaneError::InvalidIdentity, continuation));
        }
        if self.slots.iter().any(|slot| slot.lane.as_ref().is_some_and(|lane| {
            lane.suspensions.frames().iter().any(|frame| {
                frame.key == key || frame.owner.same_dispatch(owner)
            })
        })) {
            return Err((LaneError::Suspension(SuspensionError::DuplicateIdentity), continuation));
        }
        let lane = self.lane_mut(handle).expect("validated root ingress lane");
        if lane.external_tokens.len() >= lane.external_tokens.capacity()
            || lane.external_tokens.len() >= lane.suspensions.max_depth
        {
            return Err((LaneError::NoCapacity, continuation));
        }
        lane.suspensions.admit_owned_with_capacity(
            key, admission_sequence, owner, continuation,
            |frames| if frames.len() < frames.capacity() { Ok(()) }
                else { Err(SuspensionError::NoCapacity) },
        ).map_err(|(error, continuation)| (LaneError::Suspension(error), continuation))?;
        lane.suspensions.get_mut_internal(key)
            .expect("admitted root ingress")
            .nested_child = Some(receive_suspension::NestedChildAdmission {
                kind: SuspensionKind::RootIngress,
                scope: scope.identity(), child, restored: false,
            });
        Ok(())
    }
}

impl<C, R: Clone, T> ComponentSuspensionLanes<C, R, T> {
    /// A checkpoint authorizes one internal resume transition. A parked child remains separately
    /// owned by its ExternalIngress row and can settle after the parent has resumed.
    pub fn begin_root_ingress_restore(
        &mut self, scope: &NestedExecutionScope, key: SuspensionKey,
        owner: SuspensionOwner, checkpoint: &RootIngressCheckpoint, completion: R,
    ) -> Result<SuspensionResume<R>, LaneError> {
        self.validate_receive_scope(scope)?;
        if self.execution_busy()
            || self.slots.iter().any(|slot| slot.lane.as_ref().is_some_and(|lane| {
                matches!(lane.phase, LanePhase::NestedExecution(sequence)
                    if sequence > scope.identity().sequence())
            }))
        {
            return Err(LaneError::Busy);
        }
        let lane = self.lane_mut(scope.dispatch().lane())?;
        let frame = lane.suspensions.frames.last_mut()
            .ok_or(LaneError::Suspension(SuspensionError::NotFound))?;
        if frame.key != key { return Err(LaneError::Suspension(SuspensionError::NotTop)); }
        if key.kind != SuspensionKind::RootIngress || frame.owner != owner
            || checkpoint.parent != scope.identity()
            || frame.nested_child != Some(receive_suspension::NestedChildAdmission {
                kind: SuspensionKind::RootIngress,
                scope: scope.identity(), child: checkpoint.child, restored: false,
            })
        {
            return Err(LaneError::WrongBinding);
        }
        if !matches!(frame.phase, SuspensionPhase::Waiting) {
            return Err(LaneError::InvalidPhase);
        }
        let epoch = lane.resume_epoch.checked_add(1).ok_or(LaneError::NoCapacity)?;
        frame.phase = SuspensionPhase::Resuming {
            completion: completion.clone(), cancelled: false,
        };
        frame.nested_child.as_mut().expect("validated root admission").restored = true;
        lane.resume_epoch = epoch;
        Ok(SuspensionResume { key, completion, cancelled: false })
    }
}
