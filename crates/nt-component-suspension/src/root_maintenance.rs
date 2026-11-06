//! Exact native continuation ownership across one outer root maintenance pass.
//!
//! Maintenance is an internal scheduler checkpoint. It has no provider completion payload and
//! cannot acknowledge or manufacture the original syscall Reply.

use crate::*;

impl<C, R> ComponentSuspensionStack<C, R> {
    /// Pop a resumed checkpoint only after the terminal pipeline has acknowledged its Reply.
    /// This is deliberately separate from `complete_dispatch`, which requires a real `R`.
    pub(super) fn retire_root_maintenance(
        &mut self,
        key: SuspensionKey,
        owner: SuspensionOwner,
    ) -> Result<C, SuspensionError> {
        let frame = self.frames.last().ok_or(SuspensionError::NotFound)?;
        if frame.key != key { return Err(SuspensionError::NotTop); }
        if frame.owner != owner { return Err(SuspensionError::InvalidIdentity); }
        if key.kind != SuspensionKind::RootMaintenance
            || !matches!(frame.phase, SuspensionPhase::MaintenanceResuming { .. })
            || self.frames.len() != 1
        {
            return Err(SuspensionError::InvalidPhase);
        }
        Ok(self.frames.pop().unwrap().continuation)
    }
}

impl<C, R, T> ComponentSuspensionLanes<C, R, T> {
    /// Park the current dispatch until a later completed outer service-loop pass. Rejection
    /// returns the original continuation, so the caller can retain its physical Reply.
    pub fn admit_root_maintenance_owned(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        dispatch: LaneDispatchIdentity,
        key: SuspensionKey,
        admission_sequence: u64,
        owner: SuspensionOwner,
        captured_pass: u64,
        continuation: C,
    ) -> Result<(), (LaneError, C)> {
        if key.kind != SuspensionKind::RootMaintenance
            || dispatch.lane() != handle
            || !self.is_dispatch_identity_active(dispatch)
        {
            return Err((LaneError::InvalidIdentity, continuation));
        }
        // This checkpoint owns an entire running native dispatch. A lower suspension would
        // require a distinct parent-restoration transition when this one completes.
        if self.suspension_count(handle) != Ok(0)
            || self.external_depth(handle) != Ok(0)
        {
            return Err((LaneError::InvalidPhase, continuation));
        }
        self.admit_running_owned_internal(
            handle, reply_object, key, admission_sequence, owner, continuation, true,
        )?;
        let frame = self.lane_mut(handle)
            .expect("admitted maintenance lane")
            .suspensions.frames.last_mut()
            .expect("admitted maintenance frame");
        frame.phase = SuspensionPhase::MaintenanceWaiting { captured_pass };
        Ok(())
    }

    /// Record one completed, strictly newer outer service-loop pass for the exact checkpoint.
    /// This grants readiness only; it does not complete the provider or original syscall.
    pub fn mark_root_maintenance_pass(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        dispatch: LaneDispatchIdentity,
        key: SuspensionKey,
        owner: SuspensionOwner,
        observed_pass: u64,
    ) -> Result<(), LaneError> {
        self.validate(handle, reply_object)?;
        if key.kind != SuspensionKind::RootMaintenance
            || dispatch.lane() != handle
            || !self.is_dispatch_identity_active(dispatch)
        {
            return Err(LaneError::InvalidIdentity);
        }
        let lane = self.lane_mut(handle)?;
        if lane.phase != LanePhase::Suspended || lane.terminal.is_some() {
            return Err(LaneError::InvalidPhase);
        }
        let frame = lane.suspensions.top().ok_or(LaneError::Suspension(SuspensionError::NotFound))?;
        if frame.key != key { return Err(LaneError::Suspension(SuspensionError::NotTop)); }
        if frame.owner != owner { return Err(LaneError::InvalidIdentity); }
        let captured_pass = match &frame.phase {
            SuspensionPhase::MaintenanceWaiting { captured_pass } => *captured_pass,
            _ => return Err(LaneError::InvalidPhase),
        };
        if observed_pass <= captured_pass { return Err(LaneError::InvalidPhase); }
        lane.suspensions.frames.last_mut().unwrap().phase =
            SuspensionPhase::MaintenanceReady { observed_pass };
        Ok(())
    }

    /// Reacquire the exact lane once, without inventing an `R` completion payload.
    pub fn begin_root_maintenance_resume(
        &mut self,
        handle: LaneHandle,
        reply_object: u64,
        dispatch: LaneDispatchIdentity,
        key: SuspensionKey,
        owner: SuspensionOwner,
    ) -> Result<u64, LaneError> {
        self.validate(handle, reply_object)?;
        if key.kind != SuspensionKind::RootMaintenance
            || dispatch.lane() != handle
            || !self.is_dispatch_identity_active(dispatch)
        {
            return Err(LaneError::InvalidIdentity);
        }
        if self.running == Some(handle) { return Err(LaneError::InvalidPhase); }
        if self.execution_busy() { return Err(LaneError::Busy); }
        let max_depth = self.max_depth_per_lane;
        let lane = self.lane_mut(handle)?;
        if lane.phase != LanePhase::Suspended || lane.terminal.is_some() {
            return Err(LaneError::InvalidPhase);
        }
        let frame = lane.suspensions.top().ok_or(LaneError::Suspension(SuspensionError::NotFound))?;
        if frame.key != key { return Err(LaneError::Suspension(SuspensionError::NotTop)); }
        if frame.owner != owner { return Err(LaneError::InvalidIdentity); }
        let observed_pass = match &frame.phase {
            SuspensionPhase::MaintenanceReady { observed_pass } => *observed_pass,
            _ => return Err(LaneError::InvalidPhase),
        };
        let next_epoch = lane.resume_epoch.checked_add(1).ok_or(LaneError::NoCapacity)?;
        if lane.external_tokens.len() >= max_depth {
            return Err(LaneError::Suspension(SuspensionError::Overflow));
        }
        lane.external_tokens.try_reserve(1).map_err(|_| LaneError::NoCapacity)?;
        lane.suspensions.frames.last_mut().unwrap().phase =
            SuspensionPhase::MaintenanceResuming { observed_pass };
        lane.resume_epoch = next_epoch;
        lane.phase = LanePhase::Running;
        self.running = Some(handle);
        Ok(observed_pass)
    }

}
