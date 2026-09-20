//! Exclusive startup ownership before a physical worker becomes dispatchable.

use crate::{ComponentSuspensionLanes, LaneError, LaneHandle, LanePhase, ReplyBindingObservation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupError<E> {
    Lane(LaneError),
    BindingMismatch,
    Query(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupStopError<S, Q> {
    Lane(LaneError),
    Suspend(S),
    Query(Q),
    ReplyNotFree,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupDetachError<E> {
    Lane(LaneError),
    Invoke(E),
}

impl<C, R, T> ComponentSuspensionLanes<C, R, T> {
    /// Detach only the stopped worker's privately owned scheduling context.
    /// The adapter must prove the capability belongs to this executor and remains live, and
    /// invoke synchronously without reentering scheduling. Failure retains entered authority;
    /// success records the ACK but does not permit release of any capability or memory.
    pub fn detach_startup_scheduler<E>(
        &mut self,
        handle: LaneHandle,
        reply: u64,
        detach: impl FnOnce(u64) -> Result<(), E>,
    ) -> Result<(), StartupDetachError<E>> {
        self.validate(handle, reply).map_err(StartupDetachError::Lane)?;
        let lane = self.lane(handle).map_err(StartupDetachError::Lane)?;
        if lane.phase != LanePhase::StartupStopped || self.running != Some(handle) {
            return Err(StartupDetachError::Lane(LaneError::InvalidPhase));
        }
        let executor = lane.binding.executor_id;
        self.lane_mut(handle).map_err(StartupDetachError::Lane)?.phase = LanePhase::StartupDetaching;
        detach(executor).map_err(StartupDetachError::Invoke)?;
        self.lane_mut(handle).map_err(StartupDetachError::Lane)?.phase = LanePhase::StartupDetached;
        Ok(())
    }

    /// Enter a synchronous, acknowledged stop while retaining all startup authority.
    /// Callbacks must address the exact live worker and must not reenter component scheduling.
    /// Any suspension error leaves StartupStopping fenced: it is not proof of no effects and
    /// cannot authorize replay. A query failure after acknowledgment permits observation only.
    pub fn stop_startup<S, Q>(
        &mut self,
        handle: LaneHandle,
        reply: u64,
        suspend: impl FnOnce(u64) -> Result<(), S>,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, Q>,
    ) -> Result<(), StartupStopError<S, Q>> {
        self.validate(handle, reply).map_err(StartupStopError::Lane)?;
        let lane = self.lane(handle).map_err(StartupStopError::Lane)?;
        match lane.phase {
            LanePhase::Staged => {
                if self.execution_busy() {
                    return Err(StartupStopError::Lane(LaneError::Busy));
                }
            }
            LanePhase::Starting if self.running == Some(handle) => {}
            _ => return Err(StartupStopError::Lane(LaneError::InvalidPhase)),
        }
        let executor = lane.binding.executor_id;
        self.lane_mut(handle).map_err(StartupStopError::Lane)?.phase = LanePhase::StartupStopping;
        self.running = Some(handle);
        suspend(executor).map_err(StartupStopError::Suspend)?;
        self.lane_mut(handle).map_err(StartupStopError::Lane)?.phase =
            LanePhase::StartupStopAcknowledged;
        self.verify_startup_stopped(handle, reply, query)
    }

    /// Retry only cancellation observation, never the already acknowledged suspension.
    /// Success does not release the execution fence, capability ownership, or arena reservation.
    pub fn verify_startup_stopped<S, Q>(
        &mut self,
        handle: LaneHandle,
        reply: u64,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, Q>,
    ) -> Result<(), StartupStopError<S, Q>> {
        self.validate(handle, reply).map_err(StartupStopError::Lane)?;
        let lane = self.lane(handle).map_err(StartupStopError::Lane)?;
        if lane.phase != LanePhase::StartupStopAcknowledged || self.running != Some(handle) {
            return Err(StartupStopError::Lane(LaneError::InvalidPhase));
        }
        if query(lane.binding.executor_id, reply).map_err(StartupStopError::Query)?
            != ReplyBindingObservation::Free
        {
            return Err(StartupStopError::ReplyNotFree);
        }
        self.lane_mut(handle).map_err(StartupStopError::Lane)?.phase = LanePhase::StartupStopped;
        Ok(())
    }

    /// Acquire the component execution fence before resuming a newly staged worker.
    /// The adapter must validate physical/domain lifetime and query the exact pair without
    /// dispatching unrelated work. A failed native resume must retain this fence until a future
    /// acknowledged teardown transition; ordinary dispatch completion cannot release it.
    pub fn begin_startup<E>(
        &mut self,
        handle: LaneHandle,
        reply: u64,
        mut query: impl FnMut(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(), StartupError<E>> {
        if self.execution_busy() {
            return Err(StartupError::Lane(LaneError::Busy));
        }
        self.validate(handle, reply).map_err(StartupError::Lane)?;
        let lane = self.lane(handle).map_err(StartupError::Lane)?;
        if lane.phase != LanePhase::Staged {
            return Err(StartupError::Lane(LaneError::InvalidPhase));
        }
        if query(lane.binding.executor_id, reply).map_err(StartupError::Query)?
            != ReplyBindingObservation::Free
        {
            return Err(StartupError::BindingMismatch);
        }
        self.lane_mut(handle).map_err(StartupError::Lane)?.phase = LanePhase::Starting;
        self.running = Some(handle);
        Ok(())
    }

    /// Publish readiness only after the adapter receives the worker's ready protocol message.
    /// Reply binding proves the sender, not the protocol payload: the adapter must check both.
    /// Refusal preserves startup ownership and excludes every other lane from execution.
    pub fn complete_startup<E>(
        &mut self,
        handle: LaneHandle,
        reply: u64,
        mut query: impl FnMut(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(), StartupError<E>> {
        self.validate(handle, reply).map_err(StartupError::Lane)?;
        let lane = self.lane(handle).map_err(StartupError::Lane)?;
        if self.running != Some(handle) || lane.phase != LanePhase::Starting {
            return Err(StartupError::Lane(LaneError::InvalidPhase));
        }
        if query(lane.binding.executor_id, reply).map_err(StartupError::Query)?
            != ReplyBindingObservation::BoundToTarget
        {
            return Err(StartupError::BindingMismatch);
        }
        self.lane_mut(handle).map_err(StartupError::Lane)?.phase = LanePhase::Idle;
        self.running = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
