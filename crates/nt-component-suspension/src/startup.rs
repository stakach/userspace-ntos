//! Exclusive startup ownership before a physical worker becomes dispatchable.

use crate::{ComponentSuspensionLanes, LaneError, LaneHandle, LanePhase, ReplyBindingObservation};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupError<E> {
    Lane(LaneError),
    BindingMismatch,
    Query(E),
}

impl<C, R, T> ComponentSuspensionLanes<C, R, T> {
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
