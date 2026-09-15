//! Publish dispatcher readiness to its exact retained continuation before consuming resources.

use nt_component_suspension::{
    ComponentSuspensionLanes, LaneError, LaneHandle, SuspensionCaller, SuspensionError,
    SuspensionKey, SuspensionPhase,
};
use nt_provider_wait::ProviderDispatcherWaitCompletion;

#[derive(Debug, Eq, PartialEq)]
pub enum ProviderWaitSelectionError<E> {
    InvalidCompletion,
    OwnerMismatch,
    SequenceMismatch,
    Lane(LaneError),
    Continuation(E),
}

/// Use inside a guarded arbiter publication callback under the same dispatcher serialization.
/// This selects ownership only, not permission to execute an exited caller. Resume must still
/// authenticate its canonical process/thread and activation. Buried hosted frames may become
/// Selected while their newer frame runs; they cannot resume until the lane permits it.
///
/// `route` must validate the retained continuation's caller kind/identity and construct its
/// result without IPC, scheduling or externally visible effects. Every error leaves the lane
/// unchanged. After success, the arbiter must commit consumption/release before serialization
/// ends. Cancellation has a separate ownership contract and is not admitted here.
pub fn select_provider_wait<C, R, T, E>(
    lanes: &mut ComponentSuspensionLanes<C, R, T>,
    completion: ProviderDispatcherWaitCompletion,
    route: impl FnOnce(LaneHandle, &C, &ProviderDispatcherWaitCompletion) -> Result<R, E>,
) -> Result<LaneHandle, ProviderWaitSelectionError<E>> {
    if completion.cancelled || completion.wait_id == 0 || completion.admission_sequence == 0 {
        return Err(ProviderWaitSelectionError::InvalidCompletion);
    }
    let key = SuspensionKey::provider_wait(completion.wait_id);
    let (lane, frame) = lanes.frames().find(|(_, frame)| frame.key == key).ok_or(
        ProviderWaitSelectionError::Lane(LaneError::Suspension(SuspensionError::NotFound)),
    )?;
    if frame.owner != completion.owner
        || matches!(completion.owner.caller, SuspensionCaller::Kernel { lane: owner_lane } if owner_lane != lane)
    {
        return Err(ProviderWaitSelectionError::OwnerMismatch);
    }
    if frame.admission_sequence != completion.admission_sequence {
        return Err(ProviderWaitSelectionError::SequenceMismatch);
    }
    if !matches!(frame.phase, SuspensionPhase::Waiting) {
        return Err(ProviderWaitSelectionError::Lane(LaneError::Suspension(
            SuspensionError::InvalidPhase,
        )));
    }
    let result = route(lane, &frame.continuation, &completion)
        .map_err(ProviderWaitSelectionError::Continuation)?;
    lanes
        .select(key, result)
        .map_err(ProviderWaitSelectionError::Lane)?;
    Ok(lane)
}

#[cfg(test)]
#[path = "provider_wait_selection_tests.rs"]
mod tests;
