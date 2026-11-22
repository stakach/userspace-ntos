//! When a hosted instance's primary lane counts as parked for ordinary-IRP admission (#427).

use crate::{ComponentSuspensionLanes, LaneDispatchIdentity, LaneHandle, LanePhase};

/// The primary lane is parked in its own dispatch: it is suspended, and the parked provider
/// wait (`parked_wait`, the dispatch whose service wait is parked) is exactly its current
/// dispatch. A waiter of a system thread or DPC that happens to share the primary's route is
/// not a parked dispatch, and never diverts the primary's IRPs to the worker.
pub fn primary_dispatch_parked<C, R, T>(
    lanes: &ComponentSuspensionLanes<C, R, T>,
    primary: LaneHandle,
    parked_wait: Option<LaneDispatchIdentity>,
) -> bool {
    lanes.phase(primary) == Ok(LanePhase::Suspended)
        && matches!(lanes.active_dispatch_identity(primary),
            Ok(Some(dispatch)) if parked_wait == Some(dispatch))
}
