//! Retire semantic delivery while retaining the shared ingress dispatch's completion authority.

use super::*;

#[cfg(test)]
mod tests;

impl<C, R: Clone, T> ComponentSuspensionLanes<C, R, T> {
    /// Finish acknowledged semantic delivery, not the provider dispatch. The adapter must retain
    /// the exact physical peer lifetime and independently authenticate its final completion Call.
    /// Success preserves the epoch and reacquires Running ownership for retained completion. Any
    /// remaining outer frame/token still prevents dispatch completion; use the existing typed
    /// retirement transitions (including `retire_external_running`) before completing ingress.
    /// No native effect occurs here. An entered/uncertain terminal or unrelated execution refuses
    /// without consuming the semantic owner. Failed local bookkeeping retains its ACK for retry.
    pub fn finish_shared_terminal(
        &mut self,
        route: peer_registry::PeerRoute,
        dispatch: LaneDispatchIdentity,
        identity: TerminalIdentity,
        reply_object: u64,
        local_retirement: Result<(), u32>,
    ) -> Result<Option<RetiredTerminal<C, R, T>>, LaneError> {
        let record = self.terminal_record(identity, reply_object)?;
        let lane = self.lane(identity.lane())?;
        if route.identity().lane != identity.lane()
            || lane.shared_peer != Some(route)
            || dispatch != identity.dispatch
            || lane.dispatch != Some(dispatch)
            || lane.binding.executor_id != route.identity().executor
            || lane.binding.receive_endpoint != route.endpoint()
        {
            return Err(LaneError::InvalidIdentity);
        }
        if !matches!(record.phase, TerminalPhase::Acknowledged { .. }) {
            return Err(LaneError::InvalidPhase);
        }
        if self.execution_busy() {
            return Err(LaneError::Busy);
        }
        self.finish_terminal_with_execution(identity, reply_object, local_retirement, true)
    }
}
