//! Kernel result publication after independently authenticated shared-ingress completion.

use super::*;
use nt_component_suspension::peer_registry::PeerRoute;

/// One entered completion operation, not provider completion evidence. Dropping it leaves the
/// activation entered, with its result and Ps references retained and no replay permission.
#[must_use = "record the actual shared ingress completion outcome"]
#[derive(Debug)]
pub struct KernelProviderSharedCompletion {
    caller: KernelProviderCaller,
    route: PeerRoute,
    reply: u64,
    status: u32,
}

impl KernelProviderSharedCompletion {
    pub const fn route(&self) -> PeerRoute {
        self.route
    }
    pub const fn dispatch(&self) -> LaneDispatchIdentity {
        self.caller.dispatch
    }
    pub const fn reply(&self) -> u64 {
        self.reply
    }
}

impl<D> KernelProviderActivations<D> {
    /// Retain a frame-free genuine return without clearing the shared dispatch epoch. The
    /// native adapter must drop all lane/table borrows before querying its retained final Call.
    pub fn begin_shared_completion<C, R, T>(
        &mut self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        catalog: &ProviderDomainCatalog,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        status: u32,
    ) -> Result<KernelProviderSharedCompletion, u32> {
        self.validate_retained(caller, pm, catalog, lanes)?;
        let lane = caller.dispatch.lane();
        if lanes.phase(lane) != Ok(LanePhase::Running)
            || lanes.suspension_count(lane) != Ok(0)
            || lanes.external_depth(lane) != Ok(0)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        let route = lanes
            .peer_route(lane)
            .map_err(|_| STATUS_INVALID_HANDLE)?
            .ok_or(STATUS_INVALID_HANDLE)?;
        let reply = caller.current_binding(lanes)?.reply_object;
        self.enter_shared_completion(caller, route, reply, status)
    }

    fn enter_shared_completion(
        &mut self,
        caller: KernelProviderCaller,
        route: PeerRoute,
        reply: u64,
        status: u32,
    ) -> Result<KernelProviderSharedCompletion, u32> {
        let row = self
            .rows
            .iter_mut()
            .find(|row| row.caller == caller)
            .ok_or(STATUS_INVALID_HANDLE)?;
        row.completion = Some(Completion::SharedEntered {
            status,
            route,
            reply,
        });
        Ok(KernelProviderSharedCompletion {
            caller,
            route,
            reply,
            status,
        })
    }

    /// Retire only the acknowledged semantic terminal. Keep Running and the original epoch for
    /// shared ingress to consume its independently retained completion Call. Local refusal keeps
    /// the terminal ACK for retry; success cannot publish a deliverable kernel result yet.
    pub fn finish_shared_terminal_completion<C, R: Clone, T>(
        &mut self,
        caller: KernelProviderCaller,
        pm: &ProcessManager,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        terminal: TerminalIdentity,
        local_retirement: Result<(), u32>,
    ) -> Result<Option<(KernelProviderSharedCompletion, RetiredTerminal<C, R, T>)>, u32> {
        self.validate_terminal_completion(caller, pm, lanes, terminal)?;
        let route = lanes
            .peer_route(caller.dispatch.lane())
            .map_err(|_| STATUS_INVALID_HANDLE)?
            .ok_or(STATUS_INVALID_HANDLE)?;
        let reply = caller.current_binding(lanes)?.reply_object;
        let row = self
            .rows
            .iter()
            .find(|row| row.caller == caller)
            .ok_or(STATUS_INVALID_HANDLE)?;
        let Some(Completion::TerminalPending { status, .. }) = row.completion else {
            return Err(STATUS_INVALID_HANDLE);
        };
        let Some(retired) = lanes
            .finish_shared_terminal(route, caller.dispatch, terminal, reply, local_retirement)
            .map_err(|_| STATUS_INVALID_HANDLE)?
        else {
            return Ok(None);
        };
        let attempt = self
            .enter_shared_completion(caller, route, reply, status)
            .expect("validated terminal activation disappeared without native effects");
        Ok(Some((attempt, retired)))
    }

    /// `outcome` is the actual retained-ingress completion result, never a fabricated Reply ACK.
    /// An error fences replay, including when the mechanism outcome cannot be determined. Success
    /// must have cleared the epoch on this exact shared peer before a receipt becomes visible.
    pub fn record_shared_completion<C, R, T>(
        &mut self,
        attempt: KernelProviderSharedCompletion,
        pm: &ProcessManager,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        outcome: Result<(), u32>,
    ) -> Result<KernelProviderCompletionReceipt, u32> {
        let row = self
            .rows
            .iter_mut()
            .find(|row| row.caller == attempt.caller)
            .ok_or(STATUS_INVALID_HANDLE)?;
        if row.completion
            != Some(Completion::SharedEntered {
                status: attempt.status,
                route: attempt.route,
                reply: attempt.reply,
            })
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        row.reference.validate(pm)?;
        if let Err(error) = outcome {
            row.completion = Some(Completion::SharedIndeterminate {
                status: attempt.status,
                route: attempt.route,
                reply: attempt.reply,
            });
            return Err(error);
        }
        let lane = attempt.caller.dispatch.lane();
        let binding = lanes.binding(lane).map_err(|_| STATUS_INVALID_HANDLE)?;
        if lanes.peer_route(lane) != Ok(Some(attempt.route))
            || lanes.phase(lane) != Ok(LanePhase::Idle)
            || lanes.active_dispatch_identity(lane) != Ok(None)
            || binding.executor_id != attempt.caller.executor_id
            || binding.receive_endpoint != attempt.caller.receive_endpoint
            || binding.reply_object == 0
            || lanes.suspension_count(lane) != Ok(0)
            || lanes.external_depth(lane) != Ok(0)
        {
            return Err(STATUS_INVALID_HANDLE);
        }
        row.completion = Some(Completion::Ready(attempt.status));
        Ok(KernelProviderCompletionReceipt {
            caller: attempt.caller,
            status: attempt.status,
        })
    }
}
