//! Retained interim VM faults never become dispatches or release startup exclusion.

use super::*;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupFaultError<E> {
    WrongOwner,
    InvalidMessage,
    NotHeld,
    NotAcknowledged,
    BindingMismatch,
    Query(E),
    Store(RetainedWorkError),
    Ingress(crate::IngressError),
    Finish(RetainedWorkFinishError),
}

impl IngressReceiver<crate::ReceivedMessage> {
    fn validate_startup_fault<C, R, T, E>(
        &self,
        route: PeerRoute,
        reply: u64,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        peers: &PeerRegistry,
    ) -> Result<(), StartupFaultError<E>> {
        lanes
            .validate_ingress_execution(IngressExecutionOwner::Startup(route))
            .map_err(|_| StartupFaultError::WrongOwner)?;
        if peers
            .resolve_lane(
                route.badge(),
                route.identity().domain,
                route.identity().domain_generation,
                lanes,
            )
            .ok()
            != Some(route)
            || lanes
                .binding(route.identity().lane)
                .map(|b| b.reply_object == reply)
                .unwrap_or(true)
        {
            return Err(StartupFaultError::WrongOwner);
        }
        let call = self
            .store
            .stored_reply(route, reply)
            .map_err(StartupFaultError::Store)?;
        // seL4 AMD64 VMFault: FaultIP, FaultAddress, PrefetchFault, FSR; no caps/unwrapping.
        if call.admitted.is_some()
            || call.message().badge() != route.badge()
            || call.message().info() != (6 << 12) | 4
        {
            return Err(StartupFaultError::InvalidMessage);
        }
        Ok(())
    }

    /// Authenticate before native mapping/service and zero-word reply. The operation's attempt
    /// is stored before either effect; the full message and peer retention stay in this owner.
    /// Callbacks are nonreentrant and preserve physical lifetimes. NoEffects is valid only when
    /// neither service nor reply had effects; any uncertain service must return Indeterminate.
    pub fn service_startup_fault<C, R, T, E>(
        &mut self,
        route: PeerRoute,
        reply: u64,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        peers: &PeerRegistry,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
        invoke: impl FnOnce(u64, [u64; 4]) -> crate::IngressReplyObservation,
    ) -> Result<crate::IngressReplyObservation, StartupFaultError<E>> {
        self.validate_startup_fault(route, reply, lanes, peers)?;
        let call = self
            .store
            .stored_reply_mut(route, reply)
            .map_err(StartupFaultError::Store)?;
        if !call.is_held() {
            return Err(StartupFaultError::NotHeld);
        }
        if query(route.identity().executor, reply).map_err(StartupFaultError::Query)?
            != ReplyBindingObservation::BoundToTarget
        {
            return Err(StartupFaultError::BindingMismatch);
        }
        let words = core::array::from_fn(|i| call.message().word(i).expect("four-word VM fault"));
        call.reply_owned(|reply| invoke(reply, words))
            .map_err(StartupFaultError::Ingress)
    }

    /// Recover only an acknowledged, free interim fault Reply, not the canonical startup Reply.
    /// The caller must durably own the returned Reply before pool insertion; failure to insert is
    /// not permission to drop it. Query/finish refusal leaves the complete Call stored for retry.
    pub fn finish_startup_fault<C, R, T, E>(
        &mut self,
        route: PeerRoute,
        reply: u64,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        peers: &mut PeerRegistry,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<
        (
            ComponentIngress<crate::ReceivedMessage>,
            crate::ReceivedMessage,
        ),
        StartupFaultError<E>,
    > {
        self.validate_startup_fault(route, reply, lanes, peers)?;
        if !self
            .store
            .stored_reply(route, reply)
            .map_err(StartupFaultError::Store)?
            .is_acknowledged()
        {
            return Err(StartupFaultError::NotAcknowledged);
        }
        if query(route.identity().executor, reply).map_err(StartupFaultError::Query)?
            != ReplyBindingObservation::Free
        {
            return Err(StartupFaultError::BindingMismatch);
        }
        let checkout = self
            .store
            .checkout_reply(route, reply)
            .map_err(StartupFaultError::Store)?;
        match self.store.finish_checkout(checkout, peers) {
            Ok(result) => Ok(result),
            Err((error, checkout)) => {
                assert!(self.store.restore(checkout).is_ok());
                Err(StartupFaultError::Finish(error))
            }
        }
    }
}
