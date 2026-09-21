//! Authenticate retained startup publication without prematurely adopting its Reply.

use super::*;

#[cfg(test)]
#[path = "startup_ready_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartupReadyError<E> {
    WrongOwner,
    InvalidMessage,
    InvalidPublication,
    AlreadyPublished,
    OldReplyNotFree,
    ReadyReplyNotBound,
    Query(E),
}

impl IngressReceiver<crate::ReceivedMessage> {
    /// The publication decoder must validate the physical worker's expected lane and stack range.
    /// Callbacks are observational and nonreentrant. Success leaves the ready Call held and the
    /// initial Free Reply canonical; first dispatch uses ordinary retained admission to swap them.
    pub fn ready_from_message<C, R, T, P, E>(
        &mut self,
        route: PeerRoute,
        ready_reply: u64,
        label: u64,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        peers: &PeerRegistry,
        publication_slot: &mut Option<P>,
        decode: impl FnOnce([u64; 5]) -> Option<P>,
        query: impl FnMut(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(), StartupReadyError<E>> {
        self.ready_protocol_from_message(
            route,
            ready_reply,
            label,
            lanes,
            peers,
            publication_slot,
            decode,
            query,
        )
    }

    /// Authenticate a provider-specific exact publication shape. The decoder must compare the
    /// words with independently owned physical identity, never infer authority from the payload.
    pub fn ready_protocol_from_message<const N: usize, C, R, T, P, E>(
        &mut self,
        route: PeerRoute,
        ready_reply: u64,
        label: u64,
        lanes: &mut ComponentSuspensionLanes<C, R, T>,
        peers: &PeerRegistry,
        publication_slot: &mut Option<P>,
        decode: impl FnOnce([u64; N]) -> Option<P>,
        mut query: impl FnMut(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(), StartupReadyError<E>> {
        if publication_slot.is_some() {
            return Err(StartupReadyError::AlreadyPublished);
        }
        if self.phase().is_some() {
            return Err(StartupReadyError::WrongOwner);
        }
        lanes
            .validate_ingress_execution(IngressExecutionOwner::Startup(route))
            .map_err(|_| StartupReadyError::WrongOwner)?;
        if peers
            .resolve_lane(
                route.badge(),
                route.identity().domain,
                route.identity().domain_generation,
                lanes,
            )
            .ok()
            != Some(route)
        {
            return Err(StartupReadyError::WrongOwner);
        }
        // An acknowledged interim fault can still own retention/recovery work. Finish it before
        // releasing Starting; otherwise its startup-only cleanup would lose its execution owner.
        if !matches!(peers.state(route), Ok((_, 1))) {
            return Err(StartupReadyError::WrongOwner);
        }
        let binding = lanes
            .binding(route.identity().lane)
            .map_err(|_| StartupReadyError::WrongOwner)?;
        let call = self
            .store
            .stored_reply(route, ready_reply)
            .map_err(|_| StartupReadyError::WrongOwner)?;
        if binding.reply_object == ready_reply || !call.is_held() {
            return Err(StartupReadyError::WrongOwner);
        }
        let message = call.message();
        if N > 120
            || label == 0
            || label > u64::MAX >> 12
            || message.badge() != route.badge()
            || message.info() != (label << 12) | N as u64
        {
            return Err(StartupReadyError::InvalidMessage);
        }
        let words = core::array::from_fn(|index| {
            message.word(index).expect("validated exact message length")
        });
        let publication = decode(words).ok_or(StartupReadyError::InvalidPublication)?;
        if query(binding.executor_id, binding.reply_object).map_err(StartupReadyError::Query)?
            != ReplyBindingObservation::Free
        {
            return Err(StartupReadyError::OldReplyNotFree);
        }
        if query(binding.executor_id, ready_reply).map_err(StartupReadyError::Query)?
            != ReplyBindingObservation::BoundToTarget
        {
            return Err(StartupReadyError::ReadyReplyNotBound);
        }
        // Publish the physical receipt before releasing startup exclusion. No callback or native
        // effect intervenes, and both Reply owners and the ready Call remain intact.
        *publication_slot = Some(publication);
        lanes
            .lane_mut(route.identity().lane)
            .expect("validated startup lane")
            .phase = crate::LanePhase::Idle;
        lanes.running = None;
        Ok(())
    }
}
