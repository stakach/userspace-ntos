use super::*;
use crate::{ExternalIngress, ExternalIngressError};

impl<M> IngressReceiver<M> {
    pub(crate) fn retain_external<C, R, T, E>(
        &mut self,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        replacement: ComponentIngress<M>,
        executor: u64,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<ExternalIngress<M>, (ExternalIngressError<E>, ComponentIngress<M>)> {
        let Some(receive) = self.receive.as_mut() else {
            return Err((ExternalIngressError::WrongOwner, replacement));
        };
        let external = receive.retain_external(
            &mut self.store,
            lanes,
            &mut self.ingress,
            replacement,
            executor,
            query,
        )?;
        self.receive = None;
        Ok(external)
    }

    /// Keep the delivered Call published through the Free query. ACK alone never makes its
    /// Reply available. Native must remove all legacy wait-pool references before recycling the
    /// returned Ready owner, and retain that owner if insertion in a spare pool fails.
    pub fn finish_external<E>(
        &mut self,
        pending: &mut Option<ExternalIngress<M>>,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(ComponentIngress<M>, M), ExternalIngressError<E>> {
        let external = pending.as_ref().ok_or(ExternalIngressError::Empty)?;
        if self.endpoint() != external.ingress.endpoint()
            || !self.store.owns_external(&external.reservation)
        {
            return Err(ExternalIngressError::WrongOwner);
        }
        if external.stop_started() {
            return Err(ExternalIngressError::StopEntered);
        }
        if external.restart_started() {
            return Err(ExternalIngressError::RestartEntered);
        }
        if !external.is_acknowledged() {
            return Err(ExternalIngressError::NotAcknowledged);
        }
        if query(external.executor(), external.reply()).map_err(ExternalIngressError::Query)?
            != ReplyBindingObservation::Free
        {
            return Err(ExternalIngressError::NotFree);
        }
        let mut external = pending.take().expect("preflight external completion");
        self.store.release_external(&mut external.reservation);
        Ok((
            external.ingress,
            external.completed.take().expect("acknowledged payload"),
        ))
    }

    /// Cancel a held or uncertain foreign Call only with its sealed native stop ACK and a fresh
    /// Free proof. This returns the original payload as canceled work, never successful delivery.
    /// Native must remove legacy wait-pool references before recycling the returned Ready owner.
    pub fn finish_cancelled_external<E>(
        &mut self,
        pending: &mut Option<ExternalIngress<M>>,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(ComponentIngress<M>, M), ExternalIngressError<E>> {
        let external = pending.as_ref().ok_or(ExternalIngressError::Empty)?;
        if self.endpoint() != external.ingress.endpoint()
            || !self.store.owns_external(&external.reservation)
        {
            return Err(ExternalIngressError::WrongOwner);
        }
        if !external.is_stopped() {
            return Err(ExternalIngressError::NotStopped);
        }
        if query(external.executor(), external.reply()).map_err(ExternalIngressError::Query)?
            != ReplyBindingObservation::Free
        {
            return Err(ExternalIngressError::NotFree);
        }
        let mut external = pending
            .take()
            .expect("preflight external stop cancellation");
        self.store.release_external(&mut external.reservation);
        let (ingress, held) = external.ingress.into_unbound_parts();
        let message = external
            .completed
            .take()
            .or(held)
            .expect("owned canceled payload");
        Ok((ingress, message))
    }

    /// An atomic context restart consumes the Call without a Reply or Stop. Require its own
    /// sealed ACK and fresh Free proof before returning the original payload and Ready owner.
    pub fn finish_restarted_external<E>(
        &mut self,
        pending: &mut Option<ExternalIngress<M>>,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<(ComponentIngress<M>, M), ExternalIngressError<E>> {
        let external = pending.as_ref().ok_or(ExternalIngressError::Empty)?;
        if self.endpoint() != external.ingress.endpoint()
            || !self.store.owns_external(&external.reservation)
        {
            return Err(ExternalIngressError::WrongOwner);
        }
        if external.stop_started() {
            return Err(ExternalIngressError::StopEntered);
        }
        if !external.is_restarted() {
            return Err(ExternalIngressError::NotRestarted);
        }
        if query(external.executor(), external.reply()).map_err(ExternalIngressError::Query)?
            != ReplyBindingObservation::Free
        {
            return Err(ExternalIngressError::NotFree);
        }
        let mut external = pending
            .take()
            .expect("preflight external restart completion");
        self.store.release_external(&mut external.reservation);
        let (ingress, message) = external.ingress.into_unbound_parts();
        Ok((ingress, message.expect("owned restarted payload")))
    }
}

#[cfg(test)]
mod tests;
