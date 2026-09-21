use super::*;

impl<M> IngressReplyPool<M> {
    /// Transfer one uniquely owned spare for construction of a new canonical lane. Native must
    /// reserve a durable pending-initial slot before calling, retain the returned owner through
    /// staging, and consume its metadata only when that exact lane takes canonical ownership.
    /// Failure never removes the pool entry. No numeric capability is reconstructed or returned.
    pub fn take_initial_reply<C, R, T, E>(
        &mut self,
        receiver: &IngressReceiver<M>,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        free_query: impl FnOnce(u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<ComponentIngress<M>, ReplyPoolError<E>> {
        if receiver.phase().is_some() {
            return Err(ReplyPoolError::NotReady);
        }
        let owner = self.entries.last().ok_or(ReplyPoolError::Empty)?;
        self.validate(owner, receiver, lanes, free_query)?;
        Ok(self
            .entries
            .pop()
            .expect("validated initial Reply transfer"))
    }
}

#[cfg(test)]
mod tests;
