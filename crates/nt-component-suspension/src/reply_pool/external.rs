use super::*;
use crate::ExternalIngress;

impl<M> IngressReplyPool<M> {
    /// Native must reserve its durable queue before entry and independently authenticate the
    /// exact foreign ThreadBinding. No peer route or component lane is synthesized. The receiver
    /// continues excluding the detached Reply while the returned Call resides in that queue.
    pub fn retain_external<C, R, T, E>(
        &mut self,
        receiver: &mut IngressReceiver<M>,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        executor: u64,
        free_query: impl FnOnce(u64) -> Result<ReplyBindingObservation, E>,
        binding_query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<ExternalIngress<M>, ReplyPoolError<E>> {
        let owner = self.entries.last().ok_or(ReplyPoolError::Empty)?;
        self.validate(owner, receiver, lanes, free_query)?;
        let replacement = self.entries.pop().expect("validated external replacement");
        match receiver.retain_external(lanes, replacement, executor, binding_query) {
            Ok(external) => Ok(external),
            Err((error, replacement)) => {
                self.entries.push(replacement);
                Err(ReplyPoolError::External(error))
            }
        }
    }
}
