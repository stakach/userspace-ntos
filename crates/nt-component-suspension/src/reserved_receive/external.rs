use super::*;
use crate::{ExternalIngress, ExternalIngressError};

impl ReservedIngressReceive {
    pub(crate) fn retain_external<M, C, R, T, E>(
        &mut self,
        store: &mut RetainedWork<M>,
        lanes: &ComponentSuspensionLanes<C, R, T>,
        ingress: &mut ComponentIngress<M>,
        replacement: ComponentIngress<M>,
        executor: u64,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
    ) -> Result<ExternalIngress<M>, (ExternalIngressError<E>, ComponentIngress<M>)> {
        let check = (|| {
            if self.phase != ReservedReceivePhase::Held || executor == 0 {
                return Err(ExternalIngressError::WrongOwner);
            }
            self.validate(store, ingress)
                .map_err(ExternalIngressError::Receive)?;
            if store.excludes_reply(replacement.reply()) {
                return Err(ExternalIngressError::Store(RetainedWorkError::ReplyInUse));
            }
            if query(executor, ingress.reply()).map_err(ExternalIngressError::Query)?
                != ReplyBindingObservation::BoundToTarget
            {
                return Err(ExternalIngressError::NotBound);
            }
            Ok(())
        })();
        if let Err(error) = check {
            return Err((error, replacement));
        }
        let held = lanes
            .handoff_ingress_call_for_owner(ingress, replacement, self.execution_owner)
            .map_err(|(error, owner)| (ExternalIngressError::Ingress(error), owner))?;
        let reservation = self.reservation.take().expect("preflight external receive");
        store.mark_external(&reservation);
        self.phase = ReservedReceivePhase::Finished;
        Ok(ExternalIngress::new(held, reservation, executor))
    }
}
