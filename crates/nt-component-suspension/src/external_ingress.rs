//! A foreign hosted Call retains transport authority without inventing a component peer.

use crate::{
    ComponentIngress, IngressError, IngressReplyAttempt, IngressReplyObservation,
    ReplyBindingObservation, ReservedReceiveError, RetainedWorkError, RetainedWorkReservation,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalIngressError<E> {
    WrongOwner,
    Empty,
    NotAcknowledged,
    NotBound,
    NotFree,
    NotStopped,
    StopEntered,
    RestartEntered,
    NotRestarted,
    Stop(E),
    Query(E),
    Store(RetainedWorkError),
    Receive(ReservedReceiveError<E>),
    Ingress(IngressError),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum StopPhase {
    NotEntered,
    Entered,
    Acknowledged,
}

/// A restart cancels the bound Call without sending a Reply. Rejection must prove no mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalRestartObservation<E> {
    Acknowledged,
    Rejected(E),
    Indeterminate,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RestartPhase {
    NotEntered,
    Entered,
    Acknowledged,
}

/// Native owns the separately authenticated ThreadBinding (domain, generation and TCB lifetime).
/// Numeric accessors and cloned message views are observations, never transfers of this owner.
/// The receiver keeps excluding this Reply until `finish_external` consumes acknowledged work.
#[must_use = "retain the external Call through delivery, waits and uncertain Reply effects"]
pub struct ExternalIngress<M> {
    pub(crate) ingress: ComponentIngress<M>,
    pub(crate) reservation: RetainedWorkReservation,
    pub(crate) executor: u64,
    pub(crate) completed: Option<M>,
    attempt: Option<IngressReplyAttempt>,
    stop: StopPhase,
    restart: RestartPhase,
}

impl<M> ExternalIngress<M> {
    pub(crate) fn new(
        ingress: ComponentIngress<M>,
        reservation: RetainedWorkReservation,
        executor: u64,
    ) -> Self {
        Self {
            ingress,
            reservation,
            executor,
            completed: None,
            attempt: None,
            stop: StopPhase::NotEntered,
            restart: RestartPhase::NotEntered,
        }
    }
    pub fn reply(&self) -> u64 {
        self.ingress.reply()
    }
    pub fn executor(&self) -> u64 {
        self.executor
    }
    pub fn message(&self) -> &M {
        self.completed
            .as_ref()
            .or_else(|| self.ingress.message())
            .expect("owned external payload")
    }
    pub fn is_acknowledged(&self) -> bool {
        self.completed.is_some()
    }

    /// The original held Call can transfer into a wait owner only before Reply or Stop entry.
    pub fn can_park(&self) -> bool {
        self.attempt.is_none()
            && self.completed.is_none()
            && !self.stop_started()
            && !self.restart_started()
    }

    pub fn restart_started(&self) -> bool {
        self.restart != RestartPhase::NotEntered
    }

    pub fn is_restarted(&self) -> bool {
        self.restart == RestartPhase::Acknowledged
    }

    /// Publish entry before the atomic context restart. A known rejection restores the held
    /// Call, allowing an NT failure Reply; an uncertain result never permits restart replay.
    pub fn restart_owned<E>(
        &mut self,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
        invoke: impl FnOnce(u64) -> ExternalRestartObservation<E>,
    ) -> Result<ExternalRestartObservation<E>, ExternalIngressError<E>> {
        if self.restart_started() {
            return Err(ExternalIngressError::RestartEntered);
        }
        if !self.can_park() {
            return Err(ExternalIngressError::Ingress(IngressError::NotReady));
        }
        if query(self.executor, self.reply()).map_err(ExternalIngressError::Query)?
            != ReplyBindingObservation::BoundToTarget
        {
            return Err(ExternalIngressError::NotBound);
        }
        self.restart = RestartPhase::Entered;
        let observation = invoke(self.executor);
        self.restart = match &observation {
            ExternalRestartObservation::Acknowledged => RestartPhase::Acknowledged,
            ExternalRestartObservation::Rejected(_) => RestartPhase::NotEntered,
            ExternalRestartObservation::Indeterminate => RestartPhase::Entered,
        };
        Ok(observation)
    }

    pub fn is_stopped(&self) -> bool {
        self.stop == StopPhase::Acknowledged
    }

    pub fn stop_started(&self) -> bool {
        self.stop != StopPhase::NotEntered
    }

    /// Retain the exact physical ThreadBinding and publish this owner before invoking native
    /// stop. An error is indeterminate and never permits replay; an acknowledged repeated logical
    /// stop is idempotent without another effect. Stop does not acknowledge the retained Reply.
    pub fn stop_owned<E>(
        &mut self,
        invoke: impl FnOnce(u64) -> Result<(), E>,
    ) -> Result<(), ExternalIngressError<E>> {
        match self.stop {
            StopPhase::Acknowledged => return Ok(()),
            StopPhase::Entered => return Err(ExternalIngressError::StopEntered),
            StopPhase::NotEntered => {}
        }
        self.stop = StopPhase::Entered;
        invoke(self.executor).map_err(ExternalIngressError::Stop)?;
        self.stop = StopPhase::Acknowledged;
        Ok(())
    }

    /// The native closure may send the configured full IPC payload. Retain this owner in its
    /// durable native slot during the effect, and independently authenticate ThreadBinding.
    pub fn reply_owned<E>(
        &mut self,
        query: impl FnOnce(u64, u64) -> Result<ReplyBindingObservation, E>,
        invoke: impl FnOnce(u64) -> IngressReplyObservation,
    ) -> Result<IngressReplyObservation, ExternalIngressError<E>> {
        if self.stop_started()
            || self.restart_started()
            || self.attempt.is_some()
            || self.completed.is_some()
        {
            return Err(ExternalIngressError::Ingress(IngressError::NotReady));
        }
        if query(self.executor, self.reply()).map_err(ExternalIngressError::Query)?
            != ReplyBindingObservation::BoundToTarget
        {
            return Err(ExternalIngressError::NotBound);
        }
        self.attempt = Some(
            self.ingress
                .begin_reply()
                .map_err(ExternalIngressError::Ingress)?,
        );
        let observation = invoke(self.reply());
        self.completed = self
            .ingress
            .observe_reply(
                self.attempt.as_mut().expect("published external attempt"),
                observation,
            )
            .map_err(ExternalIngressError::Ingress)?;
        if observation != IngressReplyObservation::Indeterminate {
            self.attempt = None;
        }
        Ok(observation)
    }
}
