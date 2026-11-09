//! Exact root ownership while a retained component callback waits for local child work.

/// Native ingress owns the move-only ticket for an unexecuted original Call. This
/// coordinator never copies the physical Reply or binding representation. The
/// callback's child receipt is kept by its separate retained-dispatch owner.
#[derive(Debug)]
pub struct RootChildTurn<O, I> {
    owner: O,
    ingress: Option<I>,
    retry_deadline: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootChildTurnError {
    WrongOwner,
    IngressAlreadyRetained,
    InvalidRetryInterval,
    DeadlineOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootChildArrival {
    Timer { now: u64 },
    Irq,
    /// Its physical Call and Reply remain in the ingress owner; this is not completion.
    RetainedCall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootChildTurnAction {
    RetrySelected,
    KeepWaiting,
}

impl<O: Copy + Eq, I> RootChildTurn<O, I> {
    pub fn new(owner: O) -> Self {
        Self { owner, ingress: None, retry_deadline: None }
    }

    pub fn owner(&self) -> O { self.owner }

    fn require_owner(&self, observed: O) -> Result<(), RootChildTurnError> {
        if self.owner == observed { Ok(()) } else { Err(RootChildTurnError::WrongOwner) }
    }

    /// An unsuccessful attachment returns the original ticket to its caller, never drops it.
    pub fn retain_ingress(
        &mut self,
        observed: O,
        ingress: I,
    ) -> Result<(), (RootChildTurnError, I)> {
        if let Err(error) = self.require_owner(observed) { return Err((error, ingress)); }
        if self.ingress.is_some() {
            return Err((RootChildTurnError::IngressAlreadyRetained, ingress));
        }
        self.ingress = Some(ingress);
        Ok(())
    }

    pub fn retained_ingress(
        &self,
        observed: O,
    ) -> Result<Option<&I>, RootChildTurnError> {
        self.require_owner(observed)?;
        Ok(self.ingress.as_ref())
    }

    /// Publishes a bounded wake request. Native timer ownership must arm this deadline
    /// before a blocking receive; a failed physical arm retains this whole turn.
    pub fn arm_retry(
        &mut self,
        observed: O,
        now: u64,
        interval: u64,
    ) -> Result<u64, RootChildTurnError> {
        self.require_owner(observed)?;
        if interval == 0 { return Err(RootChildTurnError::InvalidRetryInterval); }
        let deadline = now.checked_add(interval).ok_or(RootChildTurnError::DeadlineOverflow)?;
        self.retry_deadline = Some(deadline);
        Ok(deadline)
    }

    pub fn retry_deadline(
        &self,
        observed: O,
    ) -> Result<Option<u64>, RootChildTurnError> {
        self.require_owner(observed)?;
        Ok(self.retry_deadline)
    }

    /// An unrelated Call stays retained by ingress. Only a notification requests
    /// another selected child/parent pass; stale timer ticks cannot consume a newer
    /// deadline. The caller still authenticates the exact physical notification.
    pub fn observe_arrival(
        &mut self,
        observed: O,
        arrival: RootChildArrival,
    ) -> Result<RootChildTurnAction, RootChildTurnError> {
        self.require_owner(observed)?;
        match arrival {
            RootChildArrival::RetainedCall => Ok(RootChildTurnAction::KeepWaiting),
            RootChildArrival::Irq => Ok(RootChildTurnAction::RetrySelected),
            RootChildArrival::Timer { now } => {
                if self.retry_deadline.is_some_and(|deadline| now >= deadline) {
                    self.retry_deadline = None;
                }
                Ok(RootChildTurnAction::RetrySelected)
            }
        }
    }

    /// Return the retained physical ingress ticket only for the same generation.
    /// A mismatch returns the move-only turn so an old Reply cannot be lost or reused.
    pub fn settle(self, observed: O) -> Result<Option<I>, Self> {
        if self.owner != observed { return Err(self); }
        Ok(self.ingress)
    }
}
