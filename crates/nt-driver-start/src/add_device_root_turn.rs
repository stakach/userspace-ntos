//! Exact root ownership while a hosted AddDevice pump is physically parked.

/// The native layer supplies the move-only ticket for an unexecuted original Call. This
/// coordinator does not know or duplicate the physical Reply and binding representation.
#[derive(Debug)]
pub struct AddDeviceRootTurn<O, I> {
    owner: O,
    ingress: Option<I>,
    retry_deadline: Option<u64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootTurnError {
    WrongOwner,
    IngressAlreadyRetained,
    InvalidRetryInterval,
    DeadlineOverflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootArrival {
    Timer { now: u64 },
    Irq,
    /// Its physical Call and Reply remain in the ingress owner; this is not completion.
    RetainedCall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RootTurnAction {
    RetrySelected,
    KeepWaiting,
}

impl<O: Copy + Eq, I> AddDeviceRootTurn<O, I> {
    pub fn new(owner: O) -> Self {
        Self { owner, ingress: None, retry_deadline: None }
    }

    pub fn owner(&self) -> O { self.owner }

    fn require_owner(&self, observed: O) -> Result<(), RootTurnError> {
        if self.owner == observed { Ok(()) } else { Err(RootTurnError::WrongOwner) }
    }

    /// An unsuccessful attachment returns the original ticket to its caller, never drops it.
    pub fn retain_ingress(
        &mut self,
        observed: O,
        ingress: I,
    ) -> Result<(), (RootTurnError, I)> {
        if let Err(error) = self.require_owner(observed) { return Err((error, ingress)); }
        if self.ingress.is_some() {
            return Err((RootTurnError::IngressAlreadyRetained, ingress));
        }
        self.ingress = Some(ingress);
        Ok(())
    }

    pub fn retained_ingress(
        &self,
        observed: O,
    ) -> Result<Option<&I>, RootTurnError> {
        self.require_owner(observed)?;
        Ok(self.ingress.as_ref())
    }

    /// Publishes a bounded wake request. The native timer owner must arm this deadline before
    /// entering a blocking receive; a failed physical arm retains this whole turn.
    pub fn arm_retry(
        &mut self,
        observed: O,
        now: u64,
        interval: u64,
    ) -> Result<u64, RootTurnError> {
        self.require_owner(observed)?;
        if interval == 0 { return Err(RootTurnError::InvalidRetryInterval); }
        let deadline = now.checked_add(interval).ok_or(RootTurnError::DeadlineOverflow)?;
        self.retry_deadline = Some(deadline);
        Ok(deadline)
    }

    pub fn retry_deadline(
        &self,
        observed: O,
    ) -> Result<Option<u64>, RootTurnError> {
        self.require_owner(observed)?;
        Ok(self.retry_deadline)
    }

    /// An unrelated Call is retained by ingress. Only a notification can request another
    /// selected child/parent pass, and a stale timer cannot consume a newer retry deadline.
    pub fn observe_arrival(
        &mut self,
        observed: O,
        arrival: RootArrival,
    ) -> Result<RootTurnAction, RootTurnError> {
        self.require_owner(observed)?;
        match arrival {
            RootArrival::RetainedCall => Ok(RootTurnAction::KeepWaiting),
            RootArrival::Irq => Ok(RootTurnAction::RetrySelected),
            RootArrival::Timer { now } => {
                if self.retry_deadline.is_some_and(|deadline| now >= deadline) {
                    self.retry_deadline = None;
                }
                Ok(RootTurnAction::RetrySelected)
            }
        }
    }

    /// The caller receives the retained physical ingress ticket only for the same generation.
    /// A mismatch returns the entire move-only turn so an old Reply cannot be lost or reused.
    pub fn settle(self, observed: O) -> Result<Option<I>, Self> {
        if self.owner != observed { return Err(self); }
        Ok(self.ingress)
    }
}
