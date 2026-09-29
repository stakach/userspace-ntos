//! Exact-owner publication of a provider Section unmap result.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmapPhase {
    Prepared,
    InFlight,
    PublishedUnacknowledged,
    EffectUncertain,
    Aborted,
    Acknowledged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnmapError {
    WrongOwner,
    InvalidPhase,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnmapCompletion<V> {
    pub view: V,
    pub status: u32,
}

/// One physical dispatch owns one captured view. The adapter reserves its row before beginning
/// the native effect and may discard the row only after a definite acknowledgement or pre-effect
/// abort. An uncertain result is retained, never implicitly replayed.
pub struct UnmapPublication<O, V> {
    owner: O,
    view: V,
    phase: UnmapPhase,
    status: Option<u32>,
}

impl<O: Copy + Eq, V: Copy> UnmapPublication<O, V> {
    pub const fn new(owner: O, view: V) -> Self {
        Self {
            owner,
            view,
            phase: UnmapPhase::Prepared,
            status: None,
        }
    }

    pub fn owner(&self) -> O {
        self.owner
    }

    pub fn phase(&self, owner: O) -> Result<UnmapPhase, UnmapError> {
        self.check_owner(owner)?;
        Ok(self.phase)
    }

    pub fn view(&self, owner: O) -> Result<V, UnmapError> {
        self.check_owner(owner)?;
        Ok(self.view)
    }

    pub fn begin_effect(&mut self, owner: O) -> Result<(), UnmapError> {
        self.check_owner(owner)?;
        if self.phase != UnmapPhase::Prepared {
            return Err(UnmapError::InvalidPhase);
        }
        self.phase = UnmapPhase::InFlight;
        Ok(())
    }

    /// Record the definite native completion, including a failing NTSTATUS. The caller retains
    /// responsibility for any partial physical cleanup associated with an error status.
    pub fn complete(&mut self, owner: O, status: u32) -> Result<(), UnmapError> {
        self.check_owner(owner)?;
        if self.phase != UnmapPhase::InFlight {
            return Err(UnmapError::InvalidPhase);
        }
        self.status = Some(status);
        self.phase = UnmapPhase::PublishedUnacknowledged;
        Ok(())
    }

    pub fn acknowledge(&mut self, owner: O) -> Result<UnmapCompletion<V>, UnmapError> {
        self.check_owner(owner)?;
        if self.phase != UnmapPhase::PublishedUnacknowledged {
            return Err(UnmapError::InvalidPhase);
        }
        let status = self.status.expect("published unmap has a definite status");
        self.phase = UnmapPhase::Acknowledged;
        Ok(UnmapCompletion {
            view: self.view,
            status,
        })
    }

    /// Abort is legal only before the effect begins. Once in flight, even an error or a lost
    /// reply cannot establish that the view is safe to discard or reuse.
    pub fn abort_before_effect(&mut self, owner: O) -> Result<V, UnmapError> {
        self.check_owner(owner)?;
        if self.phase != UnmapPhase::Prepared {
            return Err(UnmapError::InvalidPhase);
        }
        self.phase = UnmapPhase::Aborted;
        Ok(self.view)
    }

    /// Retire only this physical dispatch. A published response without ACK is still uncertain
    /// to the provider, regardless of whether the native operation returned success or failure.
    pub fn retire_dispatch(&mut self, owner: O) -> Result<UnmapPhase, UnmapError> {
        self.check_owner(owner)?;
        self.phase = match self.phase {
            UnmapPhase::Prepared => UnmapPhase::Aborted,
            UnmapPhase::InFlight | UnmapPhase::PublishedUnacknowledged => {
                UnmapPhase::EffectUncertain
            }
            _ => return Err(UnmapError::InvalidPhase),
        };
        Ok(self.phase)
    }

    fn check_owner(&self, owner: O) -> Result<(), UnmapError> {
        if self.owner == owner {
            Ok(())
        } else {
            Err(UnmapError::WrongOwner)
        }
    }
}

#[cfg(test)]
mod tests;
