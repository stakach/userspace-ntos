//! Retained acknowledgement state for a provider's final object destruction call.
//!
//! The caller owns exact process/provider identity and the PM retirement ticket separately.
//! This owner prevents replay after provider acceptance or an ambiguous transport outcome.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderFinalizationPhase {
    Pending,
    Invoking,
    Accepted,
    Indeterminate(u32),
}

/// Evidence supplied by the provider transport, not an inference from its NTSTATUS alone.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderFinalizationResult {
    /// The provider entry point provably did not execute.
    NotEntered(u32),
    /// The entry point returned. Negative statuses must denote retryable failed finalization
    /// under the provider contract; partial destructive failure requires `Indeterminate`.
    Returned(u32),
    /// Entry or completion could not be established. The retained status is diagnostic only.
    Indeterminate(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderFinalizationError {
    InvalidPhase,
}

/// Non-clone owner. Mark invocation before IPC and retain it across every transport failure.
#[derive(Debug, PartialEq, Eq)]
pub struct ProviderFinalization {
    phase: ProviderFinalizationPhase,
}

impl ProviderFinalization {
    pub const fn new(required: bool) -> Self {
        Self {
            phase: if required {
                ProviderFinalizationPhase::Pending
            } else {
                ProviderFinalizationPhase::Accepted
            },
        }
    }

    pub const fn phase(&self) -> ProviderFinalizationPhase {
        self.phase
    }

    /// True only when provider destruction completed or this object has no provider destructor.
    pub const fn ready(&self) -> bool {
        matches!(self.phase, ProviderFinalizationPhase::Accepted)
    }

    pub fn begin(&mut self) -> Result<(), ProviderFinalizationError> {
        if self.phase != ProviderFinalizationPhase::Pending {
            return Err(ProviderFinalizationError::InvalidPhase);
        }
        self.phase = ProviderFinalizationPhase::Invoking;
        Ok(())
    }

    pub fn record(
        &mut self,
        result: ProviderFinalizationResult,
    ) -> Result<(), ProviderFinalizationError> {
        if self.phase != ProviderFinalizationPhase::Invoking {
            return Err(ProviderFinalizationError::InvalidPhase);
        }
        self.phase = match result {
            ProviderFinalizationResult::NotEntered(_) => ProviderFinalizationPhase::Pending,
            ProviderFinalizationResult::Returned(0) => ProviderFinalizationPhase::Accepted,
            ProviderFinalizationResult::Returned(status) if status & 0x8000_0000 != 0 => {
                ProviderFinalizationPhase::Pending
            }
            ProviderFinalizationResult::Returned(status)
            | ProviderFinalizationResult::Indeterminate(status) => {
                ProviderFinalizationPhase::Indeterminate(status)
            }
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests;
