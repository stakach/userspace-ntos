//! Bootstrap scheduling authority, independent of shared ingress payload and Reply ownership.

use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapReceiveError {
    IdentityExhausted,
    WrongTarget,
    AlreadyAcknowledged,
    NotAcknowledged,
    CompletionTaken,
    Blocked,
    TargetComplete,
    ReceiveEntered,
    WrongPermit,
}

/// Fresh observations after the complete deadline checkpoint, never authority on their own.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapReceiveFacts {
    pub bootstrap_owned: bool,
    pub invocation_active: bool,
    pub pass_active: bool,
    pub timer_delivery_active: bool,
    pub physical_execution_active: bool,
    pub rearm_pending: bool,
}

impl BootstrapReceiveFacts {
    /// Only retained checkpoint work permits another service cycle. An active owner or
    /// transferred bootstrap store is not permission to spin until that owner disappears.
    pub fn needs_service(self) -> bool {
        self.rearm_pending
            && Self {
                rearm_pending: false,
                ..self
            }
            .permits_receive()
    }

    fn permits_receive(self) -> bool {
        self.bootstrap_owned
            && !self.invocation_active
            && !self.pass_active
            && !self.timer_delivery_active
            && !self.physical_execution_active
            && !self.rearm_pending
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Idle,
    Permitted(u64),
    Entered(u64),
}

/// A one-shot scheduling permit. It cannot authorize a Reply or carry an incoming message.
#[derive(Debug)]
#[must_use = "enter this receive once, or invalidate it at the next checkpoint"]
pub struct BootstrapReceivePermit {
    owner: u64,
    generation: u64,
    entered: bool,
    finished: bool,
}

/// Retain this coordinator across bounded passes and all fallible deadline operations.
pub struct BootstrapCoordinator<T> {
    target: T,
    owner: u64,
    generation: u64,
    phase: Phase,
    acknowledged: Option<bool>,
    completion_taken: bool,
}

impl<T: Copy + Eq> BootstrapCoordinator<T> {
    pub fn new(target: T) -> Result<Self, BootstrapReceiveError> {
        let owner = NEXT_OWNER
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            })
            .map_err(|_| BootstrapReceiveError::IdentityExhausted)?;
        Ok(Self {
            target,
            owner,
            generation: 0,
            phase: Phase::Idle,
            acknowledged: None,
            completion_taken: false,
        })
    }

    pub fn acknowledge(
        &mut self,
        target: T,
        initialized: bool,
    ) -> Result<(), BootstrapReceiveError> {
        if target != self.target {
            return Err(BootstrapReceiveError::WrongTarget);
        }
        if self.acknowledged.is_some() {
            return Err(BootstrapReceiveError::AlreadyAcknowledged);
        }
        self.acknowledged = Some(initialized);
        // A receive already entered remains owned until its arrival is observed.
        if !matches!(self.phase, Phase::Entered(_)) {
            self.phase = Phase::Idle;
        }
        Ok(())
    }

    pub fn completion(&self) -> Option<bool> {
        if self.completion_taken {
            None
        } else {
            self.acknowledged
        }
    }

    pub fn take_completion(&mut self) -> Result<bool, BootstrapReceiveError> {
        if matches!(self.phase, Phase::Entered(_)) {
            return Err(BootstrapReceiveError::ReceiveEntered);
        }
        if self.completion_taken {
            return Err(BootstrapReceiveError::CompletionTaken);
        }
        let initialized = self
            .acknowledged
            .ok_or(BootstrapReceiveError::NotAcknowledged)?;
        self.completion_taken = true;
        Ok(initialized)
    }

    /// Call before any fallible checkpoint work, including collection or programming. Failure
    /// must never leave the previous checkpoint's unentered permission usable.
    pub fn invalidate_checkpoint(&mut self) -> Result<(), BootstrapReceiveError> {
        if matches!(self.phase, Phase::Entered(_)) {
            return Err(BootstrapReceiveError::ReceiveEntered);
        }
        self.phase = Phase::Idle;
        Ok(())
    }

    pub fn checkpoint(
        &mut self,
        facts: BootstrapReceiveFacts,
    ) -> Result<BootstrapReceivePermit, BootstrapReceiveError> {
        self.invalidate_checkpoint()?;
        if self.acknowledged.is_some() {
            return Err(BootstrapReceiveError::TargetComplete);
        }
        if !facts.permits_receive() {
            return Err(BootstrapReceiveError::Blocked);
        }
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(BootstrapReceiveError::IdentityExhausted)?;
        self.phase = Phase::Permitted(self.generation);
        Ok(BootstrapReceivePermit {
            owner: self.owner,
            generation: self.generation,
            entered: false,
            finished: false,
        })
    }

    pub fn enter_receive(
        &mut self,
        permit: &mut BootstrapReceivePermit,
    ) -> Result<(), BootstrapReceiveError> {
        if permit.owner != self.owner
            || permit.entered
            || permit.finished
            || self.phase != Phase::Permitted(permit.generation)
        {
            return Err(BootstrapReceiveError::WrongPermit);
        }
        permit.entered = true;
        self.phase = Phase::Entered(permit.generation);
        Ok(())
    }

    /// Only an observed arrival finishes the scheduling effect. An uncertain receive leaves
    /// Entered intact; unrelated arrivals finish it without changing the target completion.
    pub fn finish_receive(
        &mut self,
        permit: &mut BootstrapReceivePermit,
    ) -> Result<(), BootstrapReceiveError> {
        if permit.owner != self.owner
            || !permit.entered
            || permit.finished
            || self.phase != Phase::Entered(permit.generation)
        {
            return Err(BootstrapReceiveError::WrongPermit);
        }
        permit.finished = true;
        self.phase = Phase::Idle;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
