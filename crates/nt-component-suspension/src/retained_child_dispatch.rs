//! Move-only ownership of a dispatch parked for one nested child-work step.
//!
//! The native adapter authenticates the physical route, dispatch, Reply and epoch represented
//! by `K`. This row compares that entire key at every transition. It never executes a child,
//! restores a physical parent, or manufactures a provider completion.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedChildDispatchError {
    WrongParent,
    InvalidPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedChildDispatchPhase {
    Entered,
    Parked,
    Restoring,
    /// Native continuation holds the already-run child receipt after a no-effect refusal.
    RestoreRetry,
    Restored,
    Consumed,
}

/// The `owners` bundle holds the native continuation and any rollback or registry tokens.
/// A child receipt is retained separately so an already-run child cannot be run again after
/// a no-effect restore refusal. Only an authenticated native terminal may be offered to
/// `finish_terminal`; this type checks ownership and ordering, not the native observation.
#[must_use = "retain the physical dispatch owners until exact terminal acknowledgement"]
pub struct RetainedChildDispatch<K, B, S> {
    key: K,
    owners: Option<B>,
    child_step: Option<S>,
    phase: RetainedChildDispatchPhase,
}

impl<K: Copy + Eq, B, S> RetainedChildDispatch<K, B, S> {
    pub fn retain(key: K, owners: B) -> Self {
        Self { key, owners: Some(owners), child_step: None,
            phase: RetainedChildDispatchPhase::Entered }
    }

    pub const fn key(&self) -> K { self.key }
    pub const fn phase(&self) -> RetainedChildDispatchPhase { self.phase }

    fn exact(&self, key: K) -> Result<(), RetainedChildDispatchError> {
        if self.key == key { Ok(()) } else { Err(RetainedChildDispatchError::WrongParent) }
    }

    pub fn owners(&self, key: K) -> Result<&B, RetainedChildDispatchError> {
        self.exact(key)?;
        self.owners.as_ref().ok_or(RetainedChildDispatchError::InvalidPhase)
    }

    pub fn owners_mut(&mut self, key: K) -> Result<&mut B, RetainedChildDispatchError> {
        self.exact(key)?;
        self.owners.as_mut().ok_or(RetainedChildDispatchError::InvalidPhase)
    }

    /// A parked dispatch still owns its Reply and cannot report a terminal result.
    pub fn park_for_child(&mut self, key: K) -> Result<(), RetainedChildDispatchError> {
        self.exact(key)?;
        if self.phase != RetainedChildDispatchPhase::Entered {
            return Err(RetainedChildDispatchError::InvalidPhase);
        }
        self.phase = RetainedChildDispatchPhase::Parked;
        Ok(())
    }

    /// Move the one-use receipt into the parent before attempting any fallible restoration.
    /// A refusal returns the offered receipt to its caller unchanged.
    pub fn record_child_step(
        &mut self, key: K, step: S,
    ) -> Result<(), (RetainedChildDispatchError, S)> {
        if let Err(error) = self.exact(key) { return Err((error, step)); }
        if self.phase != RetainedChildDispatchPhase::Parked || self.child_step.is_some() {
            return Err((RetainedChildDispatchError::InvalidPhase, step));
        }
        self.child_step = Some(step);
        Ok(())
    }

    pub fn begin_restore(&mut self, key: K) -> Result<(), RetainedChildDispatchError> {
        self.exact(key)?;
        if !matches!(self.phase,
            RetainedChildDispatchPhase::Parked if self.child_step.is_some())
            && self.phase != RetainedChildDispatchPhase::RestoreRetry
        {
            return Err(RetainedChildDispatchError::InvalidPhase);
        }
        self.phase = RetainedChildDispatchPhase::Restoring;
        Ok(())
    }

    /// A native continuation may already own a retryable nested physical restore ticket
    /// before any child certificate exists. Its adapter must prove that exact ticket before
    /// calling this method; the row creates no child and retains the original dispatch.
    pub fn begin_restore_without_child(
        &mut self, key: K,
    ) -> Result<(), RetainedChildDispatchError> {
        self.exact(key)?;
        if self.phase != RetainedChildDispatchPhase::Parked || self.child_step.is_some() {
            return Err(RetainedChildDispatchError::InvalidPhase);
        }
        self.phase = RetainedChildDispatchPhase::Restoring;
        Ok(())
    }

    /// Only a certified no-effect refusal may retry with the same retained child receipt.
    pub fn refuse_restore_no_effects(
        &mut self, key: K,
    ) -> Result<(), RetainedChildDispatchError> {
        self.exact(key)?;
        if self.phase != RetainedChildDispatchPhase::Restoring {
            return Err(RetainedChildDispatchError::InvalidPhase);
        }
        self.phase = if self.child_step.is_some() {
            RetainedChildDispatchPhase::Parked
        } else {
            // The native continuation owns the same receipt. The root must retry that
            // restoration without selecting or running another child.
            RetainedChildDispatchPhase::RestoreRetry
        };
        Ok(())
    }

    /// Call only after the physical parent and exact Reply are restored.
    pub fn acknowledge_restore(&mut self, key: K) -> Result<(), RetainedChildDispatchError> {
        self.exact(key)?;
        if self.phase != RetainedChildDispatchPhase::Restoring || self.child_step.is_some() {
            return Err(RetainedChildDispatchError::InvalidPhase);
        }
        self.phase = RetainedChildDispatchPhase::Restored;
        Ok(())
    }

    /// Hand the already-run child step to native restoration exactly once. The native
    /// continuation must retain it on any refusal; this row keeps the parent owners.
    pub fn take_child_step_for_native_restore(
        &mut self, key: K,
    ) -> Result<S, RetainedChildDispatchError> {
        self.exact(key)?;
        if self.phase != RetainedChildDispatchPhase::Restoring {
            return Err(RetainedChildDispatchError::InvalidPhase);
        }
        self.child_step.take().ok_or(RetainedChildDispatchError::InvalidPhase)
    }

    /// A real native child-ready result starts a new pass on this same parent. It may follow
    /// either physical restoration or a scheduler yield during the previous restore attempt.
    pub fn repark_after_native_yield(&mut self, key: K) -> Result<(), RetainedChildDispatchError> {
        self.repark_after_native_yield_with_key(key, key)
    }

    /// Atomically replace the physical witness when native authenticated a fresh child-ready
    /// result. The old Reply cannot select the parked parent or offer another child receipt.
    pub fn repark_after_native_yield_with_key(
        &mut self, old_key: K, new_key: K,
    ) -> Result<(), RetainedChildDispatchError> {
        self.exact(old_key)?;
        if !matches!(self.phase,
            RetainedChildDispatchPhase::Restoring | RetainedChildDispatchPhase::Restored)
            || self.child_step.is_some()
        {
            return Err(RetainedChildDispatchError::InvalidPhase);
        }
        self.key = new_key;
        self.phase = RetainedChildDispatchPhase::Parked;
        Ok(())
    }

    /// Release move-only owners only after a resumed native pump produced an authenticated
    /// terminal. A refusal returns that real terminal untouched; it cannot become completion.
    pub fn finish_terminal<T>(
        &mut self, key: K, terminal: T,
    ) -> Result<(B, T), (RetainedChildDispatchError, T)> {
        if let Err(error) = self.exact(key) { return Err((error, terminal)); }
        if self.phase != RetainedChildDispatchPhase::Restored || self.child_step.is_some() {
            return Err((RetainedChildDispatchError::InvalidPhase, terminal));
        }
        let Some(owners) = self.owners.take() else {
            return Err((RetainedChildDispatchError::InvalidPhase, terminal));
        };
        self.phase = RetainedChildDispatchPhase::Consumed;
        Ok((owners, terminal))
    }
}
