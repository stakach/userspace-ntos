//! A result that cannot leave its exact nested parent until restoration is acknowledged.
//!
//! The native adapter owns the physical hold and Reply. This record holds the semantic result
//! through a refused restore without granting authority to replay any uncertain native effect.

use crate::NestedExecutionIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedRestoreResultKey {
    scope: NestedExecutionIdentity,
    parent_reply: u64,
}

impl NestedRestoreResultKey {
    pub const fn new(scope: NestedExecutionIdentity, parent_reply: u64) -> Option<Self> {
        if parent_reply == 0 { None } else { Some(Self { scope, parent_reply }) }
    }

    pub const fn scope(self) -> NestedExecutionIdentity { self.scope }
    pub const fn parent_reply(self) -> u64 { self.parent_reply }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedRestoreResultPhase {
    Retained,
    Restoring,
    Quarantined,
    Restored,
    Consumed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedRestoreResultError {
    InvalidIdentity,
    InvalidPhase,
}

/// The exact parent scope and Reply gate a one-use result handoff after physical restoration.
#[must_use = "retain the result until the exact nested parent is restored"]
pub struct NestedRestoreResult<R> {
    key: NestedRestoreResultKey,
    phase: NestedRestoreResultPhase,
    result: Option<R>,
}

impl<R> NestedRestoreResult<R> {
    pub fn retain(key: NestedRestoreResultKey, result: R) -> Self {
        Self { key, phase: NestedRestoreResultPhase::Retained, result: Some(result) }
    }

    pub const fn key(&self) -> NestedRestoreResultKey { self.key }
    pub const fn phase(&self) -> NestedRestoreResultPhase { self.phase }

    fn exact(&self, key: NestedRestoreResultKey) -> Result<(), NestedRestoreResultError> {
        if self.key == key { Ok(()) } else { Err(NestedRestoreResultError::InvalidIdentity) }
    }

    /// Memory-only inspection. This never moves the result or authorizes a native effect.
    pub fn result_ref(&self, key: NestedRestoreResultKey) -> Result<&R, NestedRestoreResultError> {
        self.exact(key)?;
        self.result.as_ref().ok_or(NestedRestoreResultError::InvalidPhase)
    }

    pub fn begin_restore(&mut self, key: NestedRestoreResultKey) -> Result<(), NestedRestoreResultError> {
        self.exact(key)?;
        if self.phase != NestedRestoreResultPhase::Retained {
            return Err(NestedRestoreResultError::InvalidPhase);
        }
        self.phase = NestedRestoreResultPhase::Restoring;
        Ok(())
    }

    /// Only a certified no-effect refusal permits a later attempt with the same parent.
    pub fn refuse_no_effects(&mut self, key: NestedRestoreResultKey) -> Result<(), NestedRestoreResultError> {
        self.exact(key)?;
        if self.phase != NestedRestoreResultPhase::Restoring {
            return Err(NestedRestoreResultError::InvalidPhase);
        }
        self.phase = NestedRestoreResultPhase::Retained;
        Ok(())
    }

    /// An uncertain restore keeps the result fenced; it cannot retry or produce a completion.
    pub fn quarantine(&mut self, key: NestedRestoreResultKey) -> Result<(), NestedRestoreResultError> {
        self.exact(key)?;
        if self.phase != NestedRestoreResultPhase::Restoring {
            return Err(NestedRestoreResultError::InvalidPhase);
        }
        self.phase = NestedRestoreResultPhase::Quarantined;
        Ok(())
    }

    pub fn acknowledge_restored(&mut self, key: NestedRestoreResultKey) -> Result<(), NestedRestoreResultError> {
        self.exact(key)?;
        if self.phase != NestedRestoreResultPhase::Restoring {
            return Err(NestedRestoreResultError::InvalidPhase);
        }
        self.phase = NestedRestoreResultPhase::Restored;
        Ok(())
    }

    pub fn take(&mut self, key: NestedRestoreResultKey) -> Result<R, NestedRestoreResultError> {
        self.exact(key)?;
        if self.phase != NestedRestoreResultPhase::Restored {
            return Err(NestedRestoreResultError::InvalidPhase);
        }
        let result = self.result.take().ok_or(NestedRestoreResultError::InvalidPhase)?;
        self.phase = NestedRestoreResultPhase::Consumed;
        Ok(result)
    }
}
