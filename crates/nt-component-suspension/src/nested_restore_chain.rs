//! A nested result crosses its inner parent before an optional outer parent.
//!
//! The native adapter owns both physical holds and Replies. Each transition here requires the
//! exact route, dispatch epoch, nested sequence, and Reply; it grants no authority for an effect.

use crate::{
    NestedRestoreResult, NestedRestoreResultError, NestedRestoreResultKey,
    NestedRestoreResultPhase,
};

/// Keeps the result until every parent in the two-level restore has acknowledged completion.
#[must_use = "retain both parent Replies until the nested result is released"]
pub struct NestedRestoreChain<R> {
    inner: NestedRestoreResult<R>,
    outer: Option<NestedRestoreResult<()>>,
}

impl<R> NestedRestoreChain<R> {
    pub fn retain(
        inner: NestedRestoreResultKey,
        outer: Option<NestedRestoreResultKey>,
        result: R,
    ) -> Result<Self, NestedRestoreResultError> {
        if let Some(outer) = outer {
            // Concurrent physical rows cannot share a route or a Reply, even when their
            // generation fields differ. A recycled identity is not a second parent.
            if inner.scope().route() == outer.scope().route()
                || inner.parent_reply() == outer.parent_reply()
            {
                return Err(NestedRestoreResultError::InvalidIdentity);
            }
        }
        Ok(Self {
            inner: NestedRestoreResult::retain(inner, result),
            outer: outer.map(|key| NestedRestoreResult::retain(key, ())),
        })
    }

    pub const fn inner_key(&self) -> NestedRestoreResultKey { self.inner.key() }
    pub fn outer_key(&self) -> Option<NestedRestoreResultKey> {
        self.outer.as_ref().map(NestedRestoreResult::key)
    }
    pub const fn inner_phase(&self) -> NestedRestoreResultPhase { self.inner.phase() }
    pub fn outer_phase(&self) -> Option<NestedRestoreResultPhase> {
        self.outer.as_ref().map(NestedRestoreResult::phase)
    }

    /// Memory-only inspection, including during quarantine. This never releases the result.
    pub fn result_ref(&self, inner: NestedRestoreResultKey) -> Result<&R, NestedRestoreResultError> {
        self.inner.result_ref(inner)
    }

    pub fn begin_inner(&mut self, inner: NestedRestoreResultKey) -> Result<(), NestedRestoreResultError> {
        self.inner.begin_restore(inner)
    }
    pub fn refuse_inner_no_effects(&mut self, inner: NestedRestoreResultKey) -> Result<(), NestedRestoreResultError> {
        self.inner.refuse_no_effects(inner)
    }
    pub fn quarantine_inner(&mut self, inner: NestedRestoreResultKey) -> Result<(), NestedRestoreResultError> {
        self.inner.quarantine(inner)
    }
    pub fn acknowledge_inner(&mut self, inner: NestedRestoreResultKey) -> Result<(), NestedRestoreResultError> {
        self.inner.acknowledge_restored(inner)
    }

    fn outer_mut(&mut self, outer: NestedRestoreResultKey) -> Result<&mut NestedRestoreResult<()>, NestedRestoreResultError> {
        let record = self.outer.as_mut().ok_or(NestedRestoreResultError::InvalidIdentity)?;
        if record.key() != outer {
            return Err(NestedRestoreResultError::InvalidIdentity);
        }
        if self.inner.phase() != NestedRestoreResultPhase::Restored {
            return Err(NestedRestoreResultError::InvalidPhase);
        }
        Ok(record)
    }

    pub fn begin_outer(&mut self, outer: NestedRestoreResultKey) -> Result<(), NestedRestoreResultError> {
        self.outer_mut(outer)?.begin_restore(outer)
    }
    pub fn refuse_outer_no_effects(&mut self, outer: NestedRestoreResultKey) -> Result<(), NestedRestoreResultError> {
        self.outer_mut(outer)?.refuse_no_effects(outer)
    }
    pub fn quarantine_outer(&mut self, outer: NestedRestoreResultKey) -> Result<(), NestedRestoreResultError> {
        self.outer_mut(outer)?.quarantine(outer)
    }
    pub fn acknowledge_outer(&mut self, outer: NestedRestoreResultKey) -> Result<(), NestedRestoreResultError> {
        self.outer_mut(outer)?.acknowledge_restored(outer)
    }

    /// Both exact tickets and all physical restore acknowledgements precede result handoff.
    pub fn take(
        &mut self,
        inner: NestedRestoreResultKey,
        outer: Option<NestedRestoreResultKey>,
    ) -> Result<R, NestedRestoreResultError> {
        if self.inner.key() != inner || self.outer_key() != outer {
            return Err(NestedRestoreResultError::InvalidIdentity);
        }
        if self.outer.as_ref().is_some_and(|record| record.phase() != NestedRestoreResultPhase::Restored) {
            return Err(NestedRestoreResultError::InvalidPhase);
        }
        self.inner.take(inner)
    }
}
