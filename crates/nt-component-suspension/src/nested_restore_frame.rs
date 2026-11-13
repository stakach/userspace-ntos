//! A retained continuation for a nested physical-parent restoration.
//!
//! The native adapter owns the physical hold and both Replies. This record only gates transfer
//! of the continuation after exact restoration; it never acknowledges a provider completion.

use crate::{NestedExecutionIdentity, SuspensionOwner};

/// The scope epoch, both Replies and caller must all agree before a continuation can move.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NestedRestoreKey {
    scope: NestedExecutionIdentity,
    parent_reply: u64,
    root_reply: u64,
    owner: SuspensionOwner,
}

impl NestedRestoreKey {
    pub const fn new(
        scope: NestedExecutionIdentity,
        parent_reply: u64,
        root_reply: u64,
        owner: SuspensionOwner,
    ) -> Option<Self> {
        if parent_reply == 0 || root_reply == 0 || !owner.is_valid() {
            None
        } else {
            Some(Self { scope, parent_reply, root_reply, owner })
        }
    }

    pub const fn scope(self) -> NestedExecutionIdentity { self.scope }
    pub const fn parent_reply(self) -> u64 { self.parent_reply }
    pub const fn root_reply(self) -> u64 { self.root_reply }
    pub const fn owner(self) -> SuspensionOwner { self.owner }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedRestorePhase {
    Prepared,
    PreparedChildWork,
    ChildWorkReady,
    ChildWorkEntered,
    Retained,
    Retrying,
    Quarantined,
    Restored,
    Receiving,
    ResultRetained,
    Transferring,
    Consumed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedRestoreFrameError {
    InvalidIdentity,
    InvalidPhase,
    RefusedNoEffects,
    Indeterminate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NestedRestoreTransferRefusal {
    NoEffects,
    Indeterminate,
}

/// One-shot ownership of the exact pump and caller snapshot. Copyable keys are lookup witnesses,
/// not another owner: only this frame can surrender `C` after a witnessed restoration.
#[must_use = "retain the continuation until the physical parent and Reply are restored"]
pub struct NestedRestoreFrame<C> {
    key: NestedRestoreKey,
    phase: NestedRestorePhase,
    continuation: Option<C>,
}

impl<C> NestedRestoreFrame<C> {
    pub fn prepare(key: NestedRestoreKey, continuation: C) -> Self {
        Self { key, phase: NestedRestorePhase::Prepared, continuation: Some(continuation) }
    }

    /// An intentional outer-loop handoff must run its selected child work before the parked
    /// parent can be restored. The work's own native effects and completion remain separate.
    pub fn prepare_child_work(key: NestedRestoreKey, continuation: C) -> Self {
        Self { key, phase: NestedRestorePhase::PreparedChildWork,
            continuation: Some(continuation) }
    }

    pub const fn key(&self) -> NestedRestoreKey { self.key }
    pub const fn phase(&self) -> NestedRestorePhase { self.phase }

    /// Inspect the exact retained continuation without transferring its ownership. A caller
    /// must revalidate this key at every native boundary because this reference is memory only.
    pub fn continuation_ref(
        &self, key: NestedRestoreKey,
    ) -> Result<&C, NestedRestoreFrameError> {
        self.exact(key)?;
        self.continuation.as_ref().ok_or(NestedRestoreFrameError::InvalidPhase)
    }

    fn exact(&self, key: NestedRestoreKey) -> Result<(), NestedRestoreFrameError> {
        if self.key == key { Ok(()) } else { Err(NestedRestoreFrameError::InvalidIdentity) }
    }

    /// Publish the durable frame before the root Reply park can enter a native effect.
    pub fn retain(&mut self, key: NestedRestoreKey) -> Result<(), NestedRestoreFrameError> {
        self.exact(key)?;
        self.phase = match self.phase {
            NestedRestorePhase::Prepared => NestedRestorePhase::Retained,
            NestedRestorePhase::PreparedChildWork => NestedRestorePhase::ChildWorkReady,
            _ => return Err(NestedRestoreFrameError::InvalidPhase),
        };
        Ok(())
    }

    /// Claim one child runner after the exact parent continuation has a durable owner. A
    /// reentrant or stale caller cannot launch the same work again.
    pub fn begin_child_work(
        &mut self, key: NestedRestoreKey,
    ) -> Result<(), NestedRestoreFrameError> {
        self.exact(key)?;
        if self.phase != NestedRestorePhase::ChildWorkReady {
            return Err(NestedRestoreFrameError::InvalidPhase);
        }
        self.phase = NestedRestorePhase::ChildWorkEntered;
        Ok(())
    }

    /// Only a certified no-effects refusal restores child dispatch authority.
    pub fn refuse_child_work_no_effects(
        &mut self, key: NestedRestoreKey,
    ) -> Result<(), NestedRestoreFrameError> {
        self.exact(key)?;
        if self.phase != NestedRestorePhase::ChildWorkEntered {
            return Err(NestedRestoreFrameError::InvalidPhase);
        }
        self.phase = NestedRestorePhase::ChildWorkReady;
        Ok(())
    }

    /// The selected child runner has returned with its own outcome retained. This permits
    /// restoration of the parent, but does not assert provider completion or Reply ACK.
    pub fn finish_child_work(
        &mut self, key: NestedRestoreKey,
    ) -> Result<(), NestedRestoreFrameError> {
        self.exact(key)?;
        if self.phase != NestedRestorePhase::ChildWorkEntered {
            return Err(NestedRestoreFrameError::InvalidPhase);
        }
        self.phase = NestedRestorePhase::Retained;
        Ok(())
    }

    /// An uncertain child effect retains the parent continuation and permanently fences replay.
    pub fn quarantine_child_work(
        &mut self, key: NestedRestoreKey,
    ) -> Result<(), NestedRestoreFrameError> {
        self.exact(key)?;
        if self.phase != NestedRestorePhase::ChildWorkEntered {
            return Err(NestedRestoreFrameError::InvalidPhase);
        }
        self.phase = NestedRestorePhase::Quarantined;
        Ok(())
    }

    pub fn begin_retry(&mut self, key: NestedRestoreKey) -> Result<(), NestedRestoreFrameError> {
        self.exact(key)?;
        if self.phase != NestedRestorePhase::Retained {
            return Err(NestedRestoreFrameError::InvalidPhase);
        }
        self.phase = NestedRestorePhase::Retrying;
        Ok(())
    }

    /// A certified preflight refusal has made no physical effect and keeps the same owner.
    pub fn refuse_retry_no_effects(
        &mut self, key: NestedRestoreKey,
    ) -> Result<(), NestedRestoreFrameError> {
        self.exact(key)?;
        if self.phase != NestedRestorePhase::Retrying {
            return Err(NestedRestoreFrameError::InvalidPhase);
        }
        self.phase = NestedRestorePhase::Retained;
        Ok(())
    }

    /// An uncertain native effect is fenced permanently; no retry or terminal is fabricated.
    pub fn quarantine(&mut self, key: NestedRestoreKey) -> Result<(), NestedRestoreFrameError> {
        self.exact(key)?;
        if !matches!(self.phase, NestedRestorePhase::Retained | NestedRestorePhase::Retrying) {
            return Err(NestedRestoreFrameError::InvalidPhase);
        }
        self.phase = NestedRestorePhase::Quarantined;
        Ok(())
    }

    /// Only the adapter's exact physical restoration acknowledgement permits handoff.
    pub fn acknowledge_restored(
        &mut self, key: NestedRestoreKey,
    ) -> Result<(), NestedRestoreFrameError> {
        self.exact(key)?;
        if self.phase != NestedRestorePhase::Retrying {
            return Err(NestedRestoreFrameError::InvalidPhase);
        }
        self.phase = NestedRestorePhase::Restored;
        Ok(())
    }

    /// The physical parent is restored. Claim only its existing receive half; a second outer
    /// turn cannot enter the same receive while this attempt is in progress.
    pub fn begin_receive(&mut self, key: NestedRestoreKey) -> Result<(), NestedRestoreFrameError> {
        self.exact(key)?;
        if self.phase != NestedRestorePhase::Restored {
            return Err(NestedRestoreFrameError::InvalidPhase);
        }
        self.phase = NestedRestorePhase::Receiving;
        Ok(())
    }

    /// A refusal certified before receive entry keeps the restored parent and original snapshot.
    pub fn refuse_receive_no_effects(
        &mut self, key: NestedRestoreKey,
    ) -> Result<(), NestedRestoreFrameError> {
        self.exact(key)?;
        if self.phase != NestedRestorePhase::Receiving {
            return Err(NestedRestoreFrameError::InvalidPhase);
        }
        self.phase = NestedRestorePhase::Restored;
        Ok(())
    }

    /// Receive-side setup may have entered native mapping effects before refusing. Keep the
    /// original snapshot and both Reply identities fenced; never retry that receive half.
    pub fn quarantine_receive(
        &mut self, key: NestedRestoreKey,
    ) -> Result<(), NestedRestoreFrameError> {
        self.exact(key)?;
        if self.phase != NestedRestorePhase::Receiving {
            return Err(NestedRestoreFrameError::InvalidPhase);
        }
        self.phase = NestedRestorePhase::Quarantined;
        Ok(())
    }

    /// Replace the pre-receive snapshot with the real returned pump result. The previous
    /// snapshot is returned only after the new one is retained in this same frame.
    pub fn record_receive_result(
        &mut self, key: NestedRestoreKey, next: C,
    ) -> Result<C, (NestedRestoreFrameError, C)> {
        if let Err(error) = self.exact(key) { return Err((error, next)); }
        if self.phase != NestedRestorePhase::Receiving {
            return Err((NestedRestoreFrameError::InvalidPhase, next));
        }
        let old = core::mem::replace(self.continuation.as_mut()
            .expect("receiving frame retains its prior snapshot"), next);
        self.phase = NestedRestorePhase::ResultRetained;
        Ok(old)
    }

    /// Transfer the real returned result only after the new owner certifies a no-effects
    /// refusal by returning `C`.
    /// The continuation remains here on refusal; an uncertain native handoff must instead use
    /// its own retained effect owner and must not report `Err(C)` to this method.
    pub fn transfer_result_no_effects<T>(
        &mut self, key: NestedRestoreKey,
        transfer: impl FnOnce(C) -> Result<T, C>,
    ) -> Result<T, NestedRestoreFrameError> {
        self.exact(key)?;
        if self.phase != NestedRestorePhase::ResultRetained {
            return Err(NestedRestoreFrameError::InvalidPhase);
        }
        let continuation = self.continuation.take().ok_or(NestedRestoreFrameError::InvalidPhase)?;
        match transfer(continuation) {
            Ok(value) => {
                self.phase = NestedRestorePhase::Consumed;
                Ok(value)
            }
            Err(continuation) => {
                self.continuation = Some(continuation);
                Err(NestedRestoreFrameError::RefusedNoEffects)
            }
        }
    }

    /// Keep the original result in this frame while a destination admission runs. A refusal
    /// certified before effects may retry; an uncertain effect is fenced with the result still
    /// retained. The `Transferring` phase prevents a reentrant owner from entering twice.
    pub fn transfer_result_with<T>(
        &mut self, key: NestedRestoreKey,
        transfer: impl FnOnce(&C) -> Result<T, NestedRestoreTransferRefusal>,
    ) -> Result<T, NestedRestoreFrameError> {
        self.exact(key)?;
        if self.phase != NestedRestorePhase::ResultRetained {
            return Err(NestedRestoreFrameError::InvalidPhase);
        }
        self.phase = NestedRestorePhase::Transferring;
        let result = transfer(self.continuation.as_ref()
            .expect("result transfer retains its original continuation"));
        match result {
            Ok(value) => {
                self.continuation = None;
                self.phase = NestedRestorePhase::Consumed;
                Ok(value)
            }
            Err(NestedRestoreTransferRefusal::NoEffects) => {
                self.phase = NestedRestorePhase::ResultRetained;
                Err(NestedRestoreFrameError::RefusedNoEffects)
            }
            Err(NestedRestoreTransferRefusal::Indeterminate) => {
                self.phase = NestedRestorePhase::Quarantined;
                Err(NestedRestoreFrameError::Indeterminate)
            }
        }
    }

}
