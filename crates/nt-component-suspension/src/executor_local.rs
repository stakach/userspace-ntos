//! Stable executor-local payload ownership keyed by an exact physical TCB anchor.
//!
//! Native code installs the returned anchor in FS only after `bind` succeeds. A failed bind
//! returns the still-unpublished payload to its caller. Native retirement supplies a confirmed
//! exact-TCB observation before this registry releases the payload.

use crate::{ExecutorError, ExecutorHandle, ExecutorState, ExecutorTable};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_ANCHOR: AtomicU64 = AtomicU64::new(1);

/// Exact physical TCB slot and incarnation; a reused slot has a different generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcbIdentity {
    slot: u64,
    generation: u64,
}

impl TcbIdentity {
    pub const fn new(slot: u64, generation: u64) -> Self {
        Self { slot, generation }
    }
}

/// Proof from native ownership that this exact TCB can no longer run with its FS anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcbRetirementObservation(TcbIdentity);

impl TcbRetirementObservation {
    /// # Safety
    /// The caller must have confirmed retirement of this exact physical TCB incarnation, with
    /// no remaining path to execute it. Attempted or uncertain native teardown is insufficient.
    pub const unsafe fn new(tcb: TcbIdentity) -> Self {
        Self(tcb)
    }
}

/// Opaque identity for one live binding. Its value is never reused, even across registries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutorLocalAnchor(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorLocalError {
    MissingAnchor,
    StaleAnchor,
    InvalidTcbIdentity,
    AlreadyBound,
    ExecutorNotIdle,
    ExecutorStillActive,
    TcbMismatch,
    Table(ExecutorError),
    NoCapacity,
    IdentityExhausted,
}

struct Binding<T> {
    anchor: ExecutorLocalAnchor,
    executor: ExecutorHandle,
    tcb: TcbIdentity,
    payload: Box<T>,
}

/// Owns payload addresses until both the executor and its exact native TCB retire.
pub struct ExecutorLocalRegistry<T> {
    bindings: Vec<Binding<T>>,
}

impl<T> Drop for ExecutorLocalRegistry<T> {
    fn drop(&mut self) {
        // Losing the registry cannot prove any still-bound TCB stopped using its FS anchor.
        // Quarantine those payloads rather than free memory a live TCB may still address.
        for binding in self.bindings.drain(..) {
            core::mem::forget(binding.payload);
        }
    }
}

impl<T> ExecutorLocalRegistry<T> {
    pub const fn new() -> Self {
        Self {
            bindings: Vec::new(),
        }
    }

    /// Bind an idle executor before publishing its anchor to the TCB's FS base.
    ///
    /// On refusal, the unpublished payload is returned unchanged. The caller must not install
    /// FS until this returns `Ok`; the registry never performs a native effect.
    pub fn bind(
        &mut self,
        table: &ExecutorTable,
        executor: ExecutorHandle,
        tcb: TcbIdentity,
        payload: Box<T>,
    ) -> Result<ExecutorLocalAnchor, (ExecutorLocalError, Box<T>)> {
        let result = (|| {
            if tcb.slot == 0 || tcb.generation == 0 {
                return Err(ExecutorLocalError::InvalidTcbIdentity);
            }
            match table.state(executor) {
                Ok(ExecutorState::Idle) => {}
                Ok(_) => return Err(ExecutorLocalError::ExecutorNotIdle),
                Err(error) => return Err(ExecutorLocalError::Table(error)),
            }
            if self
                .bindings
                .iter()
                .any(|binding| binding.executor == executor || binding.tcb.slot == tcb.slot)
            {
                return Err(ExecutorLocalError::AlreadyBound);
            }
            self.bindings
                .try_reserve(1)
                .map_err(|_| ExecutorLocalError::NoCapacity)?;
            NEXT_ANCHOR
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                    next.checked_add(1)
                })
                .map(ExecutorLocalAnchor)
                .map_err(|_| ExecutorLocalError::IdentityExhausted)
        })();
        let anchor = match result {
            Ok(anchor) => anchor,
            Err(error) => return Err((error, payload)),
        };
        self.bindings.push(Binding {
            anchor,
            executor,
            tcb,
            payload,
        });
        Ok(anchor)
    }

    fn binding_index(
        &self,
        anchor: Option<ExecutorLocalAnchor>,
        tcb: TcbIdentity,
        executor: ExecutorHandle,
    ) -> Result<usize, ExecutorLocalError> {
        let anchor = anchor.ok_or(ExecutorLocalError::MissingAnchor)?;
        self.bindings
            .iter()
            .position(|binding| {
                binding.anchor == anchor && binding.tcb == tcb && binding.executor == executor
            })
            .ok_or(ExecutorLocalError::StaleAnchor)
    }

    pub fn resolve(
        &self,
        anchor: Option<ExecutorLocalAnchor>,
        tcb: TcbIdentity,
        executor: ExecutorHandle,
    ) -> Result<&T, ExecutorLocalError> {
        let index = self.binding_index(anchor, tcb, executor)?;
        Ok(&self.bindings[index].payload)
    }

    pub fn resolve_mut(
        &mut self,
        anchor: Option<ExecutorLocalAnchor>,
        tcb: TcbIdentity,
        executor: ExecutorHandle,
    ) -> Result<&mut T, ExecutorLocalError> {
        let index = self.binding_index(anchor, tcb, executor)?;
        Ok(&mut self.bindings[index].payload)
    }

    /// Release only after the executor has finished and exact native TCB retirement is confirmed.
    /// Slot reuse following `Done` is allowed: a stale generation in this same table proves the
    /// old executor was retired before its slot was registered again.
    pub fn retire(
        &mut self,
        anchor: ExecutorLocalAnchor,
        table: &ExecutorTable,
        tcb_retirement: TcbRetirementObservation,
    ) -> Result<(), ExecutorLocalError> {
        let index = self
            .bindings
            .iter()
            .position(|binding| binding.anchor == anchor)
            .ok_or(ExecutorLocalError::StaleAnchor)?;
        let binding = &self.bindings[index];
        if binding.tcb != tcb_retirement.0 {
            return Err(ExecutorLocalError::TcbMismatch);
        }
        match table.state(binding.executor) {
            Ok(ExecutorState::Retired) | Err(ExecutorError::StaleGeneration) => {}
            Ok(_) => return Err(ExecutorLocalError::ExecutorStillActive),
            Err(error) => return Err(ExecutorLocalError::Table(error)),
        }
        self.bindings.swap_remove(index);
        Ok(())
    }
}
