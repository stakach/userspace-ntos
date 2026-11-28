//! Stable executor-local payload ownership keyed by an exact physical TCB anchor.
//!
//! Native code may install the payload in FS only after `bind_native` stores a move-only physical
//! TCB claim and `begin_fs_install` records the attempt. A refused bind returns its still-owned
//! payload and claim. Exact-TCB retirement is required before an uncertain effect can release it.

use crate::{ExecutorError, ExecutorHandle, ExecutorState, ExecutorTable, RunToken};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_ANCHOR: AtomicU64 = AtomicU64::new(1);

/// Numeric TCB slot and incarnation for lookup; native authority requires a physical claim.
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

/// Move-only ownership claim for the exact physical TCB capability native will invoke.
/// The numeric identity is useful for rejecting stale rows, but never authorizes a capability.
#[must_use = "keep the physical TCB claim until its exact teardown"]
#[derive(Debug)]
pub struct PhysicalTcbClaim {
    tcb: TcbIdentity,
    target_cap: u64,
}

impl PhysicalTcbClaim {
    /// # Safety
    /// `target_cap` must name the live TCB at `tcb`, and its native owner must prevent reuse of
    /// that capability and physical slot until exact teardown is observed. Mint this only at the
    /// native retype/slot owner, not from a caller-supplied numeric identity.
    pub unsafe fn new(tcb: TcbIdentity, target_cap: u64) -> Result<Self, ExecutorLocalError> {
        if tcb.slot == 0 || tcb.generation == 0 || target_cap == 0 {
            return Err(ExecutorLocalError::InvalidTcbIdentity);
        }
        Ok(Self { tcb, target_cap })
    }

    pub const fn identity(&self) -> TcbIdentity {
        self.tcb
    }

    pub const fn target_cap(&self) -> u64 {
        self.target_cap
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

    pub const fn identity(self) -> TcbIdentity {
        self.0
    }
}

/// Opaque identity for one live binding. Its value is never reused, even across registries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutorLocalAnchor(u64);

/// One SetTLSBase attempt. Dropping it leaves the payload and TCB claim quarantined in the
/// registry until a confirmed exact-TCB teardown; it never rolls back an uncertain effect.
#[must_use = "settle the FS installation or retain the binding until exact TCB teardown"]
#[derive(Debug)]
pub struct FsInstallAttempt<T> {
    anchor: ExecutorLocalAnchor,
    executor: ExecutorHandle,
    tcb: TcbIdentity,
    target_cap: u64,
    base: *const T,
}

impl<T> FsInstallAttempt<T> {
    pub const fn target_cap(&self) -> u64 {
        self.target_cap
    }

    pub const fn base(&self) -> *const T {
        self.base
    }
}

/// Move-only proof that the native FS-base invocation acknowledged publication.
/// Only the registry can create it after an observed successful reply.
#[must_use = "activate the acknowledged worker or retain it for exact teardown"]
#[derive(Debug)]
pub struct FsInstallAcknowledgement {
    executor: ExecutorHandle,
    tcb: TcbIdentity,
    target_cap: u64,
}

impl FsInstallAcknowledgement {
    pub const fn executor(&self) -> ExecutorHandle {
        self.executor
    }

    pub const fn tcb(&self) -> TcbIdentity {
        self.tcb
    }

    pub const fn target_cap(&self) -> u64 {
        self.target_cap
    }
}

/// One-use native proof that this worker's bootstrap SC was removed while the exact TCB was
/// blocked on its private endpoint with its Reply offered. The native owner retains the worker
/// resources after issuing this proof.
#[must_use = "activate the exact worker or retain this proof with its native owner"]
#[derive(Debug)]
pub struct PassiveWorkerReadyProof {
    executor: ExecutorHandle,
    tcb: TcbIdentity,
    target_cap: u64,
}

impl PassiveWorkerReadyProof {
    /// # Safety
    /// The caller must own this exact physical TCB incarnation and have observed a successful
    /// zero-word reply to the checked passive-worker SC unbind for its private endpoint and
    /// offered Reply. A ready message, numeric cap match, or uncertain result is insufficient.
    pub unsafe fn from_checked_unbind(
        executor: ExecutorHandle,
        tcb: TcbIdentity,
        target_cap: u64,
    ) -> Result<Self, ExecutorLocalError> {
        if tcb.slot == 0 || tcb.generation == 0 || target_cap == 0 {
            return Err(ExecutorLocalError::InvalidTcbIdentity);
        }
        Ok(Self {
            executor,
            tcb,
            target_cap,
        })
    }

    pub const fn executor(&self) -> ExecutorHandle {
        self.executor
    }

    pub const fn tcb(&self) -> TcbIdentity {
        self.tcb
    }

    pub const fn target_cap(&self) -> u64 {
        self.target_cap
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutorLocalError {
    MissingAnchor,
    StaleAnchor,
    InvalidTcbIdentity,
    AlreadyBound,
    ExecutorNotIdle,
    ExecutorStillActive,
    TcbMismatch,
    MissingPhysicalTcbClaim,
    NativeClaimNeedsTransaction,
    PublicationAlreadyStarted,
    Table(ExecutorError),
    NoCapacity,
    IdentityExhausted,
}

struct Binding<T> {
    anchor: ExecutorLocalAnchor,
    executor: ExecutorHandle,
    tcb: TcbIdentity,
    payload: Box<T>,
    native_claim: Option<PhysicalTcbClaim>,
    publication: FsPublication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FsPublication {
    Unpublished,
    Installing,
    Published,
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
            core::mem::forget(binding);
        }
    }
}

impl<T> ExecutorLocalRegistry<T> {
    pub const fn new() -> Self {
        Self {
            bindings: Vec::new(),
        }
    }

    /// Bind a model executor before publishing its anchor.
    ///
    /// On refusal, the unpublished payload is returned unchanged. This numeric-ID path cannot
    /// authorize native FS installation; native callers must use [`Self::bind_native`].
    #[cfg(test)]
    pub fn bind(
        &mut self,
        table: &ExecutorTable,
        executor: ExecutorHandle,
        tcb: TcbIdentity,
        payload: Box<T>,
    ) -> Result<ExecutorLocalAnchor, (ExecutorLocalError, Box<T>)> {
        let anchor = match self.prepare_binding(table, executor, tcb) {
            Ok(anchor) => anchor,
            Err(error) => return Err((error, payload)),
        };
        self.bindings.push(Binding {
            anchor,
            executor,
            tcb,
            payload,
            native_claim: None,
            publication: FsPublication::Unpublished,
        });
        Ok(anchor)
    }

    /// Bind a physical TCB and its payload before any native FS-base effect.
    /// A refused bind returns both move-only owners unchanged.
    pub fn bind_native(
        &mut self,
        table: &ExecutorTable,
        executor: ExecutorHandle,
        claim: PhysicalTcbClaim,
        payload: Box<T>,
    ) -> Result<ExecutorLocalAnchor, (ExecutorLocalError, Box<T>, PhysicalTcbClaim)>
    where
        T: Send,
    {
        let tcb = claim.identity();
        match table.state(executor) {
            Ok(ExecutorState::Unready) => {}
            Ok(_) => return Err((ExecutorLocalError::ExecutorNotIdle, payload, claim)),
            Err(error) => return Err((ExecutorLocalError::Table(error), payload, claim)),
        }
        let anchor = match self.prepare_binding(table, executor, tcb) {
            Ok(anchor) => anchor,
            Err(error) => return Err((error, payload, claim)),
        };
        self.bindings.push(Binding {
            anchor,
            executor,
            tcb,
            payload,
            native_claim: Some(claim),
            publication: FsPublication::Unpublished,
        });
        Ok(anchor)
    }

    /// Cancel native setup before any FS-install attempt begins. This returns the exact payload
    /// and physical claim; the worker remains unready for a later bind or exact teardown.
    pub fn cancel_unpublished_native(
        &mut self,
        anchor: ExecutorLocalAnchor,
        table: &ExecutorTable,
    ) -> Result<(Box<T>, PhysicalTcbClaim), ExecutorLocalError> {
        let index = self
            .bindings
            .iter()
            .position(|binding| binding.anchor == anchor)
            .ok_or(ExecutorLocalError::StaleAnchor)?;
        let binding = &self.bindings[index];
        if table.state(binding.executor).map_err(ExecutorLocalError::Table)?
            != ExecutorState::Unready
        {
            return Err(ExecutorLocalError::ExecutorStillActive);
        }
        if binding.publication != FsPublication::Unpublished {
            return Err(ExecutorLocalError::PublicationAlreadyStarted);
        }
        if binding.native_claim.is_none() {
            return Err(ExecutorLocalError::MissingPhysicalTcbClaim);
        }
        let mut binding = self.bindings.swap_remove(index);
        Ok((
            binding.payload,
            binding.native_claim.take().expect("checked physical claim"),
        ))
    }

    fn prepare_binding(
        &mut self,
        table: &ExecutorTable,
        executor: ExecutorHandle,
        tcb: TcbIdentity,
    ) -> Result<ExecutorLocalAnchor, ExecutorLocalError> {
        if tcb.slot == 0 || tcb.generation == 0 {
            return Err(ExecutorLocalError::InvalidTcbIdentity);
        }
        match table.state(executor) {
            Ok(ExecutorState::Idle | ExecutorState::Unready) => {}
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

    /// Borrow the exact native TCB claim without transferring its ownership from this registry.
    /// The caller must keep the registry and its physical TCB owner alive while using the borrow
    /// to bind a running executor's fault path.
    pub fn physical_claim_for(
        &self,
        anchor: ExecutorLocalAnchor,
        tcb: TcbIdentity,
        executor: ExecutorHandle,
    ) -> Result<&PhysicalTcbClaim, ExecutorLocalError> {
        let index = self.binding_index(Some(anchor), tcb, executor)?;
        self.bindings[index]
            .native_claim
            .as_ref()
            .ok_or(ExecutorLocalError::MissingPhysicalTcbClaim)
    }

    #[cfg(test)]
    pub fn resolve(
        &self,
        anchor: Option<ExecutorLocalAnchor>,
        tcb: TcbIdentity,
        executor: ExecutorHandle,
    ) -> Result<&T, ExecutorLocalError> {
        let index = self.binding_index(anchor, tcb, executor)?;
        Ok(&self.bindings[index].payload)
    }

    #[cfg(test)]
    pub fn resolve_mut(
        &mut self,
        anchor: Option<ExecutorLocalAnchor>,
        tcb: TcbIdentity,
        executor: ExecutorHandle,
    ) -> Result<&mut T, ExecutorLocalError> {
        let index = self.binding_index(anchor, tcb, executor)?;
        Ok(&mut self.bindings[index].payload)
    }

    /// Compare identities in the host model. Both numbers are caller-created, so this cannot
    /// authorize a native SetTLSBase invocation; native code uses [`Self::begin_fs_install`].
    #[cfg(test)]
    pub fn authorize_fs_install(
        &self,
        anchor: ExecutorLocalAnchor,
        executor: ExecutorHandle,
        claimed: TcbIdentity,
        target: TcbIdentity,
    ) -> Result<&T, ExecutorLocalError> {
        if claimed != target {
            return Err(ExecutorLocalError::TcbMismatch);
        }
        self.resolve(Some(anchor), claimed, executor)
    }

    /// Record ownership before the native effect and return only the cap and stable payload
    /// address stored in the move-only physical TCB claim. Dropping this attempt is uncertain:
    /// it leaves the binding in `Installing` until exact TCB retirement.
    pub fn begin_fs_install(
        &mut self,
        anchor: ExecutorLocalAnchor,
        table: &ExecutorTable,
    ) -> Result<FsInstallAttempt<T>, ExecutorLocalError> {
        let binding = self
            .bindings
            .iter_mut()
            .find(|binding| binding.anchor == anchor)
            .ok_or(ExecutorLocalError::StaleAnchor)?;
        match table.state(binding.executor) {
            Ok(ExecutorState::Unready) => {}
            Ok(_) => return Err(ExecutorLocalError::ExecutorNotIdle),
            Err(error) => return Err(ExecutorLocalError::Table(error)),
        }
        if binding.publication != FsPublication::Unpublished {
            return Err(ExecutorLocalError::PublicationAlreadyStarted);
        }
        let claim = binding
            .native_claim
            .as_ref()
            .ok_or(ExecutorLocalError::MissingPhysicalTcbClaim)?;
        binding.publication = FsPublication::Installing;
        Ok(FsInstallAttempt {
            anchor,
            executor: binding.executor,
            tcb: binding.tcb,
            target_cap: claim.target_cap,
            base: &*binding.payload,
        })
    }

    /// Record the kernel's successful reply for the exact SetTLSBase invocation. The returned
    /// token is the FS-publication input to activation; a separate checked passive-worker
    /// receive proof is also required before root may route ingress to this executor.
    ///
    /// # Safety
    /// The caller must have observed a successful reply from invoking `attempt.target_cap()`
    /// with `attempt.base()` and FS selector zero. A timeout, send-only call, or missing reply
    /// is uncertain and must leave the attempt/binding retained.
    pub unsafe fn acknowledge_fs_install(
        &mut self,
        attempt: FsInstallAttempt<T>,
    ) -> Result<FsInstallAcknowledgement, ExecutorLocalError> {
        let index = self.binding_index(Some(attempt.anchor), attempt.tcb, attempt.executor)?;
        let binding = &mut self.bindings[index];
        if binding.publication != FsPublication::Installing
            || binding.native_claim.as_ref().map(|claim| claim.target_cap)
                != Some(attempt.target_cap)
        {
            return Err(ExecutorLocalError::PublicationAlreadyStarted);
        }
        binding.publication = FsPublication::Published;
        Ok(FsInstallAcknowledgement {
            executor: attempt.executor,
            tcb: attempt.tcb,
            target_cap: attempt.target_cap,
        })
    }

    /// Return both unpublished owners after native confirms SetTLSBase had no effect.
    ///
    /// # Safety
    /// The caller must have observed a definitive no-effect refusal for this exact attempt,
    /// and no path may retry or complete it after the owners are returned.
    pub unsafe fn abort_no_effect(
        &mut self,
        attempt: FsInstallAttempt<T>,
        table: &ExecutorTable,
    ) -> Result<(Box<T>, PhysicalTcbClaim), ExecutorLocalError> {
        let index = self.binding_index(Some(attempt.anchor), attempt.tcb, attempt.executor)?;
        let binding = &self.bindings[index];
        match table.state(binding.executor) {
            Ok(ExecutorState::Unready) => {}
            Ok(_) => return Err(ExecutorLocalError::ExecutorStillActive),
            Err(error) => return Err(ExecutorLocalError::Table(error)),
        }
        if binding.publication != FsPublication::Installing
            || binding.native_claim.as_ref().map(|claim| claim.target_cap)
                != Some(attempt.target_cap)
        {
            return Err(ExecutorLocalError::PublicationAlreadyStarted);
        }
        let binding = self.bindings.swap_remove(index);
        match binding.native_claim {
            Some(claim) => Ok((binding.payload, claim)),
            None => {
                // A broken internal invariant still cannot free a possibly selected FS base.
                core::mem::forget(binding.payload);
                Err(ExecutorLocalError::MissingPhysicalTcbClaim)
            }
        }
    }

    /// Undo a binding only after native reports that FS installation had no effect.
    ///
    /// # Safety
    /// The caller must have confirmed that this exact TCB incarnation never selected the
    /// payload as its FS base, and no path can still install the anchor later.
    #[cfg(test)]
    pub unsafe fn abort_unpublished(
        &mut self,
        anchor: ExecutorLocalAnchor,
        table: &ExecutorTable,
        tcb: TcbIdentity,
    ) -> Result<Box<T>, ExecutorLocalError> {
        let index = self
            .bindings
            .iter()
            .position(|binding| binding.anchor == anchor)
            .ok_or(ExecutorLocalError::StaleAnchor)?;
        let binding = &self.bindings[index];
        if binding.tcb != tcb {
            return Err(ExecutorLocalError::TcbMismatch);
        }
        match table.state(binding.executor) {
            Ok(ExecutorState::Unready) => {}
            Ok(_) => return Err(ExecutorLocalError::ExecutorStillActive),
            Err(error) => return Err(ExecutorLocalError::Table(error)),
        }
        if binding.native_claim.is_some() {
            return Err(ExecutorLocalError::NativeClaimNeedsTransaction);
        }
        if binding.publication != FsPublication::Unpublished {
            return Err(ExecutorLocalError::PublicationAlreadyStarted);
        }
        Ok(self.bindings.swap_remove(index).payload)
    }

    /// Reclaim an unready worker even after an uncertain or acknowledged FS install, but only
    /// after the exact physical TCB is confirmed unable to run. This also retires its table slot.
    pub fn retire_unready_after_teardown(
        &mut self,
        anchor: ExecutorLocalAnchor,
        table: &mut ExecutorTable,
        root: &RunToken,
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
        table
            .retire_unready(root, binding.executor)
            .map_err(ExecutorLocalError::Table)?;
        self.bindings.swap_remove(index);
        Ok(())
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
