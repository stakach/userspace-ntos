//! Exact ownership of a hosted thread's physical scheduler placement.
//!
//! The native adapter stores this owner in the published runtime row alongside its TCB
//! and SC caps. A physical configure operation is recorded before invocation. The
//! caller classifies its terminal effect; an uncertain effect retains the original
//! attempt and cannot authorize a retry, identity query, or mechanism retirement.

use alloc::alloc::{alloc, dealloc};
use alloc::boxed::Box;
use core::alloc::Layout;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use crate::process_identity::ProcessIdentity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlacementIdentity {
    pub process: ProcessIdentity,
    pub tid: u64,
    pub tcb: u64,
    pub sched_context: u64,
}

impl PlacementIdentity {
    fn is_valid(self) -> bool {
        self.process.is_valid() && self.tid != 0 && self.tcb > 1 && self.sched_context > 1
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PlacementAttempt {
    identity: PlacementIdentity,
    sequence: u64,
    from: u8,
    to: u8,
}

impl PlacementAttempt {
    pub const fn source_core(self) -> u8 {
        self.from
    }
    pub const fn target_core(self) -> u8 {
        self.to
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementEffect {
    /// The exact SC/TCB transition completed and the target core is authoritative.
    Applied,
    /// The backend proved that no physical placement effect occurred.
    NoEffect,
    /// The effect cannot yet be classified; the attempt remains retained.
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementError {
    InvalidIdentity,
    WrongIdentity,
    InvalidCore,
    SameCore,
    Busy,
    Uncertain,
    StaleAttempt,
    SequenceExhausted,
}

/// Translate a placement refusal into the NT status used by native callers.
pub fn placement_error_status(error: PlacementError) -> u32 {
    match error {
        PlacementError::Busy | PlacementError::Uncertain => nt_process::STATUS_DEVICE_BUSY,
        _ => nt_process::STATUS_INVALID_HANDLE,
    }
}

/// `NtGetCurrentProcessorNumber` returns the core in the result register, not a success status.
pub fn processor_query_result(result: Result<u8, PlacementError>) -> u32 {
    result.map_or_else(placement_error_status, u32::from)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Known(u8),
    Pending(PlacementAttempt),
    Uncertain(PlacementAttempt),
}

/// The only authoritative core for this exact published runtime and mechanism pair.
#[derive(Debug)]
pub struct PhysicalPlacementOwner {
    identity: PlacementIdentity,
    state: State,
    next_sequence: u64,
}

impl PhysicalPlacementOwner {
    /// Construct only after the initial SC was configured, bound to this TCB, and published.
    pub fn new(
        identity: PlacementIdentity,
        core: u8,
        active_count: u8,
    ) -> Result<Self, PlacementError> {
        if !identity.is_valid() {
            return Err(PlacementError::InvalidIdentity);
        }
        if active_count == 0 || active_count > 64 || core >= active_count {
            return Err(PlacementError::InvalidCore);
        }
        Ok(Self {
            identity,
            state: State::Known(core),
            next_sequence: 1,
        })
    }

    pub fn current_core(&self, identity: PlacementIdentity) -> Result<u8, PlacementError> {
        self.check_identity(identity)?;
        match self.state {
            State::Known(core) => Ok(core),
            State::Pending(_) => Err(PlacementError::Busy),
            State::Uncertain(_) => Err(PlacementError::Uncertain),
        }
    }

    /// Record the exact owner before calling SchedControlConfigure. The native adapter
    /// must retain its TCB, SC, runtime row, and Reply while this attempt is pending.
    pub fn begin(
        &mut self,
        identity: PlacementIdentity,
        target_core: u8,
        active_count: u8,
    ) -> Result<PlacementAttempt, PlacementError> {
        self.check_identity(identity)?;
        let from = match self.state {
            State::Known(core) => core,
            State::Pending(_) => return Err(PlacementError::Busy),
            State::Uncertain(_) => return Err(PlacementError::Uncertain),
        };
        if active_count == 0
            || active_count > 64
            || from >= active_count
            || target_core >= active_count
        {
            return Err(PlacementError::InvalidCore);
        }
        if target_core == from {
            return Err(PlacementError::SameCore);
        }
        let next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or(PlacementError::SequenceExhausted)?;
        let attempt = PlacementAttempt {
            identity,
            sequence: self.next_sequence,
            from,
            to: target_core,
        };
        self.next_sequence = next_sequence;
        self.state = State::Pending(attempt);
        Ok(attempt)
    }

    /// A nonzero native label is not automatically `NoEffect`. Use that outcome only
    /// when the backend proves it performed no placement operation.
    pub fn settle(
        &mut self,
        attempt: PlacementAttempt,
        effect: PlacementEffect,
    ) -> Result<(), PlacementError> {
        self.check_identity(attempt.identity)?;
        if self.state != State::Pending(attempt) {
            return Err(PlacementError::StaleAttempt);
        }
        self.state = match effect {
            PlacementEffect::Applied => State::Known(attempt.to),
            PlacementEffect::NoEffect => State::Known(attempt.from),
            PlacementEffect::Uncertain => State::Uncertain(attempt),
        };
        Ok(())
    }

    /// Reconciliation may classify the retained attempt, but never invoke it again.
    pub fn reconcile(
        &mut self,
        attempt: PlacementAttempt,
        verified_effect: PlacementEffect,
    ) -> Result<(), PlacementError> {
        self.check_identity(attempt.identity)?;
        if self.state != State::Uncertain(attempt) {
            return Err(PlacementError::StaleAttempt);
        }
        self.state = match verified_effect {
            PlacementEffect::Applied => State::Known(attempt.to),
            PlacementEffect::NoEffect => State::Known(attempt.from),
            PlacementEffect::Uncertain => return Err(PlacementError::Uncertain),
        };
        Ok(())
    }

    /// This only says no transition pins the runtime; ordinary thread lifetime
    /// and mechanism retirement checks remain separate.
    pub fn transition_is_settled(&self) -> bool {
        matches!(self.state, State::Known(_))
    }

    fn check_identity(&self, identity: PlacementIdentity) -> Result<(), PlacementError> {
        if !identity.is_valid() {
            return Err(PlacementError::InvalidIdentity);
        }
        if identity != self.identity {
            return Err(PlacementError::WrongIdentity);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlacementReadOwnerError {
    NoMemory,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReadPhase {
    Idle = 0,
    Active = 1,
    Unresolved = 2,
}

struct PlacementReadState {
    placement: UnsafeCell<PhysicalPlacementOwner>,
    nonce: AtomicU64,
    phase: AtomicU8,
}

/// Fallible stable storage reserved before a native TCB or SC construction can take effect.
/// The reservation owns only uninitialized storage; it exposes no read loan or placement state.
#[must_use = "initialize the reserved placement owner or cancel before native effects"]
pub struct PlacementReadReservation {
    storage: NonNull<MaybeUninit<PlacementReadState>>,
}

impl PlacementReadReservation {
    pub fn try_new() -> Result<Self, PlacementReadOwnerError> {
        let layout = Layout::new::<PlacementReadState>();
        // SAFETY: the fixed-size, nonzero allocation is either retained by the reservation
        // or reported as a failure before any native construction effect.
        let storage = unsafe { alloc(layout) }.cast::<MaybeUninit<PlacementReadState>>();
        let storage = NonNull::new(storage).ok_or(PlacementReadOwnerError::NoMemory)?;
        Ok(Self { storage })
    }

    /// Publish a validated placement into the already reserved stable allocation. This does
    /// not call the allocator and cannot fail after native construction has succeeded.
    pub fn initialize(self, placement: PhysicalPlacementOwner) -> PlacementReadOwner {
        let storage = self.storage.cast::<PlacementReadState>();
        // The allocation transfers to Box; the reservation must not deallocate it on return.
        core::mem::forget(self);
        unsafe {
            storage.as_ptr().write(PlacementReadState {
                placement: UnsafeCell::new(placement),
                nonce: AtomicU64::new(0),
                phase: AtomicU8::new(ReadPhase::Idle as u8),
            });
            PlacementReadOwner { state: Some(Box::from_raw(storage.as_ptr())) }
        }
    }
}

impl Drop for PlacementReadReservation {
    fn drop(&mut self) {
        // SAFETY: an uninitialized reservation alone owns this exact allocation and has not
        // transferred it to a PlacementReadOwner.
        unsafe { dealloc(self.storage.as_ptr().cast::<u8>(), Layout::new::<PlacementReadState>()) };
    }
}

/// Stable allocation for the sole authoritative physical placement owner. A wrapper can move
/// with its runtime row; its allocation cannot move while the wrapper is retained. The native
/// adapter must retain the wrapper and its exact TCB/SC caps until the loan is settled.
pub struct PlacementReadOwner {
    state: Option<Box<PlacementReadState>>,
}

impl core::fmt::Debug for PlacementReadOwner {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let mut debug = formatter.debug_struct("PlacementReadOwner");
        if let Some(state) = self.state.as_ref() {
            debug.field("nonce", &state.nonce.load(Ordering::Acquire))
                .field("phase", &state.phase.load(Ordering::Acquire));
        }
        debug.finish()
    }
}

impl PlacementReadOwner {
    /// Allocation failure returns an error before a runtime row publishes this owner.
    pub fn try_new(placement: PhysicalPlacementOwner) -> Result<Self, PlacementReadOwnerError> {
        Ok(PlacementReadReservation::try_new()?.initialize(placement))
    }

    fn state(&self) -> &PlacementReadState {
        self.state.as_deref().expect("live placement owner retains its allocation")
    }

    /// Acquire one exact job's move-only loan without copying its core.
    ///
    /// # Safety
    /// The caller must retain this stable owner, its TCB/SC capabilities, and the read loan
    /// throughout the worker Call. Root must not mutate placement while the worker can read it:
    /// the single executor run token and checked next-receive proof serialize those accesses,
    /// including when they run on different cores. An uncertain native result retains the owner
    /// and must use `retain_unresolved`, never retry or release this job.
    pub unsafe fn acquire(
        &mut self,
        identity: PlacementIdentity,
        nonce: u64,
    ) -> Result<PlacementReadLoan, PlacementError> {
        if nonce == 0 {
            return Err(PlacementError::InvalidIdentity);
        }
        let state = self.state();
        // SAFETY: no placement mutation is possible while the phase is active; before setting
        // it, the caller owns the sole mutable placement path through this wrapper.
        unsafe { (&*state.placement.get()).check_identity(identity)? };
        if state.phase.load(Ordering::Acquire) != ReadPhase::Idle as u8 {
            return Err(PlacementError::Busy);
        }
        state.nonce.store(nonce, Ordering::Relaxed);
        state.phase.store(ReadPhase::Active as u8, Ordering::Release);
        Ok(PlacementReadLoan {
            state: NonNull::from(state),
            identity,
            nonce,
        })
    }

    pub fn current_core(&self, identity: PlacementIdentity) -> Result<u8, PlacementError> {
        if self.state().phase.load(Ordering::Acquire) != ReadPhase::Idle as u8 {
            return Err(PlacementError::Busy);
        }
        // SAFETY: a job's read and a placement transition are serialized by the wrapper.
        unsafe { (&*self.state().placement.get()).current_core(identity) }
    }

    pub fn begin(
        &mut self,
        identity: PlacementIdentity,
        target_core: u8,
        active_count: u8,
    ) -> Result<PlacementAttempt, PlacementError> {
        let state = self.state();
        if state.phase.load(Ordering::Acquire) != ReadPhase::Idle as u8 {
            return Err(PlacementError::Busy);
        }
        // SAFETY: no read loan exists, and this wrapper serializes placement transitions.
        unsafe { (&mut *state.placement.get()).begin(identity, target_core, active_count) }
    }

    pub fn settle(
        &mut self,
        attempt: PlacementAttempt,
        effect: PlacementEffect,
    ) -> Result<(), PlacementError> {
        let state = self.state();
        if state.phase.load(Ordering::Acquire) != ReadPhase::Idle as u8 {
            return Err(PlacementError::Busy);
        }
        // SAFETY: no read loan exists, and this wrapper serializes placement transitions.
        unsafe { (&mut *state.placement.get()).settle(attempt, effect) }
    }

    pub fn reconcile(
        &mut self,
        attempt: PlacementAttempt,
        effect: PlacementEffect,
    ) -> Result<(), PlacementError> {
        let state = self.state();
        if state.phase.load(Ordering::Acquire) != ReadPhase::Idle as u8 {
            return Err(PlacementError::Busy);
        }
        // SAFETY: no read loan exists, and this wrapper serializes placement transitions.
        unsafe { (&mut *state.placement.get()).reconcile(attempt, effect) }
    }

    /// A live or unresolved read loan pins the physical mechanism even if its core is known.
    pub fn may_retire(&self) -> bool {
        let state = self.state();
        state.phase.load(Ordering::Acquire) == ReadPhase::Idle as u8
            && unsafe { (&*state.placement.get()).transition_is_settled() }
    }

    fn check_loan(
        &self,
        loan: &PlacementReadLoan,
        identity: PlacementIdentity,
        nonce: u64,
    ) -> Result<(), PlacementError> {
        if nonce == 0 {
            return Err(PlacementError::InvalidIdentity);
        }
        // SAFETY: the owner is live through this method, and its allocation is stable.
        unsafe { (&*self.state().placement.get()).check_identity(identity)? };
        if loan.identity != identity {
            return Err(PlacementError::WrongIdentity);
        }
        if loan.state.as_ptr() != self.state() as *const PlacementReadState as *mut PlacementReadState
            || loan.nonce != nonce
            || self.state().phase.load(Ordering::Acquire) != ReadPhase::Active as u8
            || self.state().nonce.load(Ordering::Relaxed) != nonce
        {
            return Err(PlacementError::StaleAttempt);
        }
        Ok(())
    }

    /// Release only after the exact normal worker terminal, next-receive proof, and hosted
    /// Reply settlement have all been checked by their native owners.
    ///
    /// # Safety
    /// The caller must have checked those three effects for this same job. A reply attempt,
    /// missing rearm proof, or uncertain effect cannot settle the loan.
    pub unsafe fn settle_checked_normal(
        &mut self,
        loan: PlacementReadLoan,
        identity: PlacementIdentity,
        nonce: u64,
    ) -> Result<(), (PlacementError, PlacementReadLoan)> {
        if let Err(error) = self.check_loan(&loan, identity, nonce) {
            return Err((error, loan));
        }
        self.state().nonce.store(0, Ordering::Relaxed);
        self.state().phase.store(ReadPhase::Idle as u8, Ordering::Release);
        Ok(())
    }

    /// Consume the move-only loan into a retained unresolved job. Dropping the loan alone does
    /// not clear the owner; a worker fault or uncertain native effect must take this path.
    pub fn retain_unresolved(
        &mut self,
        loan: PlacementReadLoan,
        identity: PlacementIdentity,
        nonce: u64,
    ) -> Result<(), (PlacementError, PlacementReadLoan)> {
        if let Err(error) = self.check_loan(&loan, identity, nonce) {
            return Err((error, loan));
        }
        self.state().phase.store(ReadPhase::Unresolved as u8, Ordering::Release);
        Ok(())
    }

    /// Release an unresolved job only after the exact worker TCB is retired and its private
    /// and hosted Replies have reached checked settlement. The job may never be replayed.
    ///
    /// # Safety
    /// The native owner must have acknowledged those exact physical retirements/settlements.
    /// An attempted delete or uncertain result does not authorize this call.
    pub unsafe fn settle_after_worker_retirement(
        &mut self,
        identity: PlacementIdentity,
        nonce: u64,
    ) -> Result<(), PlacementError> {
        if nonce == 0 {
            return Err(PlacementError::InvalidIdentity);
        }
        // SAFETY: the owner is live and neither a read nor transition can mutate placement
        // while the unresolved job remains recorded.
        unsafe { (&*self.state().placement.get()).check_identity(identity)? };
        if self.state().nonce.load(Ordering::Relaxed) != nonce {
            return Err(PlacementError::StaleAttempt);
        }
        if self.state().phase.load(Ordering::Acquire) != ReadPhase::Unresolved as u8 {
            return Err(PlacementError::Busy);
        }
        self.state().nonce.store(0, Ordering::Relaxed);
        self.state().phase.store(ReadPhase::Idle as u8, Ordering::Release);
        Ok(())
    }
}

impl Drop for PlacementReadOwner {
    fn drop(&mut self) {
        if self.state.as_ref().is_some_and(|state| {
            state.phase.load(Ordering::Acquire) != ReadPhase::Idle as u8
        }) {
            // A caller that violates the unsafe retention contract must not turn a surviving
            // worker pointer into freed memory. Retain the allocation rather than release it.
            if let Some(state) = self.state.take() {
                core::mem::forget(state);
            }
        }
    }
}

/// One move-only read claim for an exact live worker job. Drop never settles the owner.
#[must_use = "settle normally or retain this exact loan after uncertain effects"]
#[derive(Debug)]
pub struct PlacementReadLoan {
    state: NonNull<PlacementReadState>,
    identity: PlacementIdentity,
    nonce: u64,
}

impl PlacementReadLoan {
    /// Read the current authoritative core, including a pending/uncertain placement refusal.
    /// The unsafe `acquire` contract requires the owner and physical caps to remain retained.
    pub fn current_core(
        &self,
        identity: PlacementIdentity,
        nonce: u64,
    ) -> Result<u8, PlacementError> {
        if identity != self.identity {
            return Err(PlacementError::WrongIdentity);
        }
        if nonce != self.nonce {
            return Err(PlacementError::StaleAttempt);
        }
        // SAFETY: acquire requires the stable owner to outlive this loan. The model records
        // the job before the worker can read it and never mutates placement while it is live.
        let state = unsafe { self.state.as_ref() };
        if state.phase.load(Ordering::Acquire) != ReadPhase::Active as u8 {
            return Err(PlacementError::Busy);
        }
        if state.nonce.load(Ordering::Relaxed) != nonce {
            return Err(PlacementError::StaleAttempt);
        }
        unsafe { (&*state.placement.get()).current_core(identity) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use crate::process_identity::{ProcessGeneration, ProcessIdentity};

    fn identity(generation: u64, tcb: u64, sc: u64) -> PlacementIdentity {
        PlacementIdentity {
            process: ProcessIdentity {
                pid: 42,
                generation: ProcessGeneration::Hosted(generation),
            },
            tid: 512,
            tcb,
            sched_context: sc,
        }
    }

    #[test]
    fn physical_transition_is_invisible_until_its_exact_effect_is_known() {
        let owner = identity(7, 100, 200);
        let mut placement = PhysicalPlacementOwner::new(owner, 0, 4).unwrap();
        let attempt = placement.begin(owner, 2, 4).unwrap();
        assert_eq!(placement.current_core(owner), Err(PlacementError::Busy));
        assert_eq!(placement.begin(owner, 3, 4), Err(PlacementError::Busy));
        assert!(!placement.transition_is_settled());
        placement.settle(attempt, PlacementEffect::Applied).unwrap();
        assert_eq!(placement.current_core(owner), Ok(2));
        assert!(placement.transition_is_settled());
    }

    #[test]
    fn uncertain_effect_keeps_owner_and_forbids_replay_or_retirement() {
        let owner = identity(7, 100, 200);
        let mut placement = PhysicalPlacementOwner::new(owner, 0, 4).unwrap();
        let attempt = placement.begin(owner, 1, 4).unwrap();
        placement
            .settle(attempt, PlacementEffect::Uncertain)
            .unwrap();
        assert_eq!(
            placement.current_core(owner),
            Err(PlacementError::Uncertain)
        );
        assert_eq!(placement.begin(owner, 1, 4), Err(PlacementError::Uncertain));
        assert_eq!(
            placement.settle(attempt, PlacementEffect::Applied),
            Err(PlacementError::StaleAttempt)
        );
        assert!(!placement.transition_is_settled());
        assert_eq!(
            placement.reconcile(attempt, PlacementEffect::Uncertain),
            Err(PlacementError::Uncertain)
        );
        placement
            .reconcile(attempt, PlacementEffect::Applied)
            .unwrap();
        assert_eq!(placement.current_core(owner), Ok(1));
    }

    #[test]
    fn wrong_generation_tcb_or_sc_cannot_change_or_read_placement() {
        let owner = identity(7, 100, 200);
        let mut placement = PhysicalPlacementOwner::new(owner, 0, 4).unwrap();
        for wrong in [
            identity(8, 100, 200),
            identity(7, 101, 200),
            identity(7, 100, 201),
        ] {
            assert_eq!(
                placement.current_core(wrong),
                Err(PlacementError::WrongIdentity)
            );
            assert_eq!(
                placement.begin(wrong, 1, 4),
                Err(PlacementError::WrongIdentity)
            );
        }
        let first = placement.begin(owner, 1, 4).unwrap();
        assert_eq!(
            placement.settle(
                PlacementAttempt {
                    identity: identity(8, 100, 200),
                    ..first
                },
                PlacementEffect::Applied
            ),
            Err(PlacementError::WrongIdentity)
        );
        placement.settle(first, PlacementEffect::NoEffect).unwrap();
        assert_eq!(placement.current_core(owner), Ok(0));
        let second = placement.begin(owner, 2, 4).unwrap();
        assert_eq!(
            placement.settle(first, PlacementEffect::Applied),
            Err(PlacementError::StaleAttempt)
        );
        placement.settle(second, PlacementEffect::Applied).unwrap();
        assert_eq!(placement.current_core(owner), Ok(2));
    }

    #[test]
    fn invalid_core_and_identity_never_enter_a_transition() {
        let owner = identity(7, 100, 200);
        assert!(matches!(
            PhysicalPlacementOwner::new(owner, 0, 0),
            Err(PlacementError::InvalidCore)
        ));
        assert!(matches!(
            PhysicalPlacementOwner::new(owner, 0, 65),
            Err(PlacementError::InvalidCore)
        ));
        assert!(matches!(
            PhysicalPlacementOwner::new(identity(7, 1, 200), 0, 4),
            Err(PlacementError::InvalidIdentity)
        ));
        let mut placement = PhysicalPlacementOwner::new(owner, 0, 4).unwrap();
        assert_eq!(placement.begin(owner, 0, 4), Err(PlacementError::SameCore));
        assert_eq!(
            placement.begin(owner, 4, 4),
            Err(PlacementError::InvalidCore)
        );
        assert_eq!(placement.current_core(owner), Ok(0));
    }

    #[test]
    fn processor_number_query_returns_the_published_core_as_its_result() {
        // NtGetCurrentProcessorNumber returns a processor number in the syscall result field,
        // unlike services whose result field is an NTSTATUS success code.
        assert_eq!(processor_query_result(Ok(0)), 0);
        assert_eq!(processor_query_result(Ok(63)), 63);
    }

    #[test]
    fn processor_number_query_preserves_busy_and_identity_refusals() {
        for error in [PlacementError::Busy, PlacementError::Uncertain] {
            assert_eq!(
                processor_query_result(Err(error)),
                nt_process::STATUS_DEVICE_BUSY,
            );
        }
        for error in [
            PlacementError::InvalidIdentity,
            PlacementError::WrongIdentity,
            PlacementError::InvalidCore,
            PlacementError::SameCore,
            PlacementError::StaleAttempt,
            PlacementError::SequenceExhausted,
        ] {
            assert_eq!(
                processor_query_result(Err(error)),
                nt_process::STATUS_INVALID_HANDLE,
            );
        }
    }

    #[test]
    fn live_read_loan_keeps_the_authoritative_owner_stable_across_row_growth() {
        let key = identity(7, 100, 200);
        let mut rows = Vec::with_capacity(1);
        rows.push(PlacementReadOwner::try_new(
            PhysicalPlacementOwner::new(key, 2, 4).unwrap(),
        ).unwrap());
        // SAFETY: the native adapter retains this fallibly allocated stable owner and the
        // exact TCB/SC caps until the loan is explicitly settled. Moving the Vec wrapper
        // cannot move or destroy the placement allocation while the loan is live.
        let loan = unsafe { rows[0].acquire(key, 41) }.unwrap();

        // The native runtime table may grow after root starts a worker Call. The worker must
        // read the retained placement owner, not an address inside a movable Vec row or a
        // processor number copied by root before the Call.
        for generation in 8..40 {
            rows.push(PlacementReadOwner::try_new(
                PhysicalPlacementOwner::new(identity(generation, 100, 200), 0, 4).unwrap(),
            ).unwrap());
        }
        assert_eq!(loan.current_core(key, 41), Ok(2));
        assert_eq!(loan.current_core(identity(8, 100, 200), 41), Err(PlacementError::WrongIdentity));
        assert_eq!(loan.current_core(key, 42), Err(PlacementError::StaleAttempt));
        assert_eq!(rows[0].begin(key, 3, 4), Err(PlacementError::Busy));
        assert!(!rows[0].may_retire());

        unsafe { rows[0].settle_checked_normal(loan, key, 41) }.unwrap();
        assert!(rows[0].may_retire());
        let attempt = rows[0].begin(key, 3, 4).unwrap();
        rows[0].settle(attempt, PlacementEffect::Applied).unwrap();
        // SAFETY: the same stable owner and physical caps remain retained for this next job.
        let next = unsafe { rows[0].acquire(key, 42) }.unwrap();
        assert_eq!(next.current_core(key, 42), Ok(3));
        unsafe { rows[0].settle_checked_normal(next, key, 42) }.unwrap();
    }

    #[test]
    fn placement_anchor_is_reserved_before_physical_construction_and_initialized_without_allocation() {
        // Native construction can already own a TCB and SC when it learns their exact placement.
        // Reserve the stable allocation first, so publication does not acquire a new OOM edge
        // after those physical effects. The reservation may move before it is initialized.
        let reservation = PlacementReadReservation::try_new().unwrap();
        let mut pending = Vec::with_capacity(1);
        pending.push(reservation);
        for _ in 0..32 {
            pending.push(PlacementReadReservation::try_new().unwrap());
        }

        let key = identity(7, 100, 200);
        let mut owner = pending.swap_remove(0).initialize(
            PhysicalPlacementOwner::new(key, 2, 4).unwrap(),
        );
        // SAFETY: the initialized stable owner and exact TCB/SC caps stay retained until the
        // checked terminal settles this job.
        let loan = unsafe { owner.acquire(key, 49) }.unwrap();
        assert_eq!(loan.current_core(key, 49), Ok(2));
        assert!(!owner.may_retire());
        unsafe { owner.settle_checked_normal(loan, key, 49) }.unwrap();
        assert!(owner.may_retire());
    }

    #[test]
    fn read_loan_admission_and_normal_settlement_require_the_exact_job() {
        let key = identity(7, 100, 200);
        let mut owner = PlacementReadOwner::try_new(
            PhysicalPlacementOwner::new(key, 0, 4).unwrap(),
        ).unwrap();
        // SAFETY: this test retains the stable owner and physical cap identities throughout.
        assert!(matches!(unsafe { owner.acquire(key, 0) }, Err(PlacementError::InvalidIdentity)));
        for wrong in [identity(8, 100, 200), identity(7, 101, 200), identity(7, 100, 201)] {
            assert!(matches!(unsafe { owner.acquire(wrong, 7) }, Err(PlacementError::WrongIdentity)));
        }

        let loan = unsafe { owner.acquire(key, 7) }.unwrap();
        assert!(matches!(unsafe { owner.acquire(key, 8) }, Err(PlacementError::Busy)));
        let (error, loan) = unsafe { owner.settle_checked_normal(loan, key, 8) }.unwrap_err();
        assert_eq!(error, PlacementError::StaleAttempt);
        assert!(!owner.may_retire());
        let (error, loan) = unsafe {
            owner.settle_checked_normal(loan, identity(8, 100, 200), 7)
        }.unwrap_err();
        assert_eq!(error, PlacementError::WrongIdentity);
        assert_eq!(loan.current_core(key, 7), Ok(0));
        unsafe { owner.settle_checked_normal(loan, key, 7) }.unwrap();
        assert!(owner.may_retire());
    }

    #[test]
    fn unresolved_live_job_retains_placement_until_exact_worker_retirement() {
        let key = identity(7, 100, 200);
        for nonce in [11, 12] {
            let mut owner = PlacementReadOwner::try_new(
                PhysicalPlacementOwner::new(key, 1, 4).unwrap(),
            ).unwrap();
            // SAFETY: the owner and exact physical caps are retained until the explicit
            // worker-retirement observation settles the unresolved job.
            let loan = unsafe { owner.acquire(key, nonce) }.unwrap();
            // Both a checked worker fault and an uncertain Call/Reply/query result take this
            // conservative path. A dropped worker-side pointer cannot clear the root owner.
            let (error, loan) = owner.retain_unresolved(loan, key, nonce + 1).unwrap_err();
            assert_eq!(error, PlacementError::StaleAttempt);
            owner.retain_unresolved(loan, key, nonce).unwrap();
            assert_eq!(owner.begin(key, 2, 4), Err(PlacementError::Busy));
            assert!(!owner.may_retire());
            assert_eq!(
                unsafe { owner.settle_after_worker_retirement(key, nonce + 1) },
                Err(PlacementError::StaleAttempt),
            );
            assert_eq!(
                unsafe { owner.settle_after_worker_retirement(identity(8, 100, 200), nonce) },
                Err(PlacementError::WrongIdentity),
            );
            assert!(!owner.may_retire());
            unsafe { owner.settle_after_worker_retirement(key, nonce) }.unwrap();
            assert!(owner.may_retire());
            assert_eq!(owner.current_core(key), Ok(1));
        }
    }
}
