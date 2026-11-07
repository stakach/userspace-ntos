//! Retained, serial ownership of physical TCB priority effects.
//!
//! The payload is the canonical process-manager plan. It cannot be released for commit until
//! every exact TCB operation has a definitive acknowledgment. A lost invocation or uncertain
//! result leaves this owner busy, retaining the runtime binding and preventing replay.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::thread_binding::ThreadBinding;
use nt_process::ThreadLifetime;

static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PriorityTransitionError {
    InvalidBinding,
    DuplicateOwner,
    OwnerChanged,
    Busy,
    WrongInvocation,
    NotComplete,
    Rejected(u32),
    Indeterminate(u32),
    OwnerExhausted,
}

/// A definitive seL4 success, a definitive error before effect, or an uncertain transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PriorityTransitionOutcome {
    Acknowledged,
    Rejected(u32),
    Indeterminate(u32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PriorityEffect<R> {
    binding: ThreadBinding<R>,
    lifetime: ThreadLifetime,
    previous: u8,
    next: u8,
}

impl<R: Copy> PriorityEffect<R> {
    pub const fn new(
        binding: ThreadBinding<R>, lifetime: ThreadLifetime, previous: u8, next: u8,
    ) -> Self {
        Self { binding, lifetime, previous, next }
    }

    pub const fn binding(&self) -> ThreadBinding<R> { self.binding }
    pub const fn lifetime(&self) -> ThreadLifetime { self.lifetime }
    pub const fn previous(&self) -> u8 { self.previous }
    pub const fn next(&self) -> u8 { self.next }
}

/// Once-only authority for one physical syscall. Dropping it leaves the owner Invoking.
///
/// ```compile_fail
/// fn clone_required<T: Clone>() {}
/// clone_required::<nt_user_host::thread_priority_transition::PriorityInvocation<()>>();
/// ```
#[derive(Debug, PartialEq, Eq)]
pub struct PriorityInvocation<R> {
    owner: u64,
    index: usize,
    effect: PriorityEffect<R>,
}

impl<R: Copy> PriorityInvocation<R> {
    pub const fn binding(&self) -> ThreadBinding<R> { self.effect.binding() }
    pub const fn lifetime(&self) -> ThreadLifetime { self.effect.lifetime() }
    pub const fn tcb(&self) -> u64 { self.effect.binding.tcb }
    pub const fn previous(&self) -> u8 { self.effect.previous() }
    pub const fn next(&self) -> u8 { self.effect.next() }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Ready,
    Invoking(usize),
    Rejected(u32),
    Indeterminate(u32),
}

/// Embed in a durable native owner that retains the matching TCB capabilities. The payload is
/// private until every physical effect has been acknowledged and its exact binding revalidated.
pub struct PriorityTransitionOwner<P, R> {
    owner: u64,
    payload: Option<P>,
    effects: Vec<PriorityEffect<R>>,
    next: usize,
    phase: Phase,
}

impl<P, R: Copy + Eq> PriorityTransitionOwner<P, R> {
    pub fn new(payload: P, effects: Vec<PriorityEffect<R>>) -> Result<Self, PriorityTransitionError> {
        let mut process = None;
        let mut pi = None;
        for (index, effect) in effects.iter().enumerate() {
            let binding = effect.binding;
            let lifetime = effect.lifetime;
            if !binding.process.is_valid()
                || binding.tcb <= 1
                || binding.tid != u64::from(lifetime.thread_id())
                || binding.process.pid != lifetime.process_id()
                || lifetime.generation() == 0
                || binding.reservations.is_some_and(|r| r.badge != binding.badge)
                || process.is_some_and(|seen| seen != binding.process)
                || pi.is_some_and(|seen| seen != binding.pi)
            {
                return Err(PriorityTransitionError::InvalidBinding);
            }
            process = Some(binding.process);
            pi = Some(binding.pi);
            if effects[..index].iter().any(|prior| {
                prior.binding.tid == binding.tid
                    || prior.binding.tcb == binding.tcb
                    || prior.binding.badge == binding.badge
            }) {
                return Err(PriorityTransitionError::DuplicateOwner);
            }
        }
        let owner = NEXT_OWNER.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            if value == 0 { None } else { value.checked_add(1) }
        }).map_err(|_| PriorityTransitionError::OwnerExhausted)?;
        Ok(Self { owner, payload: Some(payload), effects, next: 0, phase: Phase::Ready })
    }

    pub fn begin(
        &mut self, current: ThreadBinding<R>, lifetime: ThreadLifetime,
    ) -> Result<PriorityInvocation<R>, PriorityTransitionError> {
        if self.phase != Phase::Ready { return Err(PriorityTransitionError::Busy); }
        let effect = *self.effects.get(self.next).ok_or(PriorityTransitionError::NotComplete)?;
        if effect.binding != current || effect.lifetime != lifetime {
            return Err(PriorityTransitionError::OwnerChanged);
        }
        self.phase = Phase::Invoking(self.next);
        Ok(PriorityInvocation { owner: self.owner, index: self.next, effect })
    }

    pub fn effects(&self) -> &[PriorityEffect<R>] { &self.effects }

    pub fn next_effect(&self) -> Option<PriorityEffect<R>> {
        (self.phase == Phase::Ready).then(|| self.effects.get(self.next).copied()).flatten()
    }

    pub fn complete(
        &mut self, invocation: PriorityInvocation<R>, outcome: PriorityTransitionOutcome,
    ) -> Result<(), PriorityTransitionError> {
        if self.phase != Phase::Invoking(self.next)
            || invocation.owner != self.owner
            || invocation.index != self.next
            || self.effects.get(self.next) != Some(&invocation.effect)
        {
            return Err(PriorityTransitionError::WrongInvocation);
        }
        match outcome {
            PriorityTransitionOutcome::Acknowledged => {
                self.next += 1;
                self.phase = Phase::Ready;
                Ok(())
            }
            PriorityTransitionOutcome::Rejected(status) => {
                self.phase = Phase::Rejected(status);
                Err(PriorityTransitionError::Rejected(status))
            }
            PriorityTransitionOutcome::Indeterminate(status) => {
                self.phase = Phase::Indeterminate(status);
                Err(PriorityTransitionError::Indeterminate(status))
            }
        }
    }

    /// The exact binding held by an incomplete native invocation or uncertain effect.
    pub fn retained_binding(&self) -> Option<ThreadBinding<R>> {
        if self.next == self.effects.len() { None } else {
            self.effects.get(self.next).map(|effect| effect.binding)
        }
    }

    /// No caller can take the PM plan before every physical priority effect is acknowledged.
    pub fn acknowledged_payload(&self) -> Result<&P, PriorityTransitionError> {
        if self.phase != Phase::Ready || self.next != self.effects.len() {
            return Err(PriorityTransitionError::NotComplete);
        }
        self.payload.as_ref().ok_or(PriorityTransitionError::NotComplete)
    }

    /// Release the PM plan after its checked commit succeeds.
    pub fn finish(&mut self) -> Result<P, PriorityTransitionError> {
        self.acknowledged_payload()?;
        self.payload.take().ok_or(PriorityTransitionError::NotComplete)
    }
}
