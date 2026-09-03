//! Kernel-owned continuation state for blocking calls made by isolated NT providers.
//!
//! The dispatcher arbiter owns object readiness and signal consumption. This crate owns the
//! continuation ordering between a provider's single component rendezvous and the native client
//! syscall that caused the provider dispatch.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

mod abi;
mod allocation;
mod arbiter;
mod domain;
mod local_event;
mod local_timer;
mod stack_activation;

pub use abi::*;
pub use allocation::*;
pub use arbiter::*;
pub use domain::*;
pub use local_event::*;
pub use local_timer::*;
pub use stack_activation::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderWaitOwner {
    pub provider_domain: u64,
    pub provider_generation: u64,
    pub client_pi: u32,
    pub client_generation: u64,
    pub client_tid: u64,
    pub client_badge: u64,
    pub dispatch_id: u64,
}

impl ProviderWaitOwner {
    pub const fn is_valid(self) -> bool {
        self.provider_domain != 0
            && self.provider_generation != 0
            && self.client_generation != 0
            && self.client_tid != 0
            && self.client_badge != 0
            && self.dispatch_id != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWaitTeardownScope {
    Provider {
        provider_domain: u64,
        provider_generation: u64,
    },
    Process {
        provider_domain: u64,
        provider_generation: u64,
        client_pi: u32,
        client_generation: u64,
    },
    Thread {
        provider_domain: u64,
        provider_generation: u64,
        client_pi: u32,
        client_generation: u64,
        client_tid: u64,
    },
}

impl ProviderWaitTeardownScope {
    pub const fn is_valid(self) -> bool {
        match self {
            Self::Provider {
                provider_domain,
                provider_generation,
            }
            | Self::Process {
                provider_domain,
                provider_generation,
                ..
            }
            | Self::Thread {
                provider_domain,
                provider_generation,
                ..
            } => {
                if provider_domain == 0 || provider_generation == 0 {
                    return false;
                }
            }
        }
        match self {
            Self::Provider { .. } => true,
            Self::Process {
                client_generation, ..
            } => client_generation != 0,
            Self::Thread {
                client_generation,
                client_tid,
                ..
            } => client_generation != 0 && client_tid != 0,
        }
    }

    pub const fn matches(self, owner: ProviderWaitOwner) -> bool {
        if !self.is_valid()
            || owner.provider_domain != self.provider_domain()
            || owner.provider_generation != self.provider_generation()
        {
            return false;
        }
        match self {
            Self::Provider { .. } => true,
            Self::Process {
                client_pi,
                client_generation,
                ..
            } => owner.client_pi == client_pi && owner.client_generation == client_generation,
            Self::Thread {
                client_pi,
                client_generation,
                client_tid,
                ..
            } => {
                owner.client_pi == client_pi
                    && owner.client_generation == client_generation
                    && owner.client_tid == client_tid
            }
        }
    }

    const fn provider_domain(self) -> u64 {
        match self {
            Self::Provider {
                provider_domain, ..
            }
            | Self::Process {
                provider_domain, ..
            }
            | Self::Thread {
                provider_domain, ..
            } => provider_domain,
        }
    }

    const fn provider_generation(self) -> u64 {
        match self {
            Self::Provider {
                provider_generation,
                ..
            }
            | Self::Process {
                provider_generation,
                ..
            }
            | Self::Thread {
                provider_generation,
                ..
            } => provider_generation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWaitPhase {
    Waiting,
    Selected { status: i32 },
    Resuming { status: i32, cancelled: bool },
    Cancelled { status: i32 },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderWaitFrame<C> {
    pub wait_id: u64,
    pub admission_sequence: u64,
    pub owner: ProviderWaitOwner,
    pub phase: ProviderWaitPhase,
    pub continuation: C,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderWaitResume {
    pub wait_id: u64,
    pub status: i32,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedProviderWait<C> {
    pub wait_id: u64,
    pub owner: ProviderWaitOwner,
    pub status: i32,
    pub cancelled: bool,
    pub continuation: C,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderWaitError {
    InvalidIdentity,
    DuplicateIdentity,
    Overflow,
    NoCapacity,
    NotFound,
    NotTop,
    InvalidPhase,
}

/// LIFO continuation ownership for a provider component with one active rendezvous.
///
/// A wait below the top may be selected or cancelled, but only the top frame can resume. This is
/// what lets an independent nested client dispatch block without allowing an older component stack
/// frame to resume out of order.
pub struct ProviderWaitStack<C> {
    frames: Vec<ProviderWaitFrame<C>>,
    max_depth: usize,
}

impl<C> ProviderWaitStack<C> {
    pub const fn new(max_depth: usize) -> Self {
        Self {
            frames: Vec::new(),
            max_depth,
        }
    }

    pub fn len(&self) -> usize {
        self.frames.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frames.is_empty()
    }

    pub fn top(&self) -> Option<&ProviderWaitFrame<C>> {
        self.frames.last()
    }

    pub fn frames(&self) -> &[ProviderWaitFrame<C>] {
        &self.frames
    }

    pub fn get(&self, wait_id: u64) -> Option<&ProviderWaitFrame<C>> {
        self.frames.iter().find(|frame| frame.wait_id == wait_id)
    }

    pub fn get_mut(&mut self, wait_id: u64) -> Option<&mut ProviderWaitFrame<C>> {
        self.frames
            .iter_mut()
            .find(|frame| frame.wait_id == wait_id)
    }

    pub fn contains_scope(&self, scope: ProviderWaitTeardownScope) -> bool {
        scope.is_valid() && self.frames.iter().any(|frame| scope.matches(frame.owner))
    }

    pub fn next_cancellable_in_scope(&self, scope: ProviderWaitTeardownScope) -> Option<u64> {
        if !scope.is_valid() {
            return None;
        }
        self.frames.iter().find_map(|frame| {
            (scope.matches(frame.owner)
                && matches!(
                    frame.phase,
                    ProviderWaitPhase::Waiting | ProviderWaitPhase::Selected { .. }
                ))
            .then_some(frame.wait_id)
        })
    }

    /// Reserve and publish a new blocked dispatch before the dispatcher arbiter commits its wait.
    pub fn admit(
        &mut self,
        wait_id: u64,
        admission_sequence: u64,
        owner: ProviderWaitOwner,
        continuation: C,
    ) -> Result<(), ProviderWaitError> {
        if wait_id == 0 || admission_sequence == 0 || !owner.is_valid() {
            return Err(ProviderWaitError::InvalidIdentity);
        }
        if self.frames.iter().any(|frame| {
            frame.wait_id == wait_id
                || (frame.owner.provider_domain == owner.provider_domain
                    && frame.owner.provider_generation == owner.provider_generation
                    && frame.owner.dispatch_id == owner.dispatch_id)
        }) {
            return Err(ProviderWaitError::DuplicateIdentity);
        }
        if self.frames.len() >= self.max_depth {
            return Err(ProviderWaitError::Overflow);
        }
        self.frames
            .try_reserve(1)
            .map_err(|_| ProviderWaitError::NoCapacity)?;
        self.frames.push(ProviderWaitFrame {
            wait_id,
            admission_sequence,
            owner,
            phase: ProviderWaitPhase::Waiting,
            continuation,
        });
        Ok(())
    }

    /// Roll back a wait whose dispatcher admission failed after continuation storage was reserved.
    pub fn rollback_admission(&mut self, wait_id: u64) -> Result<C, ProviderWaitError> {
        let frame = self.frames.last().ok_or(ProviderWaitError::NotFound)?;
        if frame.wait_id != wait_id {
            return Err(ProviderWaitError::NotTop);
        }
        if frame.phase != ProviderWaitPhase::Waiting {
            return Err(ProviderWaitError::InvalidPhase);
        }
        Ok(self.frames.pop().unwrap().continuation)
    }

    /// Mark readiness without violating the provider component's LIFO stack order.
    pub fn select(&mut self, wait_id: u64, status: i32) -> Result<(), ProviderWaitError> {
        let frame = self
            .frames
            .iter_mut()
            .find(|frame| frame.wait_id == wait_id)
            .ok_or(ProviderWaitError::NotFound)?;
        match frame.phase {
            ProviderWaitPhase::Waiting => {
                frame.phase = ProviderWaitPhase::Selected { status };
                Ok(())
            }
            ProviderWaitPhase::Selected {
                status: selected_status,
            } if selected_status == status => Ok(()),
            _ => Err(ProviderWaitError::InvalidPhase),
        }
    }

    /// Cancellation is retained on the exact frame and unwinds only when that frame reaches top.
    pub fn cancel(&mut self, wait_id: u64, status: i32) -> Result<(), ProviderWaitError> {
        let frame = self
            .frames
            .iter_mut()
            .find(|frame| frame.wait_id == wait_id)
            .ok_or(ProviderWaitError::NotFound)?;
        match frame.phase {
            ProviderWaitPhase::Waiting | ProviderWaitPhase::Selected { .. } => {
                frame.phase = ProviderWaitPhase::Cancelled { status };
                Ok(())
            }
            ProviderWaitPhase::Cancelled {
                status: cancelled_status,
            } if cancelled_status == status => Ok(()),
            _ => Err(ProviderWaitError::InvalidPhase),
        }
    }

    pub fn top_resume(&self) -> Option<ProviderWaitResume> {
        let frame = self.frames.last()?;
        match frame.phase {
            ProviderWaitPhase::Selected { status } => Some(ProviderWaitResume {
                wait_id: frame.wait_id,
                status,
                cancelled: false,
            }),
            ProviderWaitPhase::Cancelled { status } => Some(ProviderWaitResume {
                wait_id: frame.wait_id,
                status,
                cancelled: true,
            }),
            ProviderWaitPhase::Waiting | ProviderWaitPhase::Resuming { .. } => None,
        }
    }

    pub fn begin_resume(&mut self, wait_id: u64) -> Result<ProviderWaitResume, ProviderWaitError> {
        let frame = self.frames.last_mut().ok_or(ProviderWaitError::NotFound)?;
        if frame.wait_id != wait_id {
            return Err(ProviderWaitError::NotTop);
        }
        let resume = match frame.phase {
            ProviderWaitPhase::Selected { status } => ProviderWaitResume {
                wait_id,
                status,
                cancelled: false,
            },
            ProviderWaitPhase::Cancelled { status } => ProviderWaitResume {
                wait_id,
                status,
                cancelled: true,
            },
            _ => return Err(ProviderWaitError::InvalidPhase),
        };
        frame.phase = ProviderWaitPhase::Resuming {
            status: resume.status,
            cancelled: resume.cancelled,
        };
        Ok(resume)
    }

    /// Re-arm the same native dispatch if provider execution blocks again before returning to its
    /// receive loop. The caller supplies the refreshed provider-side state while retaining the
    /// same native continuation owner.
    pub fn rearm(
        &mut self,
        completed_wait_id: u64,
        next_wait_id: u64,
        admission_sequence: u64,
        owner: ProviderWaitOwner,
        continuation: C,
    ) -> Result<(), ProviderWaitError> {
        if next_wait_id == 0 || admission_sequence == 0 || !owner.is_valid() {
            return Err(ProviderWaitError::InvalidIdentity);
        }
        if self
            .frames
            .iter()
            .any(|frame| frame.wait_id == next_wait_id)
        {
            return Err(ProviderWaitError::DuplicateIdentity);
        }
        let frame = self.frames.last_mut().ok_or(ProviderWaitError::NotFound)?;
        if frame.wait_id != completed_wait_id {
            return Err(ProviderWaitError::NotTop);
        }
        if !matches!(frame.phase, ProviderWaitPhase::Resuming { .. }) || frame.owner != owner {
            return Err(ProviderWaitError::InvalidPhase);
        }
        frame.wait_id = next_wait_id;
        frame.admission_sequence = admission_sequence;
        frame.phase = ProviderWaitPhase::Waiting;
        frame.continuation = continuation;
        Ok(())
    }

    /// Finish the provider dispatch and return its native continuation exactly once.
    pub fn complete_dispatch(
        &mut self,
        wait_id: u64,
        owner: ProviderWaitOwner,
    ) -> Result<CompletedProviderWait<C>, ProviderWaitError> {
        let frame = self.frames.last().ok_or(ProviderWaitError::NotFound)?;
        if frame.wait_id != wait_id {
            return Err(ProviderWaitError::NotTop);
        }
        if frame.owner != owner {
            return Err(ProviderWaitError::InvalidIdentity);
        }
        let (status, cancelled) = match frame.phase {
            ProviderWaitPhase::Resuming { status, cancelled } => (status, cancelled),
            _ => return Err(ProviderWaitError::InvalidPhase),
        };
        let frame = self.frames.pop().unwrap();
        Ok(CompletedProviderWait {
            wait_id: frame.wait_id,
            owner: frame.owner,
            status,
            cancelled,
            continuation: frame.continuation,
        })
    }

    /// Abort a top dispatch after provider-side re-arm validation failed. This consumes the same
    /// continuation ownership as normal completion, without leaving an unreachable `Resuming`
    /// frame behind.
    pub fn abort_resume(
        &mut self,
        wait_id: u64,
        owner: ProviderWaitOwner,
        status: i32,
    ) -> Result<CompletedProviderWait<C>, ProviderWaitError> {
        let frame = self.frames.last().ok_or(ProviderWaitError::NotFound)?;
        if frame.wait_id != wait_id {
            return Err(ProviderWaitError::NotTop);
        }
        if frame.owner != owner {
            return Err(ProviderWaitError::InvalidIdentity);
        }
        if !matches!(frame.phase, ProviderWaitPhase::Resuming { .. }) {
            return Err(ProviderWaitError::InvalidPhase);
        }
        let frame = self.frames.pop().unwrap();
        Ok(CompletedProviderWait {
            wait_id: frame.wait_id,
            owner: frame.owner,
            status,
            cancelled: true,
            continuation: frame.continuation,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS_WAIT_0: i32 = 0;
    const STATUS_TIMEOUT: i32 = 0x102;
    const STATUS_CANCELLED: i32 = 0xC000_0120u32 as i32;

    fn owner(dispatch_id: u64, client_badge: u64) -> ProviderWaitOwner {
        ProviderWaitOwner {
            provider_domain: 7,
            provider_generation: 3,
            client_pi: client_badge as u32,
            client_generation: 11,
            client_tid: 100 + client_badge,
            client_badge,
            dispatch_id,
        }
    }

    #[test]
    fn selected_non_top_wait_is_deferred_until_nested_dispatch_unwinds() {
        let outer = owner(1, 10);
        let inner = owner(2, 20);
        let mut stack = ProviderWaitStack::new(4);
        stack.admit(101, 1, outer, "outer").unwrap();
        stack.admit(102, 2, inner, "inner").unwrap();
        stack.select(101, STATUS_WAIT_0).unwrap();
        assert_eq!(stack.top_resume(), None);

        stack.select(102, STATUS_TIMEOUT).unwrap();
        assert_eq!(stack.begin_resume(102).unwrap().status, STATUS_TIMEOUT);
        assert_eq!(
            stack.complete_dispatch(102, inner).unwrap().continuation,
            "inner"
        );
        assert_eq!(stack.top_resume().unwrap().wait_id, 101);
    }

    #[test]
    fn cancellation_is_exact_idempotent_and_lifo() {
        let outer = owner(1, 10);
        let inner = owner(2, 20);
        let mut stack = ProviderWaitStack::new(4);
        stack.admit(101, 1, outer, 1).unwrap();
        stack.admit(102, 2, inner, 2).unwrap();
        stack.cancel(101, STATUS_CANCELLED).unwrap();
        stack.cancel(101, STATUS_CANCELLED).unwrap();
        assert_eq!(stack.top_resume(), None);
        assert_eq!(
            stack.cancel(101, STATUS_TIMEOUT),
            Err(ProviderWaitError::InvalidPhase)
        );
        stack.cancel(102, STATUS_CANCELLED).unwrap();
        assert!(stack.begin_resume(102).unwrap().cancelled);
        assert!(stack.complete_dispatch(102, inner).unwrap().cancelled);
        assert!(stack.top_resume().unwrap().cancelled);
        assert!(stack.begin_resume(101).unwrap().cancelled);
        assert!(stack.complete_dispatch(101, outer).unwrap().cancelled);
    }

    #[test]
    fn rearm_retains_the_native_continuation() {
        let identity = owner(5, 30);
        let mut stack = ProviderWaitStack::new(2);
        stack.admit(201, 10, identity, 0xfeed).unwrap();
        stack.select(201, STATUS_WAIT_0).unwrap();
        stack.begin_resume(201).unwrap();
        stack.rearm(201, 202, 11, identity, 0xbeef).unwrap();
        let frame = stack.top().unwrap();
        assert_eq!(frame.wait_id, 202);
        assert_eq!(frame.admission_sequence, 11);
        assert_eq!(frame.phase, ProviderWaitPhase::Waiting);
        assert_eq!(frame.continuation, 0xbeef);
    }

    #[test]
    fn rollback_only_removes_the_unselected_top_admission() {
        let outer = owner(1, 10);
        let inner = owner(2, 20);
        let mut stack = ProviderWaitStack::new(3);
        stack.admit(301, 1, outer, 1).unwrap();
        stack.admit(302, 2, inner, 2).unwrap();
        assert_eq!(
            stack.rollback_admission(301),
            Err(ProviderWaitError::NotTop)
        );
        assert_eq!(stack.rollback_admission(302), Ok(2));
        stack.select(301, STATUS_WAIT_0).unwrap();
        assert_eq!(
            stack.rollback_admission(301),
            Err(ProviderWaitError::InvalidPhase)
        );
    }

    #[test]
    fn invalid_duplicate_and_stale_identities_fail_closed() {
        let identity = owner(1, 10);
        let mut stack = ProviderWaitStack::new(1);
        assert_eq!(
            stack.admit(0, 1, identity, 1),
            Err(ProviderWaitError::InvalidIdentity)
        );
        stack.admit(401, 1, identity, 1).unwrap();
        assert_eq!(
            stack.admit(402, 2, identity, 2),
            Err(ProviderWaitError::DuplicateIdentity)
        );
        assert_eq!(
            stack.select(999, STATUS_WAIT_0),
            Err(ProviderWaitError::NotFound)
        );
        assert_eq!(
            stack.complete_dispatch(401, identity),
            Err(ProviderWaitError::InvalidPhase)
        );
    }

    #[test]
    fn depth_bound_rejects_an_independent_nested_wait() {
        let mut stack = ProviderWaitStack::new(1);
        stack.admit(501, 1, owner(1, 10), 1).unwrap();
        assert_eq!(
            stack.admit(502, 2, owner(2, 20), 2),
            Err(ProviderWaitError::Overflow)
        );
    }

    #[test]
    fn teardown_scopes_match_exact_provider_process_and_thread_generations() {
        let first = owner(1, 10);
        let second = owner(2, 20);
        let mut stack = ProviderWaitStack::new(4);
        stack.admit(601, 1, first, 1).unwrap();
        stack.admit(602, 2, second, 2).unwrap();

        let thread = ProviderWaitTeardownScope::Thread {
            provider_domain: 7,
            provider_generation: 3,
            client_pi: 10,
            client_generation: 11,
            client_tid: 110,
        };
        assert!(stack.contains_scope(thread));
        assert_eq!(stack.next_cancellable_in_scope(thread), Some(601));
        stack.cancel(601, STATUS_CANCELLED).unwrap();
        assert_eq!(stack.next_cancellable_in_scope(thread), None);
        assert!(stack.contains_scope(thread));

        let stale_process = ProviderWaitTeardownScope::Process {
            provider_domain: 7,
            provider_generation: 3,
            client_pi: 10,
            client_generation: 12,
        };
        assert!(!stack.contains_scope(stale_process));
        assert!(stack.contains_scope(ProviderWaitTeardownScope::Provider {
            provider_domain: 7,
            provider_generation: 3,
        }));
        assert!(!stack.contains_scope(ProviderWaitTeardownScope::Provider {
            provider_domain: 7,
            provider_generation: 4,
        }));
    }

    #[test]
    fn failed_rearm_aborts_and_returns_the_continuation_once() {
        let identity = owner(7, 30);
        let mut stack = ProviderWaitStack::new(2);
        stack.admit(701, 1, identity, 0xcafe).unwrap();
        stack.select(701, STATUS_WAIT_0).unwrap();
        stack.begin_resume(701).unwrap();
        let completed = stack
            .abort_resume(701, identity, STATUS_CANCELLED)
            .unwrap();
        assert_eq!(completed.continuation, 0xcafe);
        assert_eq!(completed.status, STATUS_CANCELLED);
        assert!(completed.cancelled);
        assert!(stack.is_empty());
        assert_eq!(
            stack.abort_resume(701, identity, STATUS_CANCELLED),
            Err(ProviderWaitError::NotFound)
        );
    }
}
