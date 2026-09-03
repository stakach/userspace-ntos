//! Cross-kind ownership for one component's retained synchronous Calls.
//!
//! Readiness sources may select any outstanding frame, but only the top physical component frame
//! may resume. A resumed dispatch that blocks again can rearm under another typed key while keeping
//! its one native continuation.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuspensionKind {
    ProviderWait,
    LpcRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuspensionKey {
    pub kind: SuspensionKind,
    pub id: u64,
}

impl SuspensionKey {
    pub const fn provider_wait(id: u64) -> Self {
        Self {
            kind: SuspensionKind::ProviderWait,
            id,
        }
    }

    pub const fn lpc_request(id: u64) -> Self {
        Self {
            kind: SuspensionKind::LpcRequest,
            id,
        }
    }

    pub const fn is_valid(self) -> bool {
        self.id != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuspensionOwner {
    pub provider_domain: u64,
    pub provider_generation: u64,
    pub client_pi: u32,
    pub client_generation: u64,
    pub client_tid: u64,
    pub client_badge: u64,
    pub dispatch_id: u64,
}

impl SuspensionOwner {
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
pub enum SuspensionScope {
    Provider {
        domain: u64,
        generation: u64,
    },
    Process {
        domain: u64,
        provider_generation: u64,
        client_pi: u32,
        client_generation: u64,
    },
    Thread {
        domain: u64,
        provider_generation: u64,
        client_pi: u32,
        client_generation: u64,
        client_tid: u64,
        client_badge: u64,
    },
}

impl SuspensionScope {
    pub const fn is_valid(self) -> bool {
        match self {
            Self::Provider { domain, generation } => domain != 0 && generation != 0,
            Self::Process {
                domain,
                provider_generation,
                client_generation,
                ..
            } => domain != 0 && provider_generation != 0 && client_generation != 0,
            Self::Thread {
                domain,
                provider_generation,
                client_generation,
                client_tid,
                client_badge,
                ..
            } => {
                domain != 0
                    && provider_generation != 0
                    && client_generation != 0
                    && client_tid != 0
                    && client_badge != 0
            }
        }
    }

    pub const fn matches(self, owner: SuspensionOwner) -> bool {
        match self {
            Self::Provider { domain, generation } => {
                owner.provider_domain == domain && owner.provider_generation == generation
            }
            Self::Process {
                domain,
                provider_generation,
                client_pi,
                client_generation,
            } => {
                owner.provider_domain == domain
                    && owner.provider_generation == provider_generation
                    && owner.client_pi == client_pi
                    && owner.client_generation == client_generation
            }
            Self::Thread {
                domain,
                provider_generation,
                client_pi,
                client_generation,
                client_tid,
                client_badge,
            } => {
                owner.provider_domain == domain
                    && owner.provider_generation == provider_generation
                    && owner.client_pi == client_pi
                    && owner.client_generation == client_generation
                    && owner.client_tid == client_tid
                    && owner.client_badge == client_badge
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SuspensionPhase<R> {
    Waiting,
    Selected { completion: R },
    Resuming { completion: R, cancelled: bool },
    Cancelled { completion: R },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuspensionFrame<C, R> {
    pub key: SuspensionKey,
    pub admission_sequence: u64,
    pub owner: SuspensionOwner,
    pub phase: SuspensionPhase<R>,
    pub continuation: C,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuspensionResume<R> {
    pub key: SuspensionKey,
    pub completion: R,
    pub cancelled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompletedSuspension<C, R> {
    pub key: SuspensionKey,
    pub owner: SuspensionOwner,
    pub completion: R,
    pub cancelled: bool,
    pub continuation: C,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SuspensionError {
    InvalidIdentity,
    DuplicateIdentity,
    Overflow,
    NoCapacity,
    NotFound,
    NotTop,
    InvalidPhase,
}

pub struct ComponentSuspensionStack<C, R> {
    frames: Vec<SuspensionFrame<C, R>>,
    max_depth: usize,
}

impl<C, R> ComponentSuspensionStack<C, R> {
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

    pub fn top(&self) -> Option<&SuspensionFrame<C, R>> {
        self.frames.last()
    }

    pub fn frames(&self) -> &[SuspensionFrame<C, R>] {
        &self.frames
    }

    pub fn get(&self, key: SuspensionKey) -> Option<&SuspensionFrame<C, R>> {
        self.frames.iter().find(|frame| frame.key == key)
    }

    pub fn get_mut(&mut self, key: SuspensionKey) -> Option<&mut SuspensionFrame<C, R>> {
        self.frames.iter_mut().find(|frame| frame.key == key)
    }

    pub fn contains_scope(&self, scope: SuspensionScope) -> bool {
        scope.is_valid() && self.frames.iter().any(|frame| scope.matches(frame.owner))
    }

    pub fn next_cancellable_in_scope(&self, scope: SuspensionScope) -> Option<SuspensionKey> {
        if !scope.is_valid() {
            return None;
        }
        self.frames.iter().find_map(|frame| {
            (scope.matches(frame.owner)
                && matches!(
                    frame.phase,
                    SuspensionPhase::Waiting | SuspensionPhase::Selected { .. }
                ))
            .then_some(frame.key)
        })
    }

    pub fn admit(
        &mut self,
        key: SuspensionKey,
        admission_sequence: u64,
        owner: SuspensionOwner,
        continuation: C,
    ) -> Result<(), SuspensionError> {
        if !key.is_valid() || admission_sequence == 0 || !owner.is_valid() {
            return Err(SuspensionError::InvalidIdentity);
        }
        if self.frames.iter().any(|frame| {
            frame.key == key
                || (frame.owner.provider_domain == owner.provider_domain
                    && frame.owner.provider_generation == owner.provider_generation
                    && frame.owner.dispatch_id == owner.dispatch_id)
        }) {
            return Err(SuspensionError::DuplicateIdentity);
        }
        if self.frames.len() >= self.max_depth {
            return Err(SuspensionError::Overflow);
        }
        self.frames
            .try_reserve(1)
            .map_err(|_| SuspensionError::NoCapacity)?;
        self.frames.push(SuspensionFrame {
            key,
            admission_sequence,
            owner,
            phase: SuspensionPhase::Waiting,
            continuation,
        });
        Ok(())
    }

    pub fn rollback_admission(&mut self, key: SuspensionKey) -> Result<C, SuspensionError> {
        let frame = self.frames.last().ok_or(SuspensionError::NotFound)?;
        if frame.key != key {
            return Err(SuspensionError::NotTop);
        }
        if !matches!(frame.phase, SuspensionPhase::Waiting) {
            return Err(SuspensionError::InvalidPhase);
        }
        Ok(self.frames.pop().unwrap().continuation)
    }

    pub fn select(&mut self, key: SuspensionKey, completion: R) -> Result<(), SuspensionError> {
        let frame = self
            .frames
            .iter_mut()
            .find(|frame| frame.key == key)
            .ok_or(SuspensionError::NotFound)?;
        if !matches!(frame.phase, SuspensionPhase::Waiting) {
            return Err(SuspensionError::InvalidPhase);
        }
        frame.phase = SuspensionPhase::Selected { completion };
        Ok(())
    }

    pub fn cancel(&mut self, key: SuspensionKey, completion: R) -> Result<(), SuspensionError> {
        let frame = self
            .frames
            .iter_mut()
            .find(|frame| frame.key == key)
            .ok_or(SuspensionError::NotFound)?;
        if !matches!(
            frame.phase,
            SuspensionPhase::Waiting | SuspensionPhase::Selected { .. }
        ) {
            return Err(SuspensionError::InvalidPhase);
        }
        frame.phase = SuspensionPhase::Cancelled { completion };
        Ok(())
    }
}

impl<C, R: Clone> ComponentSuspensionStack<C, R> {
    pub fn top_resume(&self) -> Option<SuspensionResume<R>> {
        let frame = self.frames.last()?;
        match &frame.phase {
            SuspensionPhase::Selected { completion } => Some(SuspensionResume {
                key: frame.key,
                completion: completion.clone(),
                cancelled: false,
            }),
            SuspensionPhase::Cancelled { completion } => Some(SuspensionResume {
                key: frame.key,
                completion: completion.clone(),
                cancelled: true,
            }),
            SuspensionPhase::Waiting | SuspensionPhase::Resuming { .. } => None,
        }
    }

    pub fn begin_resume(
        &mut self,
        key: SuspensionKey,
    ) -> Result<SuspensionResume<R>, SuspensionError> {
        let frame = self.frames.last_mut().ok_or(SuspensionError::NotFound)?;
        if frame.key != key {
            return Err(SuspensionError::NotTop);
        }
        let resume = match &frame.phase {
            SuspensionPhase::Selected { completion } => SuspensionResume {
                key,
                completion: completion.clone(),
                cancelled: false,
            },
            SuspensionPhase::Cancelled { completion } => SuspensionResume {
                key,
                completion: completion.clone(),
                cancelled: true,
            },
            _ => return Err(SuspensionError::InvalidPhase),
        };
        frame.phase = SuspensionPhase::Resuming {
            completion: resume.completion.clone(),
            cancelled: resume.cancelled,
        };
        Ok(resume)
    }

    pub fn rearm(
        &mut self,
        completed_key: SuspensionKey,
        next_key: SuspensionKey,
        admission_sequence: u64,
        owner: SuspensionOwner,
        continuation: C,
    ) -> Result<(), SuspensionError> {
        if !next_key.is_valid() || admission_sequence == 0 || !owner.is_valid() {
            return Err(SuspensionError::InvalidIdentity);
        }
        if self.frames.iter().any(|frame| frame.key == next_key) {
            return Err(SuspensionError::DuplicateIdentity);
        }
        let frame = self.frames.last_mut().ok_or(SuspensionError::NotFound)?;
        if frame.key != completed_key {
            return Err(SuspensionError::NotTop);
        }
        if !matches!(frame.phase, SuspensionPhase::Resuming { .. }) || frame.owner != owner {
            return Err(SuspensionError::InvalidPhase);
        }
        frame.key = next_key;
        frame.admission_sequence = admission_sequence;
        frame.phase = SuspensionPhase::Waiting;
        frame.continuation = continuation;
        Ok(())
    }

    pub fn complete_dispatch(
        &mut self,
        key: SuspensionKey,
        owner: SuspensionOwner,
    ) -> Result<CompletedSuspension<C, R>, SuspensionError> {
        let frame = self.frames.last().ok_or(SuspensionError::NotFound)?;
        if frame.key != key {
            return Err(SuspensionError::NotTop);
        }
        if frame.owner != owner {
            return Err(SuspensionError::InvalidIdentity);
        }
        let (completion, cancelled) = match &frame.phase {
            SuspensionPhase::Resuming {
                completion,
                cancelled,
            } => (completion.clone(), *cancelled),
            _ => return Err(SuspensionError::InvalidPhase),
        };
        let frame = self.frames.pop().unwrap();
        Ok(CompletedSuspension {
            key: frame.key,
            owner: frame.owner,
            completion,
            cancelled,
            continuation: frame.continuation,
        })
    }

    pub fn abort_resume(
        &mut self,
        key: SuspensionKey,
        owner: SuspensionOwner,
        completion: R,
    ) -> Result<CompletedSuspension<C, R>, SuspensionError> {
        let frame = self.frames.last_mut().ok_or(SuspensionError::NotFound)?;
        if frame.key != key {
            return Err(SuspensionError::NotTop);
        }
        if frame.owner != owner {
            return Err(SuspensionError::InvalidIdentity);
        }
        if !matches!(frame.phase, SuspensionPhase::Resuming { .. }) {
            return Err(SuspensionError::InvalidPhase);
        }
        frame.phase = SuspensionPhase::Resuming {
            completion,
            cancelled: true,
        };
        self.complete_dispatch(key, owner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(dispatch_id: u64) -> SuspensionOwner {
        SuspensionOwner {
            provider_domain: 3,
            provider_generation: 7,
            client_pi: 2,
            client_generation: 11,
            client_tid: 24 + dispatch_id,
            client_badge: 4 + dispatch_id,
            dispatch_id,
        }
    }

    #[test]
    fn buried_provider_selection_waits_for_top_lpc() {
        let mut stack = ComponentSuspensionStack::new(4);
        let provider = SuspensionKey::provider_wait(1);
        let lpc = SuspensionKey::lpc_request(2);
        stack.admit(provider, 1, owner(1), "provider").unwrap();
        stack.admit(lpc, 2, owner(2), "lpc").unwrap();
        stack.select(provider, 0u32).unwrap();
        assert_eq!(stack.top_resume(), None);
        stack.select(lpc, 0u32).unwrap();
        stack.begin_resume(lpc).unwrap();
        stack.complete_dispatch(lpc, owner(2)).unwrap();
        assert_eq!(stack.top_resume().unwrap().key, provider);
    }

    #[test]
    fn buried_lpc_selection_waits_for_top_provider() {
        let mut stack = ComponentSuspensionStack::new(4);
        let lpc = SuspensionKey::lpc_request(1);
        let provider = SuspensionKey::provider_wait(2);
        stack.admit(lpc, 1, owner(1), "lpc").unwrap();
        stack.admit(provider, 2, owner(2), "provider").unwrap();
        stack.select(lpc, 7u32).unwrap();
        assert_eq!(stack.top_resume(), None);
        stack.select(provider, 8u32).unwrap();
        stack.begin_resume(provider).unwrap();
        stack.complete_dispatch(provider, owner(2)).unwrap();
        assert_eq!(stack.top_resume().unwrap().completion, 7);
    }

    #[test]
    fn same_dispatch_rearms_across_kinds_without_growing() {
        let mut stack = ComponentSuspensionStack::new(2);
        let first = SuspensionKey::lpc_request(1);
        let second = SuspensionKey::provider_wait(2);
        stack.admit(first, 1, owner(1), 10u64).unwrap();
        stack.select(first, 0u32).unwrap();
        stack.begin_resume(first).unwrap();
        stack.rearm(first, second, 2, owner(1), 11).unwrap();
        assert_eq!(stack.len(), 1);
        assert_eq!(stack.top().unwrap().continuation, 11);
        assert!(matches!(stack.top().unwrap().phase, SuspensionPhase::Waiting));
    }

    #[test]
    fn duplicate_key_or_dispatch_owner_is_rejected() {
        let mut stack = ComponentSuspensionStack::<u64, u32>::new(4);
        let key = SuspensionKey::provider_wait(1);
        stack.admit(key, 1, owner(1), 1).unwrap();
        assert_eq!(
            stack.admit(key, 2, owner(2), 2),
            Err(SuspensionError::DuplicateIdentity)
        );
        assert_eq!(
            stack.admit(SuspensionKey::lpc_request(2), 2, owner(1), 2),
            Err(SuspensionError::DuplicateIdentity)
        );
    }

    #[test]
    fn select_cancel_and_resume_are_exactly_once() {
        let mut stack = ComponentSuspensionStack::new(2);
        let key = SuspensionKey::lpc_request(1);
        stack.admit(key, 1, owner(1), 9u64).unwrap();
        stack.select(key, 5u32).unwrap();
        assert_eq!(stack.select(key, 5), Err(SuspensionError::InvalidPhase));
        stack.cancel(key, 6).unwrap();
        let resume = stack.begin_resume(key).unwrap();
        assert!(resume.cancelled);
        assert_eq!(resume.completion, 6);
        assert_eq!(stack.begin_resume(key), Err(SuspensionError::InvalidPhase));
        assert_eq!(stack.complete_dispatch(key, owner(1)).unwrap().continuation, 9);
        assert!(stack.is_empty());
    }

    #[test]
    fn wrong_owner_cannot_complete_or_rearm() {
        let mut stack = ComponentSuspensionStack::new(2);
        let key = SuspensionKey::provider_wait(1);
        stack.admit(key, 1, owner(1), 1u64).unwrap();
        stack.select(key, 0u32).unwrap();
        stack.begin_resume(key).unwrap();
        assert_eq!(
            stack.complete_dispatch(key, owner(2)),
            Err(SuspensionError::InvalidIdentity)
        );
        assert_eq!(
            stack.rearm(key, SuspensionKey::lpc_request(2), 2, owner(2), 2),
            Err(SuspensionError::InvalidPhase)
        );
    }

    #[test]
    fn buried_cancellation_preserves_lifo_order() {
        let mut stack = ComponentSuspensionStack::new(3);
        let outer = SuspensionKey::provider_wait(1);
        let inner = SuspensionKey::lpc_request(2);
        stack.admit(outer, 1, owner(1), 1u64).unwrap();
        stack.admit(inner, 2, owner(2), 2u64).unwrap();
        stack.cancel(outer, 0xC000_0120u32).unwrap();
        assert_eq!(stack.top_resume(), None);
        stack.select(inner, 0).unwrap();
        stack.begin_resume(inner).unwrap();
        stack.complete_dispatch(inner, owner(2)).unwrap();
        assert!(stack.top_resume().unwrap().cancelled);
    }

    #[test]
    fn teardown_scope_is_generation_exact() {
        let mut stack = ComponentSuspensionStack::<u64, u32>::new(4);
        let key = SuspensionKey::provider_wait(1);
        stack.admit(key, 1, owner(1), 1).unwrap();
        assert!(!stack.contains_scope(SuspensionScope::Process {
            domain: 3,
            provider_generation: 7,
            client_pi: 2,
            client_generation: 10,
        }));
        assert_eq!(
            stack.next_cancellable_in_scope(SuspensionScope::Thread {
                domain: 3,
                provider_generation: 7,
                client_pi: 2,
                client_generation: 11,
                client_tid: 25,
                client_badge: 5,
            }),
            Some(key)
        );
    }

    #[test]
    fn overflow_and_rollback_preserve_owned_state() {
        let mut stack = ComponentSuspensionStack::<u64, u32>::new(1);
        let key = SuspensionKey::provider_wait(1);
        stack.admit(key, 1, owner(1), 77).unwrap();
        assert_eq!(
            stack.admit(SuspensionKey::lpc_request(2), 2, owner(2), 88),
            Err(SuspensionError::Overflow)
        );
        assert_eq!(stack.rollback_admission(key).unwrap(), 77);
        assert!(stack.is_empty());
    }

    #[test]
    fn invalid_identity_fails_closed() {
        let mut stack = ComponentSuspensionStack::<u64, u32>::new(2);
        assert_eq!(
            stack.admit(SuspensionKey::lpc_request(0), 1, owner(1), 1),
            Err(SuspensionError::InvalidIdentity)
        );
        assert_eq!(
            stack.admit(SuspensionKey::lpc_request(1), 0, owner(1), 1),
            Err(SuspensionError::InvalidIdentity)
        );
        let mut invalid = owner(1);
        invalid.provider_generation = 0;
        assert_eq!(
            stack.admit(SuspensionKey::lpc_request(1), 1, invalid, 1),
            Err(SuspensionError::InvalidIdentity)
        );
    }
}
