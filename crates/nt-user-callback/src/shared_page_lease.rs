//! Temporary ownership of one physical win32k shared page while nested pumps execute.
//!
//! The active dispatch identity is the authority. Before a nested dispatch overwrites the page,
//! its caller transfers the complete validated publication into the top lease. The lease is
//! returned once to the existing durable pending owner; it is not an independent identity cache.

use crate::{CallbackHeader, DispatchContext, SharedCallbackPublication};

/// Exact client identity attached to an active win32k dispatch and its shared request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedPageClientIdentity {
    pub pi: u32,
    pub pid: u64,
    pub generation: u64,
    pub tid: u64,
    pub badge: u64,
    pub tcb: u64,
}

impl SharedPageClientIdentity {
    const fn is_executive(self) -> bool {
        self.pid == 0 && self.generation == 0 && self.tid == 0
            && self.badge == 0 && self.tcb == 0
    }

    const fn is_valid(self) -> bool {
        self.is_executive()
            || (self.pid != 0 && self.generation != 0 && self.tid != 0
                && self.badge != 0 && self.tcb > 1)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedPageLeaseIdentity {
    pub dispatch: DispatchContext,
    pub client: SharedPageClientIdentity,
}

impl SharedPageLeaseIdentity {
    const fn is_valid(self) -> bool {
        self.dispatch.lane.is_valid() && self.dispatch.dispatch_id != 0
            && (self.dispatch.ssn != 0 || self.client.is_executive())
            && self.client.is_valid()
    }
}

/// A complete shared-page capture, including request ownership independent of the header.
/// The native adapter must read a stable header both before and after the request/context cells.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedPageSnapshot {
    pub header: CallbackHeader,
    pub publication: SharedCallbackPublication,
    pub request_owner: SharedPageClientIdentity,
    pub request_ssn: u64,
}

impl SharedPageSnapshot {
    pub fn matches(self, identity: SharedPageLeaseIdentity) -> bool {
        self.header.matches_dispatch_identity(
            identity.dispatch.dispatch_id,
            identity.client.pi,
            identity.client.tid,
            identity.client.badge,
        ) && self.request_owner == identity.client
            && self.request_ssn == identity.dispatch.ssn
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedPageLeaseError {
    InvalidIdentity,
    Duplicate,
    Capacity,
    Empty,
    NotTop,
    WrongSnapshot,
    AlreadyDisplaced,
    MissingSnapshot,
    UnexpectedCurrent,
    NotDisplaced,
    RestoreNotApplied,
    Uncertain,
}

/// Native restore is acknowledged only after the exact shared-page write completed. An
/// uncertain effect pins the old publication; it does not authorize retry or release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedPageRestoreEffect {
    Applied(SharedPageSnapshot),
    NoEffect,
    Uncertain,
}

#[derive(Clone, Copy)]
struct Lease {
    identity: SharedPageLeaseIdentity,
    state: LeaseState,
}

#[derive(Clone, Copy)]
enum LeaseState {
    Live,
    Displaced(SharedPageSnapshot),
    Uncertain(SharedPageSnapshot),
}

/// Fixed capacity follows the physical nested pump stack; no allocation occurs on overwrite.
pub struct SharedPageLeaseStack<const N: usize> {
    frames: [Option<Lease>; N],
    len: usize,
}

impl<const N: usize> SharedPageLeaseStack<N> {
    pub const fn new() -> Self {
        Self { frames: [None; N], len: 0 }
    }

    pub const fn len(&self) -> usize { self.len }

    /// Enter before a pump can issue nested win32k dispatches.
    pub fn begin(&mut self, identity: SharedPageLeaseIdentity) -> Result<(), SharedPageLeaseError> {
        if !identity.is_valid() { return Err(SharedPageLeaseError::InvalidIdentity); }
        if self.frames[..self.len].last().and_then(Option::as_ref)
            .is_some_and(|frame| matches!(frame.state, LeaseState::Uncertain(_)))
        {
            return Err(SharedPageLeaseError::Uncertain);
        }
        if self.frames[..self.len].iter().flatten().any(|frame|
            frame.identity.dispatch.dispatch_id == identity.dispatch.dispatch_id
        ) {
            return Err(SharedPageLeaseError::Duplicate);
        }
        if self.len == N { return Err(SharedPageLeaseError::Capacity); }
        self.frames[self.len] = Some(Lease { identity, state: LeaseState::Live });
        self.len += 1;
        Ok(())
    }

    /// Transfer a stable full publication before another dispatch's first shared-page write.
    pub fn displace(
        &mut self,
        identity: SharedPageLeaseIdentity,
        snapshot: SharedPageSnapshot,
    ) -> Result<(), SharedPageLeaseError> {
        let Some(frame) = self.frames[..self.len].last_mut().and_then(Option::as_mut) else {
            return Err(SharedPageLeaseError::Empty);
        };
        if frame.identity != identity { return Err(SharedPageLeaseError::NotTop); }
        match frame.state {
            LeaseState::Live => {}
            LeaseState::Displaced(_) => return Err(SharedPageLeaseError::AlreadyDisplaced),
            LeaseState::Uncertain(_) => return Err(SharedPageLeaseError::Uncertain),
        }
        if !snapshot.matches(identity) { return Err(SharedPageLeaseError::WrongSnapshot); }
        frame.state = LeaseState::Displaced(snapshot);
        Ok(())
    }

    /// Clear a displaced lease only after the exact old publication was physically restored.
    /// A refusal retains it; an uncertain restore quarantines it without a replay path.
    pub fn acknowledge_restore(
        &mut self,
        identity: SharedPageLeaseIdentity,
        effect: SharedPageRestoreEffect,
    ) -> Result<(), SharedPageLeaseError> {
        let Some(frame) = self.frames[..self.len].last_mut().and_then(Option::as_mut) else {
            return Err(SharedPageLeaseError::Empty);
        };
        if frame.identity != identity { return Err(SharedPageLeaseError::NotTop); }
        let saved = match frame.state {
            LeaseState::Live => return Err(SharedPageLeaseError::NotDisplaced),
            LeaseState::Displaced(saved) => saved,
            LeaseState::Uncertain(_) => return Err(SharedPageLeaseError::Uncertain),
        };
        match effect {
            SharedPageRestoreEffect::Applied(restored) if restored == saved
                && restored.matches(identity) => {
                frame.state = LeaseState::Live;
                Ok(())
            }
            SharedPageRestoreEffect::Applied(_) => Err(SharedPageLeaseError::WrongSnapshot),
            SharedPageRestoreEffect::NoEffect => Err(SharedPageLeaseError::RestoreNotApplied),
            SharedPageRestoreEffect::Uncertain => {
                frame.state = LeaseState::Uncertain(saved);
                Err(SharedPageLeaseError::Uncertain)
            }
        }
    }

    /// Transfer once to the existing pending owner. Any refusal leaves the top lease intact.
    pub fn finish(
        &mut self,
        identity: SharedPageLeaseIdentity,
        current: Option<SharedPageSnapshot>,
    ) -> Result<SharedPageSnapshot, SharedPageLeaseError> {
        let Some(frame) = self.frames[..self.len].last().and_then(Option::as_ref) else {
            return Err(SharedPageLeaseError::Empty);
        };
        if frame.identity != identity { return Err(SharedPageLeaseError::NotTop); }
        let displaced = match frame.state {
            LeaseState::Live => None,
            LeaseState::Displaced(saved) => Some(saved),
            LeaseState::Uncertain(_) => return Err(SharedPageLeaseError::Uncertain),
        };
        let snapshot = match (displaced, current) {
            (Some(_), Some(_)) => return Err(SharedPageLeaseError::UnexpectedCurrent),
            (Some(snapshot), None) => snapshot,
            (None, Some(snapshot)) => snapshot,
            (None, None) => return Err(SharedPageLeaseError::MissingSnapshot),
        };
        if !snapshot.matches(identity) { return Err(SharedPageLeaseError::WrongSnapshot); }
        self.len -= 1;
        self.frames[self.len] = None;
        Ok(snapshot)
    }
}

impl<const N: usize> Default for SharedPageLeaseStack<N> {
    fn default() -> Self { Self::new() }
}
