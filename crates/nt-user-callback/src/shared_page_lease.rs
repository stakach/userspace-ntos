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

/// Identity known before lane admission or client-window effects. The native adapter
/// authenticates the request kind and retains the ingress Reply outside this copyable key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedPageProvisionalIdentity {
    pub dispatch_id: u64,
    pub client: SharedPageClientIdentity,
    pub request_ssn: u64,
    pub request_kind: u64,
}

impl SharedPageProvisionalIdentity {
    const fn is_valid(self) -> bool {
        self.dispatch_id != 0 && self.client.is_valid()
    }
}

/// Report the aggregate effect of pre-lane selection and grants on cancellation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SharedPageReservationEffect {
    NoEffect,
    Applied,
    Uncertain,
}

impl SharedPageLeaseIdentity {
    const fn is_valid(self) -> bool {
        // Request-class authentication belongs to the native adapter; hosted Ps uses SSN 0.
        self.dispatch.lane.is_valid() && self.dispatch.dispatch_id != 0
            && self.client.is_valid()
    }
}

/// Dispatch-owned publication in the shared page. Global SAS, GDI, SSDT, and callout cells are
/// independent publications and must not be rewound when a parked dispatch reacquires the page.
/// The native adapter must read a stable header, request/context cells, and callback payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SharedPageSnapshot {
    pub header: CallbackHeader,
    pub callback_payload: [u8; crate::CALLBACK_PAYLOAD_MAX],
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
            && self.publication.request()[0] == self.request_ssn
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
    /// A no-effect refusal retains it; uncertain or mismatched applied evidence quarantines it
    /// without a replay path.
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
            SharedPageRestoreEffect::Applied(_) => {
                frame.state = LeaseState::Uncertain(saved);
                Err(SharedPageLeaseError::WrongSnapshot)
            }
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

    /// Release a child only after the native pump certified terminal completion and retained
    /// its Reply/output effects. A yielded child must use `finish` with its full publication.
    pub fn finish_terminal(
        &mut self,
        identity: SharedPageLeaseIdentity,
    ) -> Result<(), SharedPageLeaseError> {
        let Some(frame) = self.frames[..self.len].last().and_then(Option::as_ref) else {
            return Err(SharedPageLeaseError::Empty);
        };
        if frame.identity != identity { return Err(SharedPageLeaseError::NotTop); }
        match frame.state {
            LeaseState::Live => {}
            LeaseState::Displaced(_) => return Err(SharedPageLeaseError::AlreadyDisplaced),
            LeaseState::Uncertain(_) => return Err(SharedPageLeaseError::Uncertain),
        }
        self.len -= 1;
        self.frames[self.len] = None;
        Ok(())
    }
}

impl<const N: usize> Default for SharedPageLeaseStack<N> {
    fn default() -> Self { Self::new() }
}

#[derive(Clone, Copy)]
enum PageAuthorityState {
    Reserved(SharedPageProvisionalIdentity),
    Active(SharedPageLeaseIdentity),
    Restoring(SharedPageLeaseIdentity, SharedPageSnapshot),
    Uncertain(SharedPageLeaseIdentity, Option<SharedPageSnapshot>),
    UncertainReservation(SharedPageProvisionalIdentity),
}

/// The singleton physical page has at most one writer. A parked dispatch retains its checked
/// publication until it reacquires the page; another dispatch may enter only after that park.
/// Native code must retain Replies and continuations separately before entering an effect.
pub struct SharedPageAuthority<const N: usize> {
    current: Option<PageAuthorityState>,
    parked: [Option<(SharedPageLeaseIdentity, SharedPageSnapshot)>; N],
}

impl<const N: usize> SharedPageAuthority<N> {
    pub const fn new() -> Self {
        Self { current: None, parked: [None; N] }
    }

    /// Reserve the physical page before selecting a client or granting its Ps bodies.
    pub fn reserve<R>(
        &mut self, identity: SharedPageProvisionalIdentity, reply: R,
    ) -> Result<R, (SharedPageLeaseError, R)> {
        if !identity.is_valid() { return Err((SharedPageLeaseError::InvalidIdentity, reply)); }
        if matches!(self.current, Some(PageAuthorityState::Uncertain(..)
            | PageAuthorityState::UncertainReservation(..))) {
            return Err((SharedPageLeaseError::Uncertain, reply));
        }
        if self.current.is_some() { return Err((SharedPageLeaseError::NotTop, reply)); }
        if self.parked.iter().flatten().any(|(owner, _)|
            owner.dispatch.dispatch_id == identity.dispatch_id
        ) {
            return Err((SharedPageLeaseError::Duplicate, reply));
        }
        self.current = Some(PageAuthorityState::Reserved(identity));
        Ok(reply)
    }

    /// Only a certified no-effect cancellation may release a pre-lane reservation.
    pub fn cancel_reservation(
        &mut self, identity: SharedPageProvisionalIdentity, effect: SharedPageReservationEffect,
    ) -> Result<(), SharedPageLeaseError> {
        match self.current {
            Some(PageAuthorityState::Reserved(owner)) if owner == identity => match effect {
                SharedPageReservationEffect::NoEffect => {
                    self.current = None;
                    Ok(())
                }
                SharedPageReservationEffect::Applied | SharedPageReservationEffect::Uncertain => {
                    self.current = Some(PageAuthorityState::UncertainReservation(identity));
                    Err(SharedPageLeaseError::Uncertain)
                }
            },
            Some(PageAuthorityState::Uncertain(..)
                | PageAuthorityState::UncertainReservation(..)) => Err(SharedPageLeaseError::Uncertain),
            Some(_) => Err(SharedPageLeaseError::NotTop),
            None => Err(SharedPageLeaseError::Empty),
        }
    }

    /// Bind the reservation to the exact admitted physical lane before first page write.
    pub fn promote(
        &mut self, identity: SharedPageProvisionalIdentity, admitted: SharedPageLeaseIdentity,
    ) -> Result<(), SharedPageLeaseError> {
        match self.current {
            Some(PageAuthorityState::Reserved(owner)) if owner == identity => {
                if !admitted.is_valid()
                    || admitted.dispatch.dispatch_id != identity.dispatch_id
                    || admitted.dispatch.ssn != identity.request_ssn
                    || admitted.client != identity.client
                {
                    return Err(SharedPageLeaseError::InvalidIdentity);
                }
                self.current = Some(PageAuthorityState::Active(admitted));
                Ok(())
            }
            Some(PageAuthorityState::Uncertain(..)
                | PageAuthorityState::UncertainReservation(..)) => Err(SharedPageLeaseError::Uncertain),
            Some(_) => Err(SharedPageLeaseError::NotTop),
            None => Err(SharedPageLeaseError::Empty),
        }
    }

    /// Admission returns the incoming non-Copy Reply unchanged on every refusal. A caller must
    /// retain it and defer rather than manufacture a completed NT status while the page is busy.
    pub fn enter<R>(
        &mut self, identity: SharedPageLeaseIdentity, reply: R,
    ) -> Result<R, (SharedPageLeaseError, R)> {
        if !identity.is_valid() { return Err((SharedPageLeaseError::InvalidIdentity, reply)); }
        if matches!(self.current, Some(PageAuthorityState::Uncertain(..)
            | PageAuthorityState::UncertainReservation(..))) {
            return Err((SharedPageLeaseError::Uncertain, reply));
        }
        if self.current.is_some() { return Err((SharedPageLeaseError::NotTop, reply)); }
        if self.parked.iter().flatten().any(|(owner, _)|
            owner.dispatch.dispatch_id == identity.dispatch.dispatch_id
        ) {
            return Err((SharedPageLeaseError::Duplicate, reply));
        }
        self.current = Some(PageAuthorityState::Active(identity));
        Ok(reply)
    }

    /// Transfer a stable, full publication into the exact parked owner before any foreign
    /// header or request write. On refusal the active owner remains in place.
    pub fn capture_and_park(
        &mut self, identity: SharedPageLeaseIdentity, snapshot: SharedPageSnapshot,
    ) -> Result<(), SharedPageLeaseError> {
        match self.current {
            Some(PageAuthorityState::Active(owner)) if owner == identity => {}
            Some(PageAuthorityState::Uncertain(..)
                | PageAuthorityState::UncertainReservation(..)) => return Err(SharedPageLeaseError::Uncertain),
            Some(_) => return Err(SharedPageLeaseError::NotTop),
            None => return Err(SharedPageLeaseError::Empty),
        }
        if !snapshot.matches(identity) { return Err(SharedPageLeaseError::WrongSnapshot); }
        let Some(slot) = self.parked.iter_mut().find(|slot| slot.is_none()) else {
            return Err(SharedPageLeaseError::Capacity);
        };
        *slot = Some((identity, snapshot));
        self.current = None;
        Ok(())
    }

    /// A capture whose native effect cannot be certified pins the active identity and blocks
    /// all new writers. This state has no retry or release path.
    pub fn quarantine_active(
        &mut self, identity: SharedPageLeaseIdentity,
    ) -> Result<(), SharedPageLeaseError> {
        match self.current {
            Some(PageAuthorityState::Active(owner)) if owner == identity => {
                self.current = Some(PageAuthorityState::Uncertain(identity, None));
                Ok(())
            }
            Some(PageAuthorityState::Uncertain(..)
                | PageAuthorityState::UncertainReservation(..)) => Err(SharedPageLeaseError::Uncertain),
            Some(_) => Err(SharedPageLeaseError::NotTop),
            None => Err(SharedPageLeaseError::Empty),
        }
    }

    /// Reacquisition moves the saved publication into an exclusive restoring state. No other
    /// dispatch may write while the native adapter reselects the client window and restores it.
    pub fn reacquire(
        &mut self, identity: SharedPageLeaseIdentity,
    ) -> Result<SharedPageSnapshot, SharedPageLeaseError> {
        if !identity.is_valid() { return Err(SharedPageLeaseError::InvalidIdentity); }
        if matches!(self.current, Some(PageAuthorityState::Uncertain(..)
            | PageAuthorityState::UncertainReservation(..))) {
            return Err(SharedPageLeaseError::Uncertain);
        }
        if self.current.is_some() { return Err(SharedPageLeaseError::NotTop); }
        let Some(slot) = self.parked.iter_mut().find(|slot|
            slot.as_ref().is_some_and(|(owner, _)| *owner == identity)
        ) else { return Err(SharedPageLeaseError::Empty) };
        let (_, snapshot) = slot.take().expect("exact parked entry was found");
        self.current = Some(PageAuthorityState::Restoring(identity, snapshot));
        Ok(snapshot)
    }

    /// Only an exact, physically applied restoration makes the parked owner active again.
    /// Uncertain native writes or mismatched applied evidence pin the saved publication and
    /// cannot be replayed.
    pub fn acknowledge_restore(
        &mut self, identity: SharedPageLeaseIdentity, effect: SharedPageRestoreEffect,
    ) -> Result<(), SharedPageLeaseError> {
        let saved = match self.current {
            Some(PageAuthorityState::Restoring(owner, saved)) if owner == identity => saved,
            Some(PageAuthorityState::Uncertain(..)
                | PageAuthorityState::UncertainReservation(..)) => return Err(SharedPageLeaseError::Uncertain),
            Some(_) => return Err(SharedPageLeaseError::NotDisplaced),
            None => return Err(SharedPageLeaseError::Empty),
        };
        match effect {
            SharedPageRestoreEffect::Applied(restored) if restored == saved
                && restored.matches(identity) => {
                self.current = Some(PageAuthorityState::Active(identity));
                Ok(())
            }
            SharedPageRestoreEffect::Applied(_) => {
                self.current = Some(PageAuthorityState::Uncertain(identity, Some(saved)));
                Err(SharedPageLeaseError::WrongSnapshot)
            }
            SharedPageRestoreEffect::NoEffect => Err(SharedPageLeaseError::RestoreNotApplied),
            SharedPageRestoreEffect::Uncertain => {
                self.current = Some(PageAuthorityState::Uncertain(identity, Some(saved)));
                Err(SharedPageLeaseError::Uncertain)
            }
        }
    }

    /// The native owner calls this only after terminal completion and output/Reply retention.
    pub fn finish_active(
        &mut self, identity: SharedPageLeaseIdentity,
    ) -> Result<(), SharedPageLeaseError> {
        match self.current {
            Some(PageAuthorityState::Active(owner)) if owner == identity => {
                self.current = None;
                Ok(())
            }
            Some(PageAuthorityState::Uncertain(..)
                | PageAuthorityState::UncertainReservation(..)) => Err(SharedPageLeaseError::Uncertain),
            Some(_) => Err(SharedPageLeaseError::NotTop),
            None => Err(SharedPageLeaseError::Empty),
        }
    }
}

impl<const N: usize> Default for SharedPageAuthority<N> {
    fn default() -> Self { Self::new() }
}
