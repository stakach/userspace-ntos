//! A selected Receive child's image fault whose routed source page needs a provider READ.
//!
//! The held parent stays parked and the child stays the selected Receive child throughout. An
//! owned page-in row holds the child's Reply from admission to its one send, so a Pending READ
//! is a retained continuation, never an error. Until the exact settlement the root admits only
//! notifications, which drive storage completion without other ingress, provider resume or
//! entry into the held provider. A held Receive parent has no cancellation settlement, so a
//! failed or uncertain page-in retains every owner and stops the root.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveChildRootEvent {
    /// A timer or IRQ notification: no Call and no Reply.
    Notification,
    /// A delivery of the selected child's own Call.
    SelectedChild,
    /// Any other hosted delivery.
    Unrelated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveChildRootAction {
    /// Drive storage completion and the exact page-in row only.
    ServicePageIn,
    /// The page-in row owns the child's Reply; another delivery of its Call is not authority.
    RefuseIdentity,
    /// Return the unexecuted Call and Reply to its own ingress row.
    DeferUnrelated,
    /// The child Reply, Call and held parent stay retained: the root waits for its next event
    /// (the retained-settlement wait), never exits and never continues ordinary work.
    StopRetained,
    /// The child's Reply was sent and the child delivered again (it ran on another core before
    /// the root acknowledged). Settle the page-in, then classify the delivery afresh.
    SettleFirst,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveChildPageInError {
    Unaligned,
    WrongPhase,
    Retained,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    Reading,
    Mapped,
    ReplyEntered,
    Retained(u32),
}

/// Native authenticates the child, its admission and the held parent before `admit`.
#[must_use = "retain the turn with the child Reply until its exact settlement"]
#[derive(Debug)]
pub struct ReceiveChildPageIn<C, K, P> {
    child: C,
    admission: K,
    parent: P,
    page: u64,
    phase: Phase,
}

/// One settlement receipt. The owner is consumed, so a settled turn cannot reply again.
#[derive(Debug)]
pub struct ReceiveChildPageInSettled<C, K, P> {
    child: C,
    admission: K,
    parent: P,
    page: u64,
}

impl<C: Copy, K: Copy, P: Copy> ReceiveChildPageIn<C, K, P> {
    pub fn admit(child: C, admission: K, parent: P, page: u64) -> Result<Self, ReceiveChildPageInError> {
        if page & 0xfff != 0 {
            return Err(ReceiveChildPageInError::Unaligned);
        }
        Ok(Self { child, admission, parent, page, phase: Phase::Reading })
    }

    pub fn child(&self) -> C { self.child }
    pub fn admission(&self) -> K { self.admission }
    pub fn parent(&self) -> P { self.parent }
    pub fn page(&self) -> u64 { self.page }

    pub fn retained_status(&self) -> Option<u32> {
        match self.phase {
            Phase::Retained(status) => Some(status),
            _ => None,
        }
    }

    pub fn root_action(&self, event: ReceiveChildRootEvent) -> ReceiveChildRootAction {
        if self.retained_status().is_some() {
            return ReceiveChildRootAction::StopRetained;
        }
        match event {
            ReceiveChildRootEvent::Notification => ReceiveChildRootAction::ServicePageIn,
            ReceiveChildRootEvent::SelectedChild if self.phase == Phase::ReplyEntered => {
                ReceiveChildRootAction::SettleFirst
            }
            ReceiveChildRootEvent::SelectedChild => ReceiveChildRootAction::RefuseIdentity,
            ReceiveChildRootEvent::Unrelated => ReceiveChildRootAction::DeferUnrelated,
        }
    }

    fn advance(&mut self, from: Phase, to: Phase) -> Result<(), ReceiveChildPageInError> {
        match self.phase {
            Phase::Retained(_) => Err(ReceiveChildPageInError::Retained),
            phase if phase == from => {
                self.phase = to;
                Ok(())
            }
            _ => Err(ReceiveChildPageInError::WrongPhase),
        }
    }

    /// The exact page is installed after terminal, copy and strict acknowledgement.
    pub fn page_mapped(&mut self) -> Result<(), ReceiveChildPageInError> {
        self.advance(Phase::Reading, Phase::Mapped)
    }

    /// Recorded before the one child Reply send; it is never entered again.
    pub fn enter_reply(&mut self) -> Result<(), ReceiveChildPageInError> {
        self.advance(Phase::Mapped, Phase::ReplyEntered)
    }

    /// A failed, cancelled or uncertain page-in. The first status is retained.
    pub fn retain(&mut self, status: u32) {
        if self.retained_status().is_none() {
            self.phase = Phase::Retained(status);
        }
    }

    /// The entered Reply has a positive acknowledgement and checked Free.
    pub fn acknowledge(self) -> Result<ReceiveChildPageInSettled<C, K, P>, (ReceiveChildPageInError, Self)> {
        match self.phase {
            Phase::ReplyEntered => Ok(ReceiveChildPageInSettled {
                child: self.child,
                admission: self.admission,
                parent: self.parent,
                page: self.page,
            }),
            Phase::Retained(_) => Err((ReceiveChildPageInError::Retained, self)),
            _ => Err((ReceiveChildPageInError::WrongPhase, self)),
        }
    }
}

impl<C: Copy, K: Copy, P: Copy> ReceiveChildPageInSettled<C, K, P> {
    pub fn child(&self) -> C { self.child }
    pub fn admission(&self) -> K { self.admission }
    pub fn parent(&self) -> P { self.parent }
    pub fn page(&self) -> u64 { self.page }
}

#[cfg(test)]
#[path = "receive_child_pagein_tests.rs"]
mod tests;
