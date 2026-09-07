//! Retained broker ownership of an existing key target, independent of native handle numbering.

use core::sync::atomic::{AtomicU64, Ordering};

static LAST_MANAGER_NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerKeyPhase {
    Reserved,
    BoundUnpublished,
    Active,
    ClosingInflight,
    ClosingRetryable,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerKeyOwnerError {
    WrongManager,
    WrongOwner,
    StaleTicket,
    InvalidPhase,
    Exhausted,
}

/// A bookkeeping domain, not a handle namespace or registry access authority. Moving it preserves
/// ownership; a newly constructed domain cannot operate on an earlier domain's owners or tickets.
pub struct BrokerKeyOwners {
    nonce: u64,
    last_owner: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Identity {
    manager: u64,
    owner: u64,
}

/// The native broker stores this inline in its already reserved handle row before CM open. No
/// transition allocates. Dropping an owner does not acknowledge or release its backend target.
///
/// ```compile_fail
/// use nt_config_client::BrokerKeyOwner;
/// fn duplicate(owner: BrokerKeyOwner<u64>) { let _ = owner.clone(); }
/// ```
#[must_use]
pub struct BrokerKeyOwner<T, C = ()> {
    identity: Identity,
    phase: BrokerKeyPhase,
    epoch: u64,
    publication_pending: bool,
    target: Option<T>,
    metadata: C,
}

impl<T, C> BrokerKeyOwner<T, C> {
    pub const fn phase(&self) -> BrokerKeyPhase {
        self.phase
    }
}

struct Ticket {
    identity: Identity,
    epoch: u64,
    live: bool,
}

/// One exact publication attempt. Dropping it does not publish or cancel the retained target.
///
/// ```compile_fail
/// use nt_config_client::BrokerKeyPublicationTicket;
/// fn duplicate(ticket: BrokerKeyPublicationTicket) { let _ = ticket.clone(); }
/// ```
#[must_use]
pub struct BrokerKeyPublicationTicket(Ticket);

/// One exact close attempt. A dropped in-flight ticket leaves ownership retained and nonqueryable;
/// this module deliberately provides no authority to recover a potentially still-running attempt.
///
/// ```compile_fail
/// use nt_config_client::BrokerKeyCloseTicket;
/// fn duplicate(ticket: BrokerKeyCloseTicket) { let _ = ticket.clone(); }
/// ```
#[must_use]
pub struct BrokerKeyCloseTicket(Ticket);

impl Default for BrokerKeyOwners {
    fn default() -> Self {
        Self::new()
    }
}

impl BrokerKeyOwners {
    pub const fn new() -> Self {
        Self {
            nonce: 0,
            last_owner: 0,
        }
    }

    /// Reserve the bookkeeping owner before making any backend call which can acquire a target.
    /// The caller must first reserve its native row's storage; this operation allocates no memory.
    pub fn reserve<T>(&mut self) -> Result<BrokerKeyOwner<T>, BrokerKeyOwnerError> {
        self.reserve_with_metadata(())
    }

    pub fn reserve_with_metadata<T, C>(
        &mut self,
        metadata: C,
    ) -> Result<BrokerKeyOwner<T, C>, BrokerKeyOwnerError> {
        self.reserve_with_counter(metadata, &LAST_MANAGER_NONCE)
    }

    fn reserve_with_counter<T, C>(
        &mut self,
        metadata: C,
        counter: &AtomicU64,
    ) -> Result<BrokerKeyOwner<T, C>, BrokerKeyOwnerError> {
        let owner = self
            .last_owner
            .checked_add(1)
            .ok_or(BrokerKeyOwnerError::Exhausted)?;
        let manager = if self.nonce == 0 {
            counter
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |last| {
                    last.checked_add(1)
                })
                .map_err(|_| BrokerKeyOwnerError::Exhausted)?
                + 1
        } else {
            self.nonce
        };
        self.nonce = manager;
        self.last_owner = owner;
        Ok(BrokerKeyOwner {
            identity: Identity { manager, owner },
            phase: BrokerKeyPhase::Reserved,
            epoch: 0,
            publication_pending: false,
            target: None,
            metadata,
        })
    }

    fn validate<T, C>(&self, owner: &BrokerKeyOwner<T, C>) -> Result<(), BrokerKeyOwnerError> {
        if self.nonce == 0 || owner.identity.manager != self.nonce {
            return Err(BrokerKeyOwnerError::WrongManager);
        }
        Ok(())
    }

    fn validate_ticket<T, C>(
        &self,
        owner: &BrokerKeyOwner<T, C>,
        ticket: &Ticket,
    ) -> Result<(), BrokerKeyOwnerError> {
        self.validate(owner)?;
        if ticket.identity.manager != self.nonce {
            return Err(BrokerKeyOwnerError::WrongManager);
        }
        if ticket.identity != owner.identity {
            return Err(BrokerKeyOwnerError::WrongOwner);
        }
        if !ticket.live || ticket.epoch != owner.epoch {
            return Err(BrokerKeyOwnerError::StaleTicket);
        }
        Ok(())
    }

    /// Failed attachment returns the acquired target intact, never discarding its cleanup duty.
    pub fn attach<T, C>(
        &self,
        owner: &mut BrokerKeyOwner<T, C>,
        target: T,
    ) -> Result<(), (BrokerKeyOwnerError, T)> {
        if let Err(error) = self.validate(owner) {
            return Err((error, target));
        }
        if owner.phase != BrokerKeyPhase::Reserved || owner.target.is_some() {
            return Err((BrokerKeyOwnerError::InvalidPhase, target));
        }
        owner.target = Some(target);
        owner.phase = BrokerKeyPhase::BoundUnpublished;
        Ok(())
    }

    /// Only an open which acquired no backend target may cancel its empty reservation.
    pub fn cancel_reservation<T, C>(
        &self,
        owner: &mut BrokerKeyOwner<T, C>,
    ) -> Result<(), BrokerKeyOwnerError> {
        self.validate(owner)?;
        if owner.phase != BrokerKeyPhase::Reserved || owner.target.is_some() {
            return Err(BrokerKeyOwnerError::InvalidPhase);
        }
        owner.phase = BrokerKeyPhase::Closed;
        Ok(())
    }

    pub fn active_target<'a, T, C>(
        &self,
        owner: &'a BrokerKeyOwner<T, C>,
    ) -> Result<&'a T, BrokerKeyOwnerError> {
        self.validate(owner)?;
        if owner.phase != BrokerKeyPhase::Active {
            return Err(BrokerKeyOwnerError::InvalidPhase);
        }
        owner
            .target
            .as_ref()
            .ok_or(BrokerKeyOwnerError::InvalidPhase)
    }

    pub fn begin_publication<T, C>(
        &self,
        owner: &mut BrokerKeyOwner<T, C>,
    ) -> Result<BrokerKeyPublicationTicket, BrokerKeyOwnerError> {
        self.validate(owner)?;
        if owner.phase != BrokerKeyPhase::BoundUnpublished
            || owner.publication_pending
            || owner.target.is_none()
        {
            return Err(BrokerKeyOwnerError::InvalidPhase);
        }
        let epoch = owner
            .epoch
            .checked_add(1)
            .ok_or(BrokerKeyOwnerError::Exhausted)?;
        owner.epoch = epoch;
        owner.publication_pending = true;
        Ok(BrokerKeyPublicationTicket(Ticket {
            identity: owner.identity,
            epoch,
            live: true,
        }))
    }

    fn validate_publication<T, C>(
        &self,
        owner: &BrokerKeyOwner<T, C>,
        ticket: &BrokerKeyPublicationTicket,
    ) -> Result<(), BrokerKeyOwnerError> {
        self.validate_ticket(owner, &ticket.0)?;
        if owner.phase != BrokerKeyPhase::BoundUnpublished
            || !owner.publication_pending
            || owner.target.is_none()
        {
            return Err(BrokerKeyOwnerError::InvalidPhase);
        }
        Ok(())
    }

    pub fn publish<T, C>(
        &self,
        owner: &mut BrokerKeyOwner<T, C>,
        ticket: &mut BrokerKeyPublicationTicket,
    ) -> Result<(), BrokerKeyOwnerError> {
        self.validate_publication(owner, ticket)?;
        owner.phase = BrokerKeyPhase::Active;
        owner.publication_pending = false;
        ticket.0.live = false;
        Ok(())
    }

    pub fn cancel_publication<T, C>(
        &self,
        owner: &mut BrokerKeyOwner<T, C>,
        ticket: &mut BrokerKeyPublicationTicket,
    ) -> Result<(), BrokerKeyOwnerError> {
        self.validate_publication(owner, ticket)?;
        owner.publication_pending = false;
        ticket.0.live = false;
        Ok(())
    }

    pub fn begin_close<T, C>(
        &self,
        owner: &mut BrokerKeyOwner<T, C>,
    ) -> Result<BrokerKeyCloseTicket, BrokerKeyOwnerError> {
        self.validate(owner)?;
        if !matches!(
            owner.phase,
            BrokerKeyPhase::BoundUnpublished
                | BrokerKeyPhase::Active
                | BrokerKeyPhase::ClosingRetryable
        ) || owner.publication_pending
            || owner.target.is_none()
        {
            return Err(BrokerKeyOwnerError::InvalidPhase);
        }
        let epoch = owner
            .epoch
            .checked_add(1)
            .ok_or(BrokerKeyOwnerError::Exhausted)?;
        owner.epoch = epoch;
        owner.phase = BrokerKeyPhase::ClosingInflight;
        Ok(BrokerKeyCloseTicket(Ticket {
            identity: owner.identity,
            epoch,
            live: true,
        }))
    }

    fn validate_close<T, C>(
        &self,
        owner: &BrokerKeyOwner<T, C>,
        ticket: &BrokerKeyCloseTicket,
    ) -> Result<(), BrokerKeyOwnerError> {
        self.validate_ticket(owner, &ticket.0)?;
        if owner.phase != BrokerKeyPhase::ClosingInflight || owner.target.is_none() {
            return Err(BrokerKeyOwnerError::InvalidPhase);
        }
        Ok(())
    }

    pub fn close_target<'a, T, C>(
        &self,
        owner: &'a BrokerKeyOwner<T, C>,
        ticket: &BrokerKeyCloseTicket,
    ) -> Result<&'a T, BrokerKeyOwnerError> {
        self.validate_close(owner, ticket)?;
        owner
            .target
            .as_ref()
            .ok_or(BrokerKeyOwnerError::InvalidPhase)
    }

    pub fn close_metadata<'a, T, C>(
        &self,
        owner: &'a BrokerKeyOwner<T, C>,
        ticket: &BrokerKeyCloseTicket,
    ) -> Result<&'a C, BrokerKeyOwnerError> {
        self.validate_close(owner, ticket)?;
        Ok(&owner.metadata)
    }

    /// Persist a validated backend receipt before issuing its ACK. Cleanup metadata is separate
    /// from the immutable target, so recording a receipt cannot substitute or release its lease.
    /// No borrow may span backend IPC.
    ///
    /// ```compile_fail
    /// use nt_config_client::BrokerKeyOwners;
    /// let mut owners = BrokerKeyOwners::new();
    /// let mut owner = owners.reserve_with_metadata::<u64, _>(None::<u64>).unwrap();
    /// owners.attach(&mut owner, 7).unwrap();
    /// let ticket = owners.begin_close(&mut owner).unwrap();
    /// *owners.close_target(&owner, &ticket).unwrap() = 8;
    /// ```
    pub fn close_metadata_mut<'a, T, C>(
        &self,
        owner: &'a mut BrokerKeyOwner<T, C>,
        ticket: &BrokerKeyCloseTicket,
    ) -> Result<&'a mut C, BrokerKeyOwnerError> {
        self.validate_close(owner, ticket)?;
        Ok(&mut owner.metadata)
    }

    /// The exact attempt has returned without a validated final ACK. Its target and any durable
    /// receipt remain retained. The next attempt retries ACK if a receipt was already acquired.
    pub fn close_failed<T, C>(
        &self,
        owner: &mut BrokerKeyOwner<T, C>,
        ticket: &mut BrokerKeyCloseTicket,
    ) -> Result<(), BrokerKeyOwnerError> {
        self.validate_close(owner, ticket)?;
        owner.phase = BrokerKeyPhase::ClosingRetryable;
        ticket.0.live = false;
        Ok(())
    }

    /// Commit only after the adapter validates the backend's exact close-receipt acknowledgment.
    /// An error status, including INVALID_HANDLE, is never an acknowledgment. The returned target
    /// is retired bookkeeping, not a live backend lease; no earlier operation removes it.
    pub fn finish_close<T, C>(
        &self,
        owner: &mut BrokerKeyOwner<T, C>,
        ticket: &mut BrokerKeyCloseTicket,
    ) -> Result<T, BrokerKeyOwnerError> {
        self.validate_close(owner, ticket)?;
        let target = owner
            .target
            .take()
            .ok_or(BrokerKeyOwnerError::InvalidPhase)?;
        owner.phase = BrokerKeyPhase::Closed;
        ticket.0.live = false;
        Ok(target)
    }
}

#[cfg(test)]
mod tests;
