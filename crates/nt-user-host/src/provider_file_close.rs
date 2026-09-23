//! Retained provider continuation for a final file-handle close.
//!
//! This ledger owns the semantic close payload across cleanup and an uncertain reply. The
//! adapter must separately validate the live route, dispatch, and Reply capability before each
//! native effect. Neither an entered reply nor a dropped ticket grants permission to replay it.

use alloc::vec::Vec;
use nt_component_suspension::peer_registry::PeerRoute;
use nt_component_suspension::LaneDispatchIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderFileCloseIdentity {
    pub route: PeerRoute,
    pub dispatch: LaneDispatchIdentity,
    pub reply: u64,
    pub token: u64,
    pub file_id: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFileClosePhase {
    Reserved,
    WaitingCleanup,
    ReadyToReply,
    ReplyEntered,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderFileCloseError {
    InvalidIdentity,
    DuplicateFile,
    DuplicateDispatch,
    NoCapacity,
    StaleTicket,
    WrongPhase,
}

/// Slot and generation identify one reservation, even after its slot is recycled.
#[must_use = "retain this ticket until acknowledged completion or cancellation"]
#[derive(Debug, Eq, PartialEq)]
pub struct ProviderFileCloseTicket {
    slot: usize,
    generation: u64,
}

struct Entry<R> {
    identity: ProviderFileCloseIdentity,
    phase: ProviderFileClosePhase,
    owner: R,
}

struct Slot<R> {
    generation: u64,
    entry: Option<Entry<R>>,
}

/// Bounded semantic owner; capacity is fixed so admission cannot silently evict live work.
pub struct ProviderFileCloseLedger<R> {
    slots: Vec<Slot<R>>,
    capacity: usize,
}

impl<R> ProviderFileCloseLedger<R> {
    pub const fn new(capacity: usize) -> Self {
        Self {
            slots: Vec::new(),
            capacity,
        }
    }

    pub fn len(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.entry.is_some())
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Reserve before close or cleanup effects. Failure returns the unconsumed semantic owner.
    pub fn reserve(
        &mut self,
        identity: ProviderFileCloseIdentity,
        owner: R,
    ) -> Result<ProviderFileCloseTicket, (ProviderFileCloseError, R)> {
        if identity.reply == 0
            || identity.token == 0
            || identity.file_id == 0
            || identity.dispatch.lane() != identity.route.identity().lane
        {
            return Err((ProviderFileCloseError::InvalidIdentity, owner));
        }
        for slot in &self.slots {
            let Some(entry) = &slot.entry else { continue };
            if entry.identity.file_id == identity.file_id {
                return Err((ProviderFileCloseError::DuplicateFile, owner));
            }
            if entry.identity.route == identity.route
                && entry.identity.dispatch == identity.dispatch
                && entry.identity.reply == identity.reply
                && entry.identity.token == identity.token
            {
                return Err((ProviderFileCloseError::DuplicateDispatch, owner));
            }
        }
        if let Some((index, slot)) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.entry.is_none() && slot.generation != u64::MAX)
        {
            slot.generation += 1;
            slot.entry = Some(Entry {
                identity,
                phase: ProviderFileClosePhase::Reserved,
                owner,
            });
            return Ok(ProviderFileCloseTicket {
                slot: index,
                generation: slot.generation,
            });
        }
        if self.slots.len() >= self.capacity || self.slots.try_reserve(1).is_err() {
            return Err((ProviderFileCloseError::NoCapacity, owner));
        }
        self.slots.push(Slot {
            generation: 1,
            entry: Some(Entry {
                identity,
                phase: ProviderFileClosePhase::Reserved,
                owner,
            }),
        });
        Ok(ProviderFileCloseTicket {
            slot: self.slots.len() - 1,
            generation: 1,
        })
    }

    fn entry(&self, ticket: &ProviderFileCloseTicket) -> Result<&Entry<R>, ProviderFileCloseError> {
        self.slots
            .get(ticket.slot)
            .filter(|slot| slot.generation == ticket.generation)
            .and_then(|slot| slot.entry.as_ref())
            .ok_or(ProviderFileCloseError::StaleTicket)
    }

    fn entry_mut(
        &mut self,
        ticket: &ProviderFileCloseTicket,
    ) -> Result<&mut Entry<R>, ProviderFileCloseError> {
        self.slots
            .get_mut(ticket.slot)
            .filter(|slot| slot.generation == ticket.generation)
            .and_then(|slot| slot.entry.as_mut())
            .ok_or(ProviderFileCloseError::StaleTicket)
    }

    pub fn get(
        &self,
        ticket: &ProviderFileCloseTicket,
    ) -> Result<(ProviderFileCloseIdentity, ProviderFileClosePhase, &R), ProviderFileCloseError>
    {
        let entry = self.entry(ticket)?;
        Ok((entry.identity, entry.phase, &entry.owner))
    }

    pub fn ticket_for_file(&self, file_id: u64) -> Option<ProviderFileCloseTicket> {
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            (slot.entry.as_ref()?.identity.file_id == file_id).then_some(ProviderFileCloseTicket {
                slot: index,
                generation: slot.generation,
            })
        })
    }

    /// Walk a phase without consuming its owner. `after` must still identify a live row.
    pub fn next_in_phase(
        &self,
        phase: ProviderFileClosePhase,
        after: Option<&ProviderFileCloseTicket>,
    ) -> Result<Option<ProviderFileCloseTicket>, ProviderFileCloseError> {
        let start = match after {
            Some(ticket) => {
                self.entry(ticket)?;
                ticket.slot + 1
            }
            None => 0,
        };
        Ok(self
            .slots
            .iter()
            .enumerate()
            .skip(start)
            .find_map(|(index, slot)| {
                (slot.entry.as_ref()?.phase == phase).then_some(ProviderFileCloseTicket {
                    slot: index,
                    generation: slot.generation,
                })
            }))
    }

    fn transition(
        &mut self,
        ticket: &ProviderFileCloseTicket,
        from: ProviderFileClosePhase,
        to: ProviderFileClosePhase,
    ) -> Result<(), ProviderFileCloseError> {
        let entry = self.entry_mut(ticket)?;
        if entry.phase != from {
            return Err(ProviderFileCloseError::WrongPhase);
        }
        entry.phase = to;
        Ok(())
    }

    /// Admission occurs before any destructive provider effect. The reservation stays owned if
    /// the ticket is dropped after this point.
    pub fn admit(
        &mut self,
        ticket: &ProviderFileCloseTicket,
    ) -> Result<(), ProviderFileCloseError> {
        self.transition(
            ticket,
            ProviderFileClosePhase::Reserved,
            ProviderFileClosePhase::WaitingCleanup,
        )
    }

    pub fn cleanup_ready(
        &mut self,
        ticket: &ProviderFileCloseTicket,
    ) -> Result<(), ProviderFileCloseError> {
        self.transition(
            ticket,
            ProviderFileClosePhase::WaitingCleanup,
            ProviderFileClosePhase::ReadyToReply,
        )
    }

    /// Resolve a cleanup completion through the unique live file owner.
    pub fn cleanup_ready_for_file(
        &mut self,
        file_id: u64,
    ) -> Result<ProviderFileCloseTicket, ProviderFileCloseError> {
        let ticket = self
            .ticket_for_file(file_id)
            .ok_or(ProviderFileCloseError::StaleTicket)?;
        self.cleanup_ready(&ticket)?;
        Ok(ticket)
    }

    /// Record entry *before* invoking the reply mechanism. An ambiguous outcome remains entered
    /// and cannot be retried by this ledger.
    pub fn enter_reply(
        &mut self,
        ticket: &ProviderFileCloseTicket,
    ) -> Result<(), ProviderFileCloseError> {
        self.transition(
            ticket,
            ProviderFileClosePhase::ReadyToReply,
            ProviderFileClosePhase::ReplyEntered,
        )
    }

    fn retire(&mut self, ticket: &ProviderFileCloseTicket) -> Result<R, ProviderFileCloseError> {
        let slot = self
            .slots
            .get_mut(ticket.slot)
            .filter(|slot| slot.generation == ticket.generation)
            .ok_or(ProviderFileCloseError::StaleTicket)?;
        Ok(slot
            .entry
            .take()
            .ok_or(ProviderFileCloseError::StaleTicket)?
            .owner)
    }

    /// Abort only a reservation for which no native effects have begun.
    pub fn abort_reservation(
        &mut self,
        ticket: &ProviderFileCloseTicket,
    ) -> Result<R, ProviderFileCloseError> {
        if self.entry(ticket)?.phase != ProviderFileClosePhase::Reserved {
            return Err(ProviderFileCloseError::WrongPhase);
        }
        self.retire(ticket)
    }

    /// The caller must supply independent evidence that the exact reply was acknowledged.
    pub fn retire_acknowledged(
        &mut self,
        ticket: &ProviderFileCloseTicket,
    ) -> Result<R, ProviderFileCloseError> {
        if self.entry(ticket)?.phase != ProviderFileClosePhase::ReplyEntered {
            return Err(ProviderFileCloseError::WrongPhase);
        }
        self.retire(ticket)
    }

    /// The caller must supply independent evidence that exact retained work was cancelled. An
    /// uncertain reply or cleanup effect is not cancellation evidence.
    pub fn retire_cancelled(
        &mut self,
        ticket: &ProviderFileCloseTicket,
    ) -> Result<R, ProviderFileCloseError> {
        if self.entry(ticket)?.phase == ProviderFileClosePhase::Reserved {
            return Err(ProviderFileCloseError::WrongPhase);
        }
        self.retire(ticket)
    }
}

#[cfg(test)]
mod tests;
