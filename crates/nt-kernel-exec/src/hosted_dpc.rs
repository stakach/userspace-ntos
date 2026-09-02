//! Generation-fenced ownership for hosted `KDPC` projections.
//!
//! Driver memory contains the Windows-visible `KDPC`, but root owns inserted state and dispatch
//! order. A projection may be reinitialized only while idle, and every reuse receives a fresh
//! generation so an old queue or completion token cannot target the replacement object.

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedDpcOwner {
    pub domain_id: u64,
    pub domain_cookie: u64,
}

impl HostedDpcOwner {
    pub const fn new(domain_id: u64, domain_cookie: u64) -> Option<Self> {
        if domain_id == 0 || domain_cookie == 0 {
            None
        } else {
            Some(Self {
                domain_id,
                domain_cookie,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedDpcIdentity {
    pub owner: HostedDpcOwner,
    pub dpc_token: u64,
    pub generation: u64,
}

impl HostedDpcIdentity {
    pub const fn new(owner: HostedDpcOwner, dpc_token: u64, generation: u64) -> Option<Self> {
        if dpc_token == 0 || generation == 0 {
            None
        } else {
            Some(Self {
                owner,
                dpc_token,
                generation,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedDpcActivation {
    pub identity: HostedDpcIdentity,
    pub sequence: u64,
    pub routine: u64,
    pub deferred_context: u64,
    pub system_argument1: u64,
    pub system_argument2: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedDpcQueueResult {
    Queued(HostedDpcIdentity),
    AlreadyQueued(HostedDpcIdentity),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedDpcSnapshot {
    pub identity: HostedDpcIdentity,
    pub routine: u64,
    pub deferred_context: u64,
    pub queued: bool,
    pub in_flight: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedDpcError {
    InvalidIdentity,
    NotRegistered,
    Busy,
    StaleActivation,
    GenerationExhausted,
    SequenceExhausted,
    OutOfMemory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HostedDpcQueued {
    sequence: u64,
    argument1: u64,
    argument2: u64,
}

struct HostedDpcRecord {
    identity: HostedDpcIdentity,
    live: bool,
    routine: u64,
    deferred_context: u64,
    queued: Option<HostedDpcQueued>,
    in_flight: Option<u64>,
}

pub struct HostedDpcTable {
    records: Vec<HostedDpcRecord>,
    next_generation: u64,
    next_sequence: u64,
}

impl Default for HostedDpcTable {
    fn default() -> Self {
        Self::new()
    }
}

impl HostedDpcTable {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            next_generation: 1,
            next_sequence: 1,
        }
    }

    fn identity_valid(identity: HostedDpcIdentity) -> bool {
        HostedDpcOwner::new(identity.owner.domain_id, identity.owner.domain_cookie)
            == Some(identity.owner)
            && HostedDpcIdentity::new(identity.owner, identity.dpc_token, identity.generation)
                == Some(identity)
    }

    fn record_index(&self, identity: HostedDpcIdentity) -> Result<usize, HostedDpcError> {
        if !Self::identity_valid(identity) {
            return Err(HostedDpcError::InvalidIdentity);
        }
        self.records
            .iter()
            .position(|record| record.live && record.identity == identity)
            .ok_or(HostedDpcError::NotRegistered)
    }

    fn allocate_generation(&mut self) -> Result<u64, HostedDpcError> {
        let generation = self.next_generation;
        self.next_generation = generation
            .checked_add(1)
            .ok_or(HostedDpcError::GenerationExhausted)?;
        Ok(generation)
    }

    pub fn register(
        &mut self,
        owner: HostedDpcOwner,
        dpc_token: u64,
        routine: u64,
        deferred_context: u64,
    ) -> Result<HostedDpcIdentity, HostedDpcError> {
        if HostedDpcOwner::new(owner.domain_id, owner.domain_cookie) != Some(owner)
            || dpc_token == 0
            || routine == 0
        {
            return Err(HostedDpcError::InvalidIdentity);
        }
        if let Some(index) = self.records.iter().position(|record| {
            record.live && record.identity.owner == owner && record.identity.dpc_token == dpc_token
        }) {
            let record = &self.records[index];
            if record.routine == routine && record.deferred_context == deferred_context {
                return Ok(record.identity);
            }
            if record.queued.is_some() || record.in_flight.is_some() {
                return Err(HostedDpcError::Busy);
            }
            let generation = self.allocate_generation()?;
            let identity = HostedDpcIdentity::new(owner, dpc_token, generation)
                .ok_or(HostedDpcError::InvalidIdentity)?;
            let record = &mut self.records[index];
            record.identity = identity;
            record.routine = routine;
            record.deferred_context = deferred_context;
            return Ok(identity);
        }

        let generation = self.allocate_generation()?;
        let identity = HostedDpcIdentity::new(owner, dpc_token, generation)
            .ok_or(HostedDpcError::InvalidIdentity)?;
        let replacement = HostedDpcRecord {
            identity,
            live: true,
            routine,
            deferred_context,
            queued: None,
            in_flight: None,
        };
        if let Some(record) = self.records.iter_mut().find(|record| !record.live) {
            *record = replacement;
        } else {
            self.records
                .try_reserve(1)
                .map_err(|_| HostedDpcError::OutOfMemory)?;
            self.records.push(replacement);
        }
        Ok(identity)
    }

    pub fn queue(
        &mut self,
        identity: HostedDpcIdentity,
        argument1: u64,
        argument2: u64,
    ) -> Result<HostedDpcQueueResult, HostedDpcError> {
        let index = self.record_index(identity)?;
        if self.records[index].queued.is_some() {
            return Ok(HostedDpcQueueResult::AlreadyQueued(identity));
        }
        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(HostedDpcError::SequenceExhausted)?;
        self.records[index].queued = Some(HostedDpcQueued {
            sequence,
            argument1,
            argument2,
        });
        self.next_sequence = next_sequence;
        Ok(HostedDpcQueueResult::Queued(identity))
    }

    pub fn register_and_queue(
        &mut self,
        owner: HostedDpcOwner,
        dpc_token: u64,
        routine: u64,
        deferred_context: u64,
        argument1: u64,
        argument2: u64,
    ) -> Result<HostedDpcQueueResult, HostedDpcError> {
        let identity = self.register(owner, dpc_token, routine, deferred_context)?;
        self.queue(identity, argument1, argument2)
    }

    pub fn remove(&mut self, identity: HostedDpcIdentity) -> Result<bool, HostedDpcError> {
        let index = self.record_index(identity)?;
        if self.records[index].queued.take().is_some() {
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn begin_next(
        &mut self,
        owner: HostedDpcOwner,
    ) -> Result<Option<HostedDpcActivation>, HostedDpcError> {
        if HostedDpcOwner::new(owner.domain_id, owner.domain_cookie) != Some(owner) {
            return Err(HostedDpcError::InvalidIdentity);
        }
        let Some(index) = self
            .records
            .iter()
            .enumerate()
            .filter_map(|(index, record)| {
                record
                    .queued
                    .filter(|_| {
                        record.live && record.identity.owner == owner && record.in_flight.is_none()
                    })
                    .map(|queued| (index, queued.sequence))
            })
            .min_by_key(|(_, sequence)| *sequence)
            .map(|(index, _)| index)
        else {
            return Ok(None);
        };
        let record = &mut self.records[index];
        if record.in_flight.is_some() {
            return Err(HostedDpcError::Busy);
        }
        let queued = record
            .queued
            .take()
            .ok_or(HostedDpcError::StaleActivation)?;
        record.in_flight = Some(queued.sequence);
        Ok(Some(HostedDpcActivation {
            identity: record.identity,
            sequence: queued.sequence,
            routine: record.routine,
            deferred_context: record.deferred_context,
            system_argument1: queued.argument1,
            system_argument2: queued.argument2,
        }))
    }

    pub fn complete(&mut self, activation: HostedDpcActivation) -> Result<(), HostedDpcError> {
        let index = self.record_index(activation.identity)?;
        let record = &mut self.records[index];
        if record.in_flight != Some(activation.sequence) {
            return Err(HostedDpcError::StaleActivation);
        }
        record.in_flight = None;
        Ok(())
    }

    pub fn retire(&mut self, identity: HostedDpcIdentity) -> Result<(), HostedDpcError> {
        let index = self.record_index(identity)?;
        if self.records[index].queued.is_some() || self.records[index].in_flight.is_some() {
            return Err(HostedDpcError::Busy);
        }
        self.records[index].live = false;
        Ok(())
    }

    pub fn snapshot(
        &self,
        identity: HostedDpcIdentity,
    ) -> Result<HostedDpcSnapshot, HostedDpcError> {
        let record = &self.records[self.record_index(identity)?];
        Ok(HostedDpcSnapshot {
            identity,
            routine: record.routine,
            deferred_context: record.deferred_context,
            queued: record.queued.is_some(),
            in_flight: record.in_flight.is_some(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(id: u64) -> HostedDpcOwner {
        HostedDpcOwner::new(id, id + 1).unwrap()
    }

    #[test]
    fn queue_is_exact_and_duplicate_insert_is_false_semantics() {
        let mut table = HostedDpcTable::new();
        let identity = table.register(owner(7), 0x1000, 0x2000, 0x3000).unwrap();
        assert_eq!(
            table.queue(identity, 11, 13),
            Ok(HostedDpcQueueResult::Queued(identity))
        );
        assert_eq!(
            table.queue(identity, 17, 19),
            Ok(HostedDpcQueueResult::AlreadyQueued(identity))
        );
        let activation = table.begin_next(owner(7)).unwrap().unwrap();
        assert_eq!(activation.system_argument1, 11);
        assert_eq!(activation.system_argument2, 13);
        assert!(table.snapshot(identity).unwrap().in_flight);
        table.complete(activation).unwrap();
        assert!(!table.snapshot(identity).unwrap().queued);
    }

    #[test]
    fn clear_inserted_before_callback_allows_requeue_during_dispatch() {
        let mut table = HostedDpcTable::new();
        let identity = table.register(owner(7), 0x1000, 0x2000, 0).unwrap();
        table.queue(identity, 0, 0).unwrap();
        let activation = table.begin_next(owner(7)).unwrap().unwrap();
        assert_eq!(
            table.queue(identity, 1, 2),
            Ok(HostedDpcQueueResult::Queued(identity))
        );
        table.complete(activation).unwrap();
        assert_eq!(
            table.queue(identity, 3, 4),
            Ok(HostedDpcQueueResult::AlreadyQueued(identity))
        );
    }

    #[test]
    fn reinitialization_and_slot_reuse_change_generation() {
        let mut table = HostedDpcTable::new();
        let first = table.register(owner(7), 0x1000, 0x2000, 0).unwrap();
        assert_eq!(table.register(owner(7), 0x1000, 0x2000, 0), Ok(first));
        let replacement = table.register(owner(7), 0x1000, 0x2001, 1).unwrap();
        assert_ne!(replacement.generation, first.generation);
        assert_eq!(table.queue(first, 0, 0), Err(HostedDpcError::NotRegistered));
        table.retire(replacement).unwrap();
        let reused = table.register(owner(9), 0x1000, 0x3000, 0).unwrap();
        assert_ne!(reused.generation, replacement.generation);
        assert_eq!(table.records.len(), 1);
    }

    #[test]
    fn queued_projection_cannot_be_reinitialized_or_retired() {
        let mut table = HostedDpcTable::new();
        let identity = table.register(owner(7), 0x1000, 0x2000, 0).unwrap();
        table.queue(identity, 0, 0).unwrap();
        assert_eq!(
            table.register(owner(7), 0x1000, 0x2001, 0),
            Err(HostedDpcError::Busy)
        );
        assert_eq!(table.retire(identity), Err(HostedDpcError::Busy));
        assert!(table.remove(identity).unwrap());
        table.retire(identity).unwrap();
    }

    #[test]
    fn fifo_is_per_owner_and_completion_is_generation_fenced() {
        let mut table = HostedDpcTable::new();
        let a = table.register(owner(7), 0x1000, 0x2000, 0).unwrap();
        let b = table.register(owner(7), 0x1001, 0x2001, 0).unwrap();
        let other = table.register(owner(9), 0x1000, 0x3000, 0).unwrap();
        table.queue(a, 1, 0).unwrap();
        table.queue(other, 2, 0).unwrap();
        table.queue(b, 3, 0).unwrap();
        assert_eq!(table.begin_next(owner(7)).unwrap().unwrap().identity, a);
        assert_eq!(table.begin_next(owner(9)).unwrap().unwrap().identity, other);
        let activation = table.begin_next(owner(7)).unwrap().unwrap();
        assert_eq!(activation.identity, b);
        assert_eq!(
            table.complete(HostedDpcActivation {
                sequence: activation.sequence + 1,
                ..activation
            }),
            Err(HostedDpcError::StaleActivation)
        );
        table.complete(activation).unwrap();
    }
}
