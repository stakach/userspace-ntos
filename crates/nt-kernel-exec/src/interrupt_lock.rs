//! Generation-fenced ownership for interrupt `ActualLock` identities.
//!
//! A caller-supplied lock may be shared by several connected `KINTERRUPT` objects in one hosted
//! domain. ISR execution and `KeSynchronizeExecution` must acquire the same record, while disconnect
//! must retain the record until every exact execution lease has drained.

use alloc::vec::Vec;

use crate::InterruptConnectionIdentity;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptActualLockIdentity {
    pub owner_domain: u64,
    pub owner_cookie: u64,
    pub lock_token: u64,
    pub generation: u64,
}

impl InterruptActualLockIdentity {
    pub const fn new(
        owner_domain: u64,
        owner_cookie: u64,
        lock_token: u64,
        generation: u64,
    ) -> Option<Self> {
        if owner_domain == 0 || owner_cookie == 0 || lock_token == 0 || generation == 0 {
            None
        } else {
            Some(Self {
                owner_domain,
                owner_cookie,
                lock_token,
                generation,
            })
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptActualLockLease {
    pub identity: InterruptActualLockIdentity,
    pub owner: InterruptConnectionIdentity,
    pub sequence: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptActualLockSnapshot {
    pub identity: InterruptActualLockIdentity,
    pub owner_count: usize,
    pub held: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptActualLockError {
    InvalidIdentity,
    AlreadyRegistered,
    NotRegistered,
    Busy,
    StaleLease,
    SequenceExhausted,
    GenerationExhausted,
    OutOfMemory,
}

struct InterruptActualLockRecord {
    identity: InterruptActualLockIdentity,
    live: bool,
    owners: Vec<InterruptConnectionIdentity>,
    next_sequence: u64,
    held: Option<(u64, InterruptConnectionIdentity)>,
}

pub struct InterruptActualLockTable {
    records: Vec<InterruptActualLockRecord>,
    next_generation: u64,
}

impl Default for InterruptActualLockTable {
    fn default() -> Self {
        Self::new()
    }
}

impl InterruptActualLockTable {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            next_generation: 1,
        }
    }

    fn owner_valid(owner: InterruptConnectionIdentity) -> bool {
        InterruptConnectionIdentity::new(
            owner.owner_domain,
            owner.owner_cookie,
            owner.connection_id,
            owner.grant_generation,
        ) == Some(owner)
    }

    fn record_index(
        &self,
        identity: InterruptActualLockIdentity,
    ) -> Result<usize, InterruptActualLockError> {
        if InterruptActualLockIdentity::new(
            identity.owner_domain,
            identity.owner_cookie,
            identity.lock_token,
            identity.generation,
        ) != Some(identity)
        {
            return Err(InterruptActualLockError::InvalidIdentity);
        }
        self.records
            .iter()
            .position(|record| record.live && record.identity == identity)
            .ok_or(InterruptActualLockError::NotRegistered)
    }

    pub fn register(
        &mut self,
        owner: InterruptConnectionIdentity,
        lock_token: u64,
    ) -> Result<InterruptActualLockIdentity, InterruptActualLockError> {
        if !Self::owner_valid(owner) || lock_token == 0 {
            return Err(InterruptActualLockError::InvalidIdentity);
        }
        if let Some(record) = self
            .records
            .iter()
            .find(|record| record.live && record.owners.contains(&owner))
        {
            return if record.identity.owner_domain == owner.owner_domain
                && record.identity.owner_cookie == owner.owner_cookie
                && record.identity.lock_token == lock_token
            {
                Ok(record.identity)
            } else {
                Err(InterruptActualLockError::AlreadyRegistered)
            };
        }
        if let Some(record) = self.records.iter_mut().find(|record| {
            record.live
                && record.identity.owner_domain == owner.owner_domain
                && record.identity.owner_cookie == owner.owner_cookie
                && record.identity.lock_token == lock_token
        }) {
            record
                .owners
                .try_reserve(1)
                .map_err(|_| InterruptActualLockError::OutOfMemory)?;
            record.owners.push(owner);
            return Ok(record.identity);
        }

        let generation = self.next_generation;
        let next_generation = generation
            .checked_add(1)
            .ok_or(InterruptActualLockError::GenerationExhausted)?;
        let identity = InterruptActualLockIdentity::new(
            owner.owner_domain,
            owner.owner_cookie,
            lock_token,
            generation,
        )
        .ok_or(InterruptActualLockError::InvalidIdentity)?;
        let mut owners = Vec::new();
        owners
            .try_reserve_exact(1)
            .map_err(|_| InterruptActualLockError::OutOfMemory)?;
        owners.push(owner);
        let replacement = InterruptActualLockRecord {
            identity,
            live: true,
            owners,
            next_sequence: 1,
            held: None,
        };
        if let Some(record) = self.records.iter_mut().find(|record| !record.live) {
            *record = replacement;
        } else {
            self.records
                .try_reserve(1)
                .map_err(|_| InterruptActualLockError::OutOfMemory)?;
            self.records.push(replacement);
        }
        self.next_generation = next_generation;
        Ok(identity)
    }

    pub fn validate_owner(
        &self,
        identity: InterruptActualLockIdentity,
        owner: InterruptConnectionIdentity,
    ) -> Result<(), InterruptActualLockError> {
        let record = &self.records[self.record_index(identity)?];
        if record.owners.contains(&owner) {
            Ok(())
        } else {
            Err(InterruptActualLockError::NotRegistered)
        }
    }

    pub fn prepare_unregister(
        &self,
        identity: InterruptActualLockIdentity,
        owner: InterruptConnectionIdentity,
    ) -> Result<(), InterruptActualLockError> {
        let record = &self.records[self.record_index(identity)?];
        if !record.owners.contains(&owner) {
            return Err(InterruptActualLockError::NotRegistered);
        }
        if record
            .held
            .is_some_and(|(_, held_owner)| held_owner == owner)
        {
            return Err(InterruptActualLockError::Busy);
        }
        Ok(())
    }

    pub fn acquire(
        &mut self,
        identity: InterruptActualLockIdentity,
        owner: InterruptConnectionIdentity,
    ) -> Result<InterruptActualLockLease, InterruptActualLockError> {
        let index = self.record_index(identity)?;
        let record = &mut self.records[index];
        if !record.owners.contains(&owner) {
            return Err(InterruptActualLockError::NotRegistered);
        }
        if record.held.is_some() {
            return Err(InterruptActualLockError::Busy);
        }
        let sequence = record.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(InterruptActualLockError::SequenceExhausted)?;
        record.next_sequence = next_sequence;
        record.held = Some((sequence, owner));
        Ok(InterruptActualLockLease {
            identity,
            owner,
            sequence,
        })
    }

    pub fn release(
        &mut self,
        lease: InterruptActualLockLease,
    ) -> Result<(), InterruptActualLockError> {
        let index = self.record_index(lease.identity)?;
        let record = &mut self.records[index];
        if record.held != Some((lease.sequence, lease.owner)) {
            return Err(InterruptActualLockError::StaleLease);
        }
        record.held = None;
        Ok(())
    }

    pub fn unregister(
        &mut self,
        identity: InterruptActualLockIdentity,
        owner: InterruptConnectionIdentity,
    ) -> Result<bool, InterruptActualLockError> {
        let index = self.record_index(identity)?;
        let record = &mut self.records[index];
        let owner_index = record
            .owners
            .iter()
            .position(|candidate| *candidate == owner)
            .ok_or(InterruptActualLockError::NotRegistered)?;
        if record
            .held
            .is_some_and(|(_, held_owner)| held_owner == owner)
        {
            return Err(InterruptActualLockError::Busy);
        }
        record.owners.remove(owner_index);
        if record.owners.is_empty() {
            if record.held.is_some() {
                return Err(InterruptActualLockError::Busy);
            }
            record.live = false;
            return Ok(true);
        }
        Ok(false)
    }

    pub fn snapshot(
        &self,
        identity: InterruptActualLockIdentity,
    ) -> Result<InterruptActualLockSnapshot, InterruptActualLockError> {
        let record = &self.records[self.record_index(identity)?];
        Ok(InterruptActualLockSnapshot {
            identity,
            owner_count: record.owners.len(),
            held: record.held.is_some(),
        })
    }

    #[cfg(test)]
    fn set_next_sequence_for_test(&mut self, identity: InterruptActualLockIdentity, sequence: u64) {
        let index = self.record_index(identity).unwrap();
        self.records[index].next_sequence = sequence;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(connection_id: u64, generation: u64) -> InterruptConnectionIdentity {
        InterruptConnectionIdentity::new(7, 11, connection_id, generation).unwrap()
    }

    #[test]
    fn shared_actual_lock_has_one_identity_and_exact_exclusion() {
        let mut table = InterruptActualLockTable::new();
        let first = owner(13, 17);
        let second = owner(19, 23);
        let identity = table.register(first, 0x1000).unwrap();
        assert_eq!(table.register(second, 0x1000), Ok(identity));
        assert_eq!(table.snapshot(identity).unwrap().owner_count, 2);

        let lease = table.acquire(identity, first).unwrap();
        assert_eq!(
            table.acquire(identity, second),
            Err(InterruptActualLockError::Busy)
        );
        assert_eq!(table.release(lease), Ok(()));
        assert!(table.acquire(identity, second).is_ok());
    }

    #[test]
    fn stale_identity_owner_and_lease_are_rejected() {
        let mut table = InterruptActualLockTable::new();
        let first = owner(13, 17);
        let identity = table.register(first, 0x1000).unwrap();
        let stale = InterruptActualLockIdentity {
            generation: identity.generation + 1,
            ..identity
        };
        assert_eq!(
            table.acquire(stale, first),
            Err(InterruptActualLockError::NotRegistered)
        );
        assert_eq!(
            table.acquire(identity, owner(29, 31)),
            Err(InterruptActualLockError::NotRegistered)
        );
        let lease = table.acquire(identity, first).unwrap();
        assert_eq!(
            table.release(InterruptActualLockLease {
                sequence: lease.sequence + 1,
                ..lease
            }),
            Err(InterruptActualLockError::StaleLease)
        );
        assert_eq!(table.release(lease), Ok(()));
        assert_eq!(
            table.release(lease),
            Err(InterruptActualLockError::StaleLease)
        );
    }

    #[test]
    fn retirement_waits_for_owner_lease_and_reuse_changes_generation() {
        let mut table = InterruptActualLockTable::new();
        let first = owner(13, 17);
        let identity = table.register(first, 0x1000).unwrap();
        let lease = table.acquire(identity, first).unwrap();
        assert_eq!(
            table.unregister(identity, first),
            Err(InterruptActualLockError::Busy)
        );
        table.release(lease).unwrap();
        assert_eq!(table.unregister(identity, first), Ok(true));
        assert_eq!(
            table.snapshot(identity),
            Err(InterruptActualLockError::NotRegistered)
        );
        let record_count = table.records.len();
        let replacement = table.register(owner(37, 41), 0x1000).unwrap();
        assert_ne!(replacement.generation, identity.generation);
        assert_eq!(table.records.len(), record_count);
    }

    #[test]
    fn sequence_exhaustion_does_not_publish_a_lease() {
        let mut table = InterruptActualLockTable::new();
        let first = owner(13, 17);
        let identity = table.register(first, 0x1000).unwrap();
        table.set_next_sequence_for_test(identity, u64::MAX);
        assert_eq!(
            table.acquire(identity, first),
            Err(InterruptActualLockError::SequenceExhausted)
        );
        assert!(!table.snapshot(identity).unwrap().held);
    }

    #[test]
    fn one_connection_cannot_register_two_lock_tokens() {
        let mut table = InterruptActualLockTable::new();
        let first = owner(13, 17);
        let identity = table.register(first, 0x1000).unwrap();
        assert_eq!(table.register(first, 0x1000), Ok(identity));
        assert_eq!(
            table.register(first, 0x2000),
            Err(InterruptActualLockError::AlreadyRegistered)
        );
    }

    #[test]
    fn owner_validation_and_retirement_preflight_are_exact() {
        let mut table = InterruptActualLockTable::new();
        let first = owner(13, 17);
        let second = owner(19, 23);
        let identity = table.register(first, 0x1000).unwrap();
        assert_eq!(table.validate_owner(identity, first), Ok(()));
        assert_eq!(table.prepare_unregister(identity, first), Ok(()));
        assert_eq!(
            table.validate_owner(identity, second),
            Err(InterruptActualLockError::NotRegistered)
        );
        let lease = table.acquire(identity, first).unwrap();
        assert_eq!(
            table.prepare_unregister(identity, first),
            Err(InterruptActualLockError::Busy)
        );
        table.release(lease).unwrap();
        assert_eq!(table.prepare_unregister(identity, first), Ok(()));
    }
}
