//! Exact storage for native object-wait owners, independent of their reply or dispatch state.
//!
//! This table deliberately does not interpret the payload. Wait arbitration and retained effect
//! transitions remain with their owning policy; clearing a capability field never releases a row.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_TABLE_IDENTITY: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectWaiterIdentity {
    table: u64,
    slot: usize,
    generation: u64,
}

impl ObjectWaiterIdentity {
    pub const fn slot(self) -> usize {
        self.slot
    }
}

#[derive(Debug)]
struct Owned<T> {
    generation: u64,
    payload: T,
}

/// Move-stable ownership. Neither this table nor an owned payload needs to be clonable.
///
/// ```compile_fail
/// use nt_user_host::object_wait::ObjectWaiterTable;
/// let table = ObjectWaiterTable::<u64>::new();
/// let _duplicate = table.clone();
/// ```
#[derive(Debug)]
pub struct ObjectWaiterTable<T> {
    entries: Vec<Option<Owned<T>>>,
    live: usize,
    identity: u64,
    next_generation: u64,
    allocation_failures: u64,
    store_failures: u64,
}

impl<T> Default for ObjectWaiterTable<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ObjectWaiterTable<T> {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            live: 0,
            identity: 0,
            next_generation: 1,
            allocation_failures: 0,
            store_failures: 0,
        }
    }

    /// Prepare empty storage without invalidating identities or discarding any owner.
    pub fn reserve(&mut self, initial_reserve: usize) -> bool {
        if !self.is_empty() {
            return false;
        }
        if self.entries.capacity() < initial_reserve
            && self
                .entries
                .try_reserve(initial_reserve - self.entries.len())
                .is_err()
        {
            self.allocation_failures = self.allocation_failures.saturating_add(1);
            return false;
        }
        true
    }

    /// Empty slot compaction is safe only after every owner has been explicitly taken. The table
    /// identity and next generation survive reset, so an old token never names a replacement.
    pub fn reset(&mut self, initial_reserve: usize) -> bool {
        if !self.reserve(initial_reserve) {
            return false;
        }
        self.entries.clear();
        true
    }

    pub fn insert(&mut self, payload: T) -> Result<ObjectWaiterIdentity, T> {
        self.insert_with_identity_source(payload, &NEXT_TABLE_IDENTITY)
    }

    fn insert_with_identity_source(
        &mut self,
        payload: T,
        source: &AtomicU64,
    ) -> Result<ObjectWaiterIdentity, T> {
        if self.next_generation == 0 {
            self.store_failures = self.store_failures.saturating_add(1);
            return Err(payload);
        }
        if self.identity == 0 {
            let identity = source.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                if next == 0 {
                    None
                } else {
                    next.checked_add(1)
                }
            });
            match identity {
                Ok(identity) => self.identity = identity,
                Err(_) => {
                    self.store_failures = self.store_failures.saturating_add(1);
                    return Err(payload);
                }
            }
        }
        let slot = match self.entries.iter().position(Option::is_none) {
            Some(slot) => slot,
            None => {
                if self.entries.len() == self.entries.capacity()
                    && self.entries.try_reserve(1).is_err()
                {
                    self.allocation_failures = self.allocation_failures.saturating_add(1);
                    self.store_failures = self.store_failures.saturating_add(1);
                    return Err(payload);
                }
                self.entries.push(None);
                self.entries.len() - 1
            }
        };
        let generation = self.next_generation;
        self.next_generation = generation.checked_add(1).unwrap_or(0);
        self.entries[slot] = Some(Owned {
            generation,
            payload,
        });
        self.live += 1;
        Ok(ObjectWaiterIdentity {
            table: self.identity,
            slot,
            generation,
        })
    }

    pub fn get(&self, slot: usize) -> Option<(ObjectWaiterIdentity, &T)> {
        let entry = self.entries.get(slot)?.as_ref()?;
        Some((
            ObjectWaiterIdentity {
                table: self.identity,
                slot,
                generation: entry.generation,
            },
            &entry.payload,
        ))
    }

    pub fn get_exact(&self, identity: ObjectWaiterIdentity) -> Option<&T> {
        if identity.table == 0 || identity.table != self.identity {
            return None;
        }
        let entry = self.entries.get(identity.slot)?.as_ref()?;
        (entry.generation == identity.generation).then_some(&entry.payload)
    }

    /// The closure may mutate payload fields, never storage identity or occupancy. It must not
    /// retain its borrow across reentrant native operations.
    pub fn update_exact(
        &mut self,
        identity: ObjectWaiterIdentity,
        update: impl FnOnce(&mut T),
    ) -> bool {
        if self.get_exact(identity).is_none() {
            return false;
        }
        update(&mut self.entries[identity.slot].as_mut().unwrap().payload);
        true
    }

    pub fn take(&mut self, identity: ObjectWaiterIdentity) -> Option<T> {
        self.get_exact(identity)?;
        let entry = self.entries[identity.slot].take()?;
        self.live -= 1;
        Some(entry.payload)
    }

    pub fn iter(&self) -> impl Iterator<Item = (ObjectWaiterIdentity, &T)> {
        self.entries.iter().enumerate().filter_map(|(slot, entry)| {
            let entry = entry.as_ref()?;
            Some((
                ObjectWaiterIdentity {
                    table: self.identity,
                    slot,
                    generation: entry.generation,
                },
                &entry.payload,
            ))
        })
    }

    pub const fn len(&self) -> usize {
        self.live
    }
    pub const fn is_empty(&self) -> bool {
        self.live == 0
    }
    pub fn slot_len(&self) -> usize {
        self.entries.len()
    }
    pub fn capacity(&self) -> usize {
        self.entries.capacity()
    }

    pub fn stats(&self) -> (usize, usize, usize, u64, u64) {
        (
            self.live,
            self.entries.len(),
            self.entries.capacity(),
            self.allocation_failures,
            self.store_failures,
        )
    }
}

#[cfg(test)]
#[path = "object_wait/tests.rs"]
mod tests;
