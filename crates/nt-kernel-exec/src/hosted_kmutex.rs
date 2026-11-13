//! Exact-generation, owner-tracked KMUTEX state for hosted drivers.

use alloc::vec::Vec;
use crate::{MutantAcquire, MutantError, MutantStore};

/// x64 `KMUTANT` / `KMUTEX`: 0x18-byte dispatcher header, 0x10-byte list,
/// owner pointer at +0x28, Abandoned at +0x30, ApcDisable at +0x31.
pub fn initial_header(component_address: u64) -> [u8; 0x38] {
    let mut bytes = [0u8; 0x38];
    bytes[0] = 2; // MutantObject
    bytes[2] = 14; // sizeof(KMUTEX) / sizeof(ULONG)
    bytes[4..8].copy_from_slice(&1i32.to_le_bytes());
    bytes[8..16].copy_from_slice(&(component_address + 8).to_le_bytes());
    bytes[16..24].copy_from_slice(&(component_address + 8).to_le_bytes());
    bytes[24..32].copy_from_slice(&(component_address + 0x18).to_le_bytes());
    bytes[32..40].copy_from_slice(&(component_address + 0x18).to_le_bytes());
    bytes[0x31] = 1; // disable kernel APC while held
    bytes
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KmutexKey(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KmutexError { Stale, Busy, NotOwned, Exhausted }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KmutexWait { Busy, Acquired { count: i32 } }

struct Row {
    domain: (u64, u64),
    object: u64,
    key: KmutexKey,
    pool: Option<(u64, u64)>,
}

pub struct HostedKmutexManager {
    next: u64,
    rows: Vec<Row>,
    mutants: MutantStore,
}

impl HostedKmutexManager {
    pub const fn new() -> Self {
        Self { next: 1, rows: Vec::new(), mutants: MutantStore::new() }
    }

    pub fn initialize(&mut self, domain: (u64, u64), object: u64) -> Result<KmutexKey, KmutexError> {
        self.initialize_with_pool(domain, object, None)
    }

    pub fn initialize_with_pool(&mut self, domain: (u64, u64), object: u64,
        pool: Option<(u64, u64)>) -> Result<KmutexKey, KmutexError> {
        if domain.0 == 0 || domain.1 == 0 || object == 0 { return Err(KmutexError::Stale); }
        let next = self.next.checked_add(1).ok_or(KmutexError::Exhausted)?;
        self.rows.try_reserve(1).map_err(|_| KmutexError::Exhausted)?;
        if !self.mutants.try_reserve(1) { return Err(KmutexError::Exhausted); }
        if let Some(index) = self.rows.iter().position(|row| row.domain == domain && row.object == object) {
            let old = self.rows[index].key;
            if self.mutants.query(old.0, 0).is_some_and(|state| state.current_count != 1) {
                return Err(KmutexError::Busy);
            }
            self.mutants.remove(old.0);
            self.rows.remove(index);
        }
        let key = KmutexKey(self.next);
        self.next = next;
        self.mutants.initialize(key.0, None);
        self.rows.push(Row { domain, object, key, pool });
        Ok(key)
    }

    pub fn key_for(&self, domain: (u64, u64), object: u64) -> Option<KmutexKey> {
        self.rows.iter().find(|row| row.domain == domain && row.object == object).map(|row| row.key)
    }

    pub fn key_matches_object(&self, key: KmutexKey, object: u64) -> bool {
        self.rows.iter().any(|row| row.key == key && row.object == object)
    }

    pub fn domain_quiesced(&self, domain: (u64, u64)) -> bool {
        self.rows.iter().filter(|row| row.domain == domain)
            .all(|row| self.count(row.key) == Ok(1))
    }

    pub fn key_in_domain(&self, key: KmutexKey, domain: (u64, u64)) -> bool {
        self.rows.iter().any(|row| row.key == key && row.domain == domain)
    }

    pub fn pool_free_admission(&self, domain: (u64, u64), pool: (u64, u64)) -> bool {
        self.rows.iter().filter(|row| row.domain == domain && row.pool == Some(pool))
            .all(|row| self.count(row.key) == Ok(1))
    }

    pub fn key_in_pool(&self, key: KmutexKey, domain: (u64, u64), pool: (u64, u64)) -> bool {
        self.rows.iter().any(|row| row.key == key && row.domain == domain && row.pool == Some(pool))
    }

    pub fn retire_pool(&mut self, domain: (u64, u64), pool: (u64, u64)) -> Result<(), KmutexError> {
        if !self.pool_free_admission(domain, pool) { return Err(KmutexError::Busy); }
        let mut index = 0;
        while index < self.rows.len() {
            if self.rows[index].domain == domain && self.rows[index].pool == Some(pool) {
                self.mutants.remove(self.rows[index].key.0);
                self.rows.remove(index);
            } else { index += 1; }
        }
        Ok(())
    }

    pub fn wait(&mut self, key: KmutexKey, thread: u64) -> Result<KmutexWait, KmutexError> {
        if thread == 0 || !self.rows.iter().any(|row| row.key == key) { return Err(KmutexError::Stale); }
        match self.mutants.acquire(key.0, thread) {
            Ok(MutantAcquire::Busy) => Ok(KmutexWait::Busy),
            Ok(MutantAcquire::Acquired { .. }) => Ok(KmutexWait::Acquired {
                count: self.mutants.query(key.0, thread).ok_or(KmutexError::Stale)?.current_count,
            }),
            Err(MutantError::LimitExceeded) => Err(KmutexError::Exhausted),
            Err(_) => Err(KmutexError::Stale),
        }
    }

    pub fn ready(&self, key: KmutexKey, thread: u64) -> Result<bool, KmutexError> {
        if thread == 0 || !self.rows.iter().any(|row| row.key == key) { return Err(KmutexError::Stale); }
        if self.mutants.acquire_would_exceed(key.0, thread) { return Err(KmutexError::Exhausted); }
        Ok(self.mutants.ready_for(key.0, thread))
    }

    /// Return the previous NT `SignalState`; zero means the final release made it available.
    pub fn release(&mut self, key: KmutexKey, thread: u64) -> Result<i32, KmutexError> {
        if thread == 0 || !self.rows.iter().any(|row| row.key == key) { return Err(KmutexError::Stale); }
        self.mutants.release(key.0, thread).map_err(|error| match error {
            MutantError::NotOwned => KmutexError::NotOwned,
            _ => KmutexError::Stale,
        })
    }

    pub fn count(&self, key: KmutexKey) -> Result<i32, KmutexError> {
        if !self.rows.iter().any(|row| row.key == key) { return Err(KmutexError::Stale); }
        Ok(self.mutants.query(key.0, 0).ok_or(KmutexError::Stale)?.current_count)
    }

    pub fn remove(&mut self, key: KmutexKey) -> Result<(), KmutexError> {
        let index = self.rows.iter().position(|row| row.key == key).ok_or(KmutexError::Stale)?;
        if self.count(key)? != 1 { return Err(KmutexError::Busy); }
        self.mutants.remove(key.0);
        self.rows.remove(index);
        Ok(())
    }

    pub fn retire_domain(&mut self, domain: (u64, u64)) -> Result<(), KmutexError> {
        if self.rows.iter().filter(|row| row.domain == domain)
            .any(|row| self.count(row.key) != Ok(1)) { return Err(KmutexError::Busy); }
        let mut index = 0;
        while index < self.rows.len() {
            if self.rows[index].domain == domain {
                self.mutants.remove(self.rows[index].key.0);
                self.rows.remove(index);
            } else { index += 1; }
        }
        Ok(())
    }
}
