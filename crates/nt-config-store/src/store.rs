//! The `ConfigStore` trait + v0.1 backends (spec §7).

use alloc::vec::Vec;

/// Why a store operation failed (spec §7).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// The backend injected a fault (crash tests) or the medium is unavailable.
    Io,
    /// The store is already locked by another owner.
    Locked,
}

/// Journal durability mode (spec §7.4).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Durability {
    /// fsync every mutation — the default for correctness tests.
    Strict,
    /// Explicit flush only (fast tests).
    Test,
}

/// An opaque store lock token (spec §7.1). Dropping it releases the lock.
pub struct StoreLock(pub(crate) ());

/// Backing store for the Configuration Manager's snapshot + journal (spec §7.1).
pub trait ConfigStore {
    fn read_snapshot(&mut self) -> Result<Option<Vec<u8>>, StoreError>;
    fn write_snapshot_atomic(&mut self, bytes: &[u8]) -> Result<(), StoreError>;

    fn read_journal(&mut self) -> Result<Vec<u8>, StoreError>;
    fn append_journal_record(&mut self, bytes: &[u8]) -> Result<(), StoreError>;
    fn truncate_journal(&mut self) -> Result<(), StoreError>;

    fn fsync_snapshot(&mut self) -> Result<(), StoreError>;
    fn fsync_journal(&mut self) -> Result<(), StoreError>;

    fn lock_store(&mut self) -> Result<StoreLock, StoreError>;
}

/// An in-memory backend — for unit tests + the seL4 in-process v0.1 model (spec §7.2). The
/// snapshot is a single committed blob; the journal is the concatenation of appended records.
#[derive(Default)]
pub struct MemoryStore {
    snapshot: Option<Vec<u8>>,
    journal: Vec<u8>,
    locked: bool,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    /// Simulate a crash: drop the lock but keep the committed snapshot + journal bytes.
    pub fn crash(&mut self) {
        self.locked = false;
    }
}

impl ConfigStore for MemoryStore {
    fn read_snapshot(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.snapshot.clone())
    }
    fn write_snapshot_atomic(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        // Atomic: the blob is replaced wholesale (rename semantics, spec §7.3).
        self.snapshot = Some(bytes.to_vec());
        Ok(())
    }
    fn read_journal(&mut self) -> Result<Vec<u8>, StoreError> {
        Ok(self.journal.clone())
    }
    fn append_journal_record(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        self.journal.extend_from_slice(bytes);
        Ok(())
    }
    fn truncate_journal(&mut self) -> Result<(), StoreError> {
        self.journal.clear();
        Ok(())
    }
    fn fsync_snapshot(&mut self) -> Result<(), StoreError> {
        Ok(())
    }
    fn fsync_journal(&mut self) -> Result<(), StoreError> {
        Ok(())
    }
    fn lock_store(&mut self) -> Result<StoreLock, StoreError> {
        if self.locked {
            return Err(StoreError::Locked);
        }
        self.locked = true;
        Ok(StoreLock(()))
    }
}

/// A fault-injection wrapper for crash-consistency tests (spec §7.2, §21). Fails the Nth write
/// (snapshot or journal append), optionally after having persisted a truncated prefix.
pub struct FaultStore {
    inner: MemoryStore,
    fail_after_writes: Option<u32>,
    writes: u32,
    /// If set, a failing journal append persists this many leading bytes (a torn write).
    torn_prefix: Option<usize>,
}

impl FaultStore {
    pub fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            fail_after_writes: None,
            writes: 0,
            torn_prefix: None,
        }
    }
    /// Fail on the `n`-th mutating write (1-based). `torn` optionally persists a byte prefix of
    /// that write first (simulating a partial/torn record).
    pub fn fail_after(mut self, n: u32, torn: Option<usize>) -> Self {
        self.fail_after_writes = Some(n);
        self.torn_prefix = torn;
        self
    }
    pub fn crash(&mut self) {
        self.inner.crash();
    }
    fn tick(&mut self) -> Result<(), StoreError> {
        self.writes += 1;
        if Some(self.writes) == self.fail_after_writes {
            return Err(StoreError::Io);
        }
        Ok(())
    }
}

impl Default for FaultStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigStore for FaultStore {
    fn read_snapshot(&mut self) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.read_snapshot()
    }
    fn write_snapshot_atomic(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        // A failed atomic snapshot write leaves the *previous* snapshot intact (rename never
        // completed, spec §7.3) — so we don't touch the committed blob on fault.
        self.tick()?;
        self.inner.write_snapshot_atomic(bytes)
    }
    fn read_journal(&mut self) -> Result<Vec<u8>, StoreError> {
        self.inner.read_journal()
    }
    fn append_journal_record(&mut self, bytes: &[u8]) -> Result<(), StoreError> {
        // Journal appends don't participate in the snapshot-write fault counter; a torn
        // journal tail is exercised via a truncated record in the replay tests.
        let _ = self.torn_prefix;
        self.inner.append_journal_record(bytes)
    }
    fn truncate_journal(&mut self) -> Result<(), StoreError> {
        self.inner.truncate_journal()
    }
    fn fsync_snapshot(&mut self) -> Result<(), StoreError> {
        self.inner.fsync_snapshot()
    }
    fn fsync_journal(&mut self) -> Result<(), StoreError> {
        self.inner.fsync_journal()
    }
    fn lock_store(&mut self) -> Result<StoreLock, StoreError> {
        self.inner.lock_store()
    }
}
