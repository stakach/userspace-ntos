//! Atomic publication of one DMA allocation projection shared across component domains.
//!
//! The root manager owns the allocation. This record is only a versioned projection of that
//! claim. Every field is atomic because root snapshots may race a provider publication.

use core::sync::atomic::{AtomicU64, Ordering};

pub const RESERVED: u64 = u64::MAX;
const DIRECTION_MASK: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub logical: u64,
    pub length: u64,
    pub va: u64,
    pub kind: u64,
    pub source_va: u64,
    pub flags: u64,
    pub map_register: u64,
    pub adapter_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Busy;

#[repr(C)]
pub struct SharedDmaRecord {
    logical: AtomicU64,
    length: AtomicU64,
    va: AtomicU64,
    kind: AtomicU64,
    source_va: AtomicU64,
    flags: AtomicU64,
    map_register: AtomicU64,
    adapter_id: AtomicU64,
}

impl Default for SharedDmaRecord {
    fn default() -> Self {
        Self::new()
    }
}

impl SharedDmaRecord {
    pub const fn new() -> Self {
        Self {
            logical: AtomicU64::new(0),
            length: AtomicU64::new(0),
            va: AtomicU64::new(0),
            kind: AtomicU64::new(0),
            source_va: AtomicU64::new(0),
            flags: AtomicU64::new(0),
            map_register: AtomicU64::new(0),
            adapter_id: AtomicU64::new(0),
        }
    }

    fn field(&self, offset: u64) -> &AtomicU64 {
        match offset {
            0x00 => &self.logical,
            0x08 => &self.length,
            0x10 => &self.va,
            0x18 => &self.kind,
            0x20 => &self.source_va,
            0x28 => &self.flags,
            0x30 => &self.map_register,
            0x38 => &self.adapter_id,
            _ => panic!("invalid shared DMA record field"),
        }
    }

    pub fn load(&self, offset: u64) -> u64 {
        self.field(offset).load(Ordering::SeqCst)
    }

    /// Only the provider's allocation guard may mutate a record. `length` is the commit
    /// marker: mutation starts with `begin` and ends with `publish` or `clear`.
    pub fn store(&self, offset: u64, value: u64) {
        assert!(offset != 0x08 && offset != 0x28);
        self.field(offset).store(value, Ordering::SeqCst);
    }

    pub fn begin(&self) {
        self.length.store(RESERVED, Ordering::SeqCst);
    }

    fn next_generation(&self, direction: u64) {
        let old = self.flags.load(Ordering::SeqCst) & !DIRECTION_MASK;
        let next = old.checked_add(2).expect("DMA record generation exhausted");
        self.flags.store(next | (direction & DIRECTION_MASK), Ordering::SeqCst);
    }

    pub fn publish(&self, length: u64, direction: u64) {
        assert!(length != 0 && length != RESERVED);
        self.next_generation(direction);
        self.length.store(length, Ordering::SeqCst);
    }

    pub fn clear(&self) {
        self.begin();
        self.logical.store(0, Ordering::SeqCst);
        self.va.store(0, Ordering::SeqCst);
        self.kind.store(0, Ordering::SeqCst);
        self.source_va.store(0, Ordering::SeqCst);
        self.map_register.store(0, Ordering::SeqCst);
        self.adapter_id.store(0, Ordering::SeqCst);
        self.next_generation(0);
        self.length.store(0, Ordering::SeqCst);
    }

    pub fn snapshot(&self) -> Result<Snapshot, Busy> {
        for _ in 0..8 {
            let length = self.length.load(Ordering::SeqCst);
            if length == RESERVED {
                core::hint::spin_loop();
                continue;
            }
            let flags = self.flags.load(Ordering::SeqCst);
            let snapshot = Snapshot {
                logical: self.logical.load(Ordering::SeqCst),
                length,
                va: self.va.load(Ordering::SeqCst),
                kind: self.kind.load(Ordering::SeqCst),
                source_va: self.source_va.load(Ordering::SeqCst),
                flags,
                map_register: self.map_register.load(Ordering::SeqCst),
                adapter_id: self.adapter_id.load(Ordering::SeqCst),
            };
            if self.length.load(Ordering::SeqCst) == length
                && self.flags.load(Ordering::SeqCst) == flags {
                return Ok(snapshot);
            }
            core::hint::spin_loop();
        }
        Err(Busy)
    }
}

const _: () = assert!(core::mem::size_of::<SharedDmaRecord>() == 0x40);
const _: () = assert!(core::mem::offset_of!(SharedDmaRecord, logical) == 0x00);
const _: () = assert!(core::mem::offset_of!(SharedDmaRecord, length) == 0x08);
const _: () = assert!(core::mem::offset_of!(SharedDmaRecord, va) == 0x10);
const _: () = assert!(core::mem::offset_of!(SharedDmaRecord, kind) == 0x18);
const _: () = assert!(core::mem::offset_of!(SharedDmaRecord, source_va) == 0x20);
const _: () = assert!(core::mem::offset_of!(SharedDmaRecord, flags) == 0x28);
const _: () = assert!(core::mem::offset_of!(SharedDmaRecord, map_register) == 0x30);
const _: () = assert!(core::mem::offset_of!(SharedDmaRecord, adapter_id) == 0x38);

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::sync::{Arc, atomic::{AtomicBool, Ordering as StdOrdering}};

    #[test]
    fn concurrent_publish_and_clear_never_yields_torn_snapshot() {
        let record = Arc::new(SharedDmaRecord::new());
        let running = Arc::new(AtomicBool::new(true));
        let writer = {
            let record = Arc::clone(&record);
            let running = Arc::clone(&running);
            std::thread::spawn(move || {
                for generation in 1..10_000u64 {
                    record.begin();
                    record.store(0x00, generation);
                    record.store(0x10, generation + 100);
                    record.store(0x18, 1);
                    record.store(0x20, generation + 200);
                    record.store(0x30, generation + 300);
                    record.store(0x38, generation + 400);
                    record.publish(64, generation & 1);
                    record.clear();
                }
                running.store(false, StdOrdering::Release);
            })
        };
        while running.load(StdOrdering::Acquire) {
            if let Ok(snapshot) = record.snapshot() {
                if snapshot.length == 0 {
                    assert_eq!((snapshot.logical, snapshot.va, snapshot.kind,
                        snapshot.source_va, snapshot.map_register, snapshot.adapter_id),
                        (0, 0, 0, 0, 0, 0));
                } else {
                    assert_eq!(snapshot.length, 64);
                    assert_eq!(snapshot.va, snapshot.logical + 100);
                    assert_eq!(snapshot.source_va, snapshot.logical + 200);
                    assert_eq!(snapshot.map_register, snapshot.logical + 300);
                    assert_eq!(snapshot.adapter_id, snapshot.logical + 400);
                }
            }
        }
        writer.join().unwrap();
    }
}
