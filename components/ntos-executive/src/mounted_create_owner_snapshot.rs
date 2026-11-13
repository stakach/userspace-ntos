//! Bounded observation of one exact parked mounted CREATE, independent of File ownership.

use core::sync::atomic::{AtomicU64, Ordering};

const UNOBSERVED: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OwnerKey {
    pub table: u64,
    pub slot: u64,
    pub generation: u64,
    pub irp: u64,
    pub file: u64,
    pub device: u64,
    pub physical: u64,
    pub logical: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub(crate) enum Phase { Parked = 1, Terminal = 2, ReplyPublished = 3, BackendAcked = 4 }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Observation {
    pub key: OwnerKey,
    pub pi: u64,
    pub tid: u64,
    pub badge: u64,
    pub name_hash: u64,
    pub name_len: u64,
    pub route: u64,
    pub phase: Phase,
    pub status: u64,
    pub delivery: u64,
    pub parked_100ns: u64,
    pub terminal_100ns: Option<u64>,
    pub reply_100ns: Option<u64>,
    pub ack_100ns: Option<u64>,
}

/// One latest-owner sample. Writers use a nonblocking sequence claim; nested diagnostics may
/// skip a sample, but cannot publish a mixed identity or mutate an unrelated owner.
pub(crate) struct OwnerSnapshot {
    sequence: AtomicU64,
    table: AtomicU64,
    slot: AtomicU64,
    generation: AtomicU64,
    irp: AtomicU64,
    file: AtomicU64,
    device: AtomicU64,
    physical: AtomicU64,
    logical: AtomicU64,
    pi: AtomicU64,
    tid: AtomicU64,
    badge: AtomicU64,
    name_hash: AtomicU64,
    name_len: AtomicU64,
    route: AtomicU64,
    phase: AtomicU64,
    status: AtomicU64,
    delivery: AtomicU64,
    parked_100ns: AtomicU64,
    terminal_100ns: AtomicU64,
    reply_100ns: AtomicU64,
    ack_100ns: AtomicU64,
}

impl OwnerSnapshot {
    pub(crate) const fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0), table: AtomicU64::new(0),
            slot: AtomicU64::new(0), generation: AtomicU64::new(0),
            irp: AtomicU64::new(0), file: AtomicU64::new(0),
            device: AtomicU64::new(0), physical: AtomicU64::new(0),
            logical: AtomicU64::new(0), pi: AtomicU64::new(0),
            tid: AtomicU64::new(0), badge: AtomicU64::new(0),
            name_hash: AtomicU64::new(0), name_len: AtomicU64::new(0),
            route: AtomicU64::new(0),
            phase: AtomicU64::new(0), status: AtomicU64::new(0),
            delivery: AtomicU64::new(0),
            parked_100ns: AtomicU64::new(UNOBSERVED),
            terminal_100ns: AtomicU64::new(UNOBSERVED),
            reply_100ns: AtomicU64::new(UNOBSERVED),
            ack_100ns: AtomicU64::new(UNOBSERVED),
        }
    }

    fn claim(&self) -> Option<u64> {
        let current = self.sequence.load(Ordering::Acquire);
        if current & 1 != 0 || current.checked_add(2).is_none() { return None; }
        self.sequence.compare_exchange(current, current + 1,
            Ordering::AcqRel, Ordering::Acquire).ok()
    }

    fn release(&self, previous: u64) {
        self.sequence.store(previous + 2, Ordering::Release);
    }

    fn key(&self) -> OwnerKey {
        OwnerKey {
            table: self.table.load(Ordering::Relaxed),
            slot: self.slot.load(Ordering::Relaxed),
            generation: self.generation.load(Ordering::Relaxed),
            irp: self.irp.load(Ordering::Relaxed),
            file: self.file.load(Ordering::Relaxed),
            device: self.device.load(Ordering::Relaxed),
            physical: self.physical.load(Ordering::Relaxed),
            logical: self.logical.load(Ordering::Relaxed),
        }
    }

    pub(crate) fn park(&self, key: OwnerKey, pi: u64, tid: u64, badge: u64,
        name_hash: u64, name_len: u64, route: u64, now_100ns: u64) -> bool {
        if key.table == 0 || key.generation == 0 || key.irp == 0 || key.file == 0
            || key.device == 0 || key.physical == 0 || key.logical == 0 { return false; }
        let Some(previous) = self.claim() else { return false; };
        self.table.store(key.table, Ordering::Relaxed);
        self.slot.store(key.slot, Ordering::Relaxed);
        self.generation.store(key.generation, Ordering::Relaxed);
        self.irp.store(key.irp, Ordering::Relaxed);
        self.file.store(key.file, Ordering::Relaxed);
        self.device.store(key.device, Ordering::Relaxed);
        self.physical.store(key.physical, Ordering::Relaxed);
        self.logical.store(key.logical, Ordering::Relaxed);
        self.pi.store(pi, Ordering::Relaxed);
        self.tid.store(tid, Ordering::Relaxed);
        self.badge.store(badge, Ordering::Relaxed);
        self.name_hash.store(name_hash, Ordering::Relaxed);
        self.name_len.store(name_len, Ordering::Relaxed);
        self.route.store(route, Ordering::Relaxed);
        self.phase.store(Phase::Parked as u64, Ordering::Relaxed);
        self.status.store(0, Ordering::Relaxed);
        self.delivery.store(0, Ordering::Relaxed);
        self.parked_100ns.store(now_100ns, Ordering::Relaxed);
        self.terminal_100ns.store(UNOBSERVED, Ordering::Relaxed);
        self.reply_100ns.store(UNOBSERVED, Ordering::Relaxed);
        self.ack_100ns.store(UNOBSERVED, Ordering::Relaxed);
        self.release(previous);
        true
    }

    pub(crate) fn advance(&self, key: OwnerKey, phase: Phase, status: u64,
        delivery: u64, now_100ns: u64) -> bool {
        let Some(previous) = self.claim() else { return false; };
        if self.key() != key || (phase as u64) < self.phase.load(Ordering::Relaxed) {
            self.release(previous);
            return false;
        }
        self.phase.store(phase as u64, Ordering::Relaxed);
        self.status.store(status, Ordering::Relaxed);
        self.delivery.store(delivery, Ordering::Relaxed);
        let timestamp = match phase {
            Phase::Parked => &self.parked_100ns,
            Phase::Terminal => &self.terminal_100ns,
            Phase::ReplyPublished => &self.reply_100ns,
            Phase::BackendAcked => &self.ack_100ns,
        };
        if timestamp.load(Ordering::Relaxed) == UNOBSERVED {
            timestamp.store(now_100ns, Ordering::Relaxed);
        }
        self.release(previous);
        true
    }

    pub(crate) fn read(&self) -> Option<Observation> {
        let before = self.sequence.load(Ordering::Acquire);
        if before & 1 != 0 { return None; }
        let raw_phase = self.phase.load(Ordering::Relaxed);
        let phase = match raw_phase {
            1 => Phase::Parked, 2 => Phase::Terminal,
            3 => Phase::ReplyPublished, 4 => Phase::BackendAcked,
            _ => return None,
        };
        let observation = Observation {
            key: self.key(), pi: self.pi.load(Ordering::Relaxed),
            tid: self.tid.load(Ordering::Relaxed),
            badge: self.badge.load(Ordering::Relaxed),
            name_hash: self.name_hash.load(Ordering::Relaxed),
            name_len: self.name_len.load(Ordering::Relaxed),
            route: self.route.load(Ordering::Relaxed),
            phase, status: self.status.load(Ordering::Relaxed),
            delivery: self.delivery.load(Ordering::Relaxed),
            parked_100ns: self.parked_100ns.load(Ordering::Relaxed),
            terminal_100ns: observed(self.terminal_100ns.load(Ordering::Relaxed)),
            reply_100ns: observed(self.reply_100ns.load(Ordering::Relaxed)),
            ack_100ns: observed(self.ack_100ns.load(Ordering::Relaxed)),
        };
        (self.sequence.load(Ordering::Acquire) == before).then_some(observation)
    }
}

fn observed(timestamp: u64) -> Option<u64> {
    (timestamp != UNOBSERVED).then_some(timestamp)
}
