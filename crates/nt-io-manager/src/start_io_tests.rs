use super::*;
use alloc::{vec, vec::Vec};
use crate::device_queue::{initialize_device_queue, DEVICE_QUEUE_ENTRY_SIZE, DEVICE_QUEUE_SIZE};
use alloc::rc::Rc;
use core::cell::{Cell, RefCell};

const D: u64 = 0x100;
const X: u64 = 0x250;
const A: u64 = 0x400;
const B: u64 = 0x500;
const C: u64 = 0x600;

#[derive(Debug, PartialEq, Eq)]
struct Owner { address: u64, generation: u64 }
struct Memory { bytes: Vec<u8>, generation: u64, refused: Option<u64>, commits: usize }
impl Memory {
    fn new() -> Self {
        let mut m = Self { bytes: vec![0; 2048], generation: 1, refused: None, commits: 0 };
        initialize_device_queue(&mut m, D + 0xa0).unwrap();
        m
    }
    fn u32(&self, a: u64) -> u32 { u32::from_le_bytes(self.bytes[a as usize..a as usize + 4].try_into().unwrap()) }
    fn u64(&self, a: u64) -> u64 { u64::from_le_bytes(self.bytes[a as usize..a as usize + 8].try_into().unwrap()) }
    fn put32(&mut self, a: u64, v: u32) { self.bytes[a as usize..a as usize + 4].copy_from_slice(&v.to_le_bytes()); }
    fn put64(&mut self, a: u64, v: u64) { self.bytes[a as usize..a as usize + 8].copy_from_slice(&v.to_le_bytes()); }
    fn apply_writes(&mut self, writes: &[DeviceQueueWrite]) {
        for write in writes { match *write {
            DeviceQueueWrite::U8 { address, value } => self.bytes[address as usize] = value,
            DeviceQueueWrite::U16 { address, value } => self.bytes[address as usize..address as usize + 2].copy_from_slice(&value.to_le_bytes()),
            DeviceQueueWrite::U32 { address, value } => self.put32(address, value),
            DeviceQueueWrite::U64 { address, value } => self.put64(address, value),
        } }
        self.commits += 1;
    }
    fn start(&mut self, irp: u64, key: Option<u32>) -> Action<Owner, u64> {
        match start_packet(self, D, irp + 0x78, key, None, None::<CancelLock<u64>>) {
            Ok(outcome) => outcome.action, Err(_) => panic!("start refused"),
        }
    }
    fn next(&mut self, key: Option<u32>) -> Action<Owner, u64> {
        match start_next(self, D, key, false, None::<CancelLock<u64>>) {
            Ok(outcome) => outcome.action, Err(_) => panic!("next refused"),
        }
    }
}
impl LockedDeviceQueueMemory for Memory {
    type Error = &'static str;
    fn validate_unpublished_queue_storage(&self, _: u64) -> Result<(), Self::Error> { Ok(()) }
    fn queue(&self, a: u64) -> Result<DeviceQueueSnapshot, Self::Error> {
        DeviceQueueSnapshot::read(&self.bytes[a as usize..a as usize + DEVICE_QUEUE_SIZE]).map_err(|_| "queue")
    }
    fn entry(&self, a: u64) -> Result<DeviceQueueEntrySnapshot, Self::Error> {
        DeviceQueueEntrySnapshot::read(&self.bytes[a as usize..a as usize + DEVICE_QUEUE_ENTRY_SIZE]).map_err(|_| "entry")
    }
    fn apply(&mut self, edits: &DeviceQueueEdits) { self.apply_writes(edits.writes()); }
}
impl LockedStartIoMemory for Memory {
    type Owner = Owner;
    fn validate_device_owner(&self, retained: &Device<Owner>) -> Result<(), Self::Error> {
        if retained.owner.address == D && retained.owner.generation == self.generation { Ok(()) } else { Err("retired device generation") }
    }
    fn device(&self, address: u64) -> Result<Device<Owner>, Self::Error> {
        if address != D || self.refused == Some(address) { return Err("device authority"); }
        Ok(Device { address, queue: D + 0xa0, extension: X, current_irp: self.u64(D + 0x20),
            start_io: 0x9000, count: self.u32(X + 0x38), key: self.u32(X + 0x3c), flags: self.u32(X + 0x40),
            owner: Owner { address, generation: self.generation } })
    }
    fn packet(&self, entry: u64, _: Option<u64>) -> Result<Packet<Owner>, Self::Error> {
        let irp = entry.checked_sub(0x78).ok_or("IRP")?;
        if ![A, B, C].contains(&irp) || self.refused == Some(irp) { return Err("IRP generation authority"); }
        Ok(Packet { irp, entry, cancelled: self.bytes[(irp + 0x44) as usize] != 0,
            owner: Owner { address: irp, generation: self.generation } })
    }
    fn commit_start_io(&mut self, writes: &[DeviceQueueWrite]) { self.apply_writes(writes); }
}

#[test]
fn idle_current_and_fifo_use_actual_intrusive_entries_and_retained_owners() {
    let mut m = Memory::new();
    match m.start(A, None) { Action::Start { device, packet, finish_deferred } => {
        assert_eq!(device.owner, Owner { address: D, generation: 1 });
        assert_eq!(packet.owner, Owner { address: A, generation: 1 });
        assert!(!finish_deferred);
    }, _ => panic!("idle packet must start") }
    assert_eq!(m.u64(D + 0x20), A);
    assert!(matches!(m.start(B, None), Action::Queued { packet: Packet { irp: B, .. }, .. }));
    assert!(matches!(m.start(C, None), Action::Queued { packet: Packet { irp: C, .. }, .. }));
    assert_eq!(m.u64(D + 0xa8), B + 0x78);
    assert!(matches!(m.next(None), Action::Start { packet: Packet { irp: B, .. }, .. }));
    assert_eq!(m.u64(D + 0x20), B);
    assert!(matches!(m.next(None), Action::Start { packet: Packet { irp: C, .. }, .. }));
    assert!(matches!(m.next(None), Action::Retained { .. }));
    assert_eq!(m.u64(D + 0x20), 0);
    assert!(!m.queue(D + 0xa0).unwrap().busy);
}

#[test]
fn keyed_selection_wraps_and_preserves_actual_current() {
    let mut m = Memory::new(); m.start(A, None); m.start(B, Some(10)); m.start(C, Some(30));
    assert!(matches!(m.next(Some(20)), Action::Start { packet: Packet { irp: C, .. }, .. }));
    assert!(matches!(m.next(Some(40)), Action::Start { packet: Packet { irp: B, .. }, .. }));
    assert_eq!(m.u64(D + 0x20), B);
}

#[test]
fn queued_cancel_transfers_lock_but_idle_cancel_releases_before_start() {
    let mut m = Memory::new(); m.bytes[(A + 0x44) as usize] = 1;
    let out = match start_packet(&mut m, D, A + 0x78, None, Some(0xa000), Some(CancelLock { token: 11, previous_irql: 2 })) { Ok(v) => v, Err(_) => panic!() };
    assert!(matches!(out.action, Action::Start { .. }));
    assert_eq!(out.release_lock.unwrap().token, 11);
    m.bytes[(B + 0x44) as usize] = 1;
    let out = match start_packet(&mut m, D, B + 0x78, None, Some(0xa000), Some(CancelLock { token: 12, previous_irql: 2 })) { Ok(v) => v, Err(_) => panic!() };
    assert!(out.release_lock.is_none());
    match out.action { Action::Cancel { lock, routine, packet, .. } => {
        assert_eq!(lock.token, 12); assert_eq!(routine, 0xa000); assert_eq!(packet.irp, B);
    }, _ => panic!() }
    assert!(m.entry(B + 0x78).unwrap().inserted);
    assert_eq!(m.u64(B + 0x68), 0);
    assert_eq!(m.bytes[(B + 0x45) as usize], 2);
}

#[test]
fn attributes_or_and_noncancelable_active_packet_clears_routine() {
    let mut m = Memory::new();
    set_attributes(&mut m, D, true, true).unwrap();
    set_attributes(&mut m, D, false, false).unwrap();
    assert_eq!(m.u32(X + 0x40), DEFERRED | NO_CANCEL);
    let out = match start_packet(&mut m, D, A + 0x78, None, Some(0xa000), Some(CancelLock { token: 1, previous_irql: 2 })) { Ok(v) => v, Err(_) => panic!() };
    assert!(matches!(out.action, Action::Start { finish_deferred: true, .. }));
    assert_eq!(m.u64(A + 0x68), 0);
    assert_eq!(m.u32(X + 0x38), 1);
}

#[test]
fn initial_deferred_start_records_nested_next_and_drains_latest_key_after_return() {
    let mut m = Memory::new(); set_attributes(&mut m, D, true, false).unwrap();
    let retained = match m.start(A, None) { Action::Start { device, finish_deferred: true, .. } => device, _ => panic!() };
    m.start(B, Some(10)); m.start(C, Some(30));
    assert!(matches!(m.next(Some(10)), Action::Retained { .. }));
    assert!(matches!(m.next(Some(30)), Action::Retained { .. }));
    assert_eq!(m.u64(D + 0x20), A);
    assert_eq!(m.u32(X + 0x38), 1);
    assert_eq!(m.u32(X + 0x3c), 30);
    assert!(matches!(finish_deferred(&mut m, retained), Ok(Action::NextRequested { key: Some(30), .. })));
    let retained = match m.next(Some(30)) { Action::Start { device, packet: Packet { irp: C, .. }, finish_deferred: true } => device, _ => panic!() };
    assert_eq!(m.u32(X + 0x38), 1);
    assert_eq!(m.u32(X + 0x40), DEFERRED);
    assert!(matches!(finish_deferred(&mut m, retained), Ok(Action::Retained { .. })));
    let idle = m.device(D).unwrap();
    assert!(finish_deferred(&mut m, idle).is_err());
}

#[test]
fn refused_owner_or_duplicate_current_is_atomic_and_returns_lock_owner() {
    let mut m = Memory::new(); m.start(A, None);
    let before = m.bytes.clone(); let commits = m.commits;
    let err = match start_packet(&mut m, D, A + 0x78, None, Some(0xa000), Some(CancelLock { token: 9, previous_irql: 2 })) { Err(e) => e, Ok(_) => panic!() };
    assert_eq!(err.error, Error::DuplicateCurrent); assert_eq!(err.lock.unwrap().token, 9);
    m.refused = Some(B);
    assert!(start_packet(&mut m, D, B + 0x78, None, None, None::<CancelLock<u64>>).is_err());
    assert_eq!(m.bytes, before); assert_eq!(m.commits, commits);
    m.refused = None; m.start(B, None); m.refused = Some(B);
    let before = m.bytes.clone();
    assert!(start_next(&mut m, D, None, false, None::<CancelLock<u64>>).is_err());
    assert_eq!(m.bytes, before, "staged unlink cannot precede packet admission");
}

#[test]
fn missing_lock_and_deferred_overflow_leave_all_bytes_unchanged() {
    let mut m = Memory::new(); let before = m.bytes.clone();
    assert!(start_packet(&mut m, D, A + 0x78, None, Some(0xa000), None::<CancelLock<u64>>).is_err());
    assert_eq!(m.bytes, before);
    set_attributes(&mut m, D, true, false).unwrap(); m.put32(X + 0x38, i32::MAX as u32);
    let before = m.bytes.clone();
    assert!(start_packet(&mut m, D, A + 0x78, None, None, None::<CancelLock<u64>>).is_err());
    assert!(start_next(&mut m, D, None, false, None::<CancelLock<u64>>).is_err());
    assert_eq!(m.bytes, before);
    m.put32(X + 0x38, u32::MAX);
    let before = m.bytes.clone();
    match start_packet(&mut m, D, A + 0x78, None, None, None::<CancelLock<u64>>) {
        Err(refusal) => assert_eq!(refusal.error, Error::InvalidCount),
        Ok(_) => panic!("negative LONG count cannot authorize work"),
    }
    assert_eq!(m.bytes, before);
}

#[test]
fn deferred_requests_or_cancelability_and_keep_latest_key() {
    let mut m = Memory::new(); set_attributes(&mut m, D, true, false).unwrap();
    let retained = match m.start(A, None) { Action::Start { device, .. } => device, _ => panic!() };
    assert!(start_next(&mut m, D, Some(5), true, None::<CancelLock<u64>>).is_ok(),
        "nested deferral needs no cancel lock because it performs no queue selection");
    m.next(None);
    assert_eq!(m.u32(X + 0x40), DEFERRED | REQUESTED | REQUESTED_BY_KEY | CANCELABLE);
    match finish_deferred(&mut m, retained) {
        Ok(Action::NextRequested { key, cancelable, .. }) => { assert_eq!(key, Some(0)); assert!(cancelable); }
        _ => panic!(),
    }
}

#[test]
fn deferred_finish_refuses_reused_device_and_retains_original_owner() {
    let mut m = Memory::new(); set_attributes(&mut m, D, true, false).unwrap();
    let retained = match m.start(A, None) { Action::Start { device, .. } => device, _ => panic!() };
    m.generation = 2;
    let before = m.bytes.clone(); let commits = m.commits;
    match finish_deferred(&mut m, retained) {
        Err(refusal) => { assert_eq!(refusal.retained.owner.generation, 1); assert_eq!(refusal.error, Error::Memory("retired device generation")); }
        Ok(_) => panic!(),
    }
    assert_eq!(m.bytes, before); assert_eq!(m.commits, commits);
}

struct DropOwner {
    id: u64,
    address: u64,
    generation: u64,
    dropped: Rc<RefCell<Vec<u64>>>,
}
impl Drop for DropOwner {
    fn drop(&mut self) { self.dropped.borrow_mut().push(self.id); }
}
struct DropMemory {
    memory: Memory,
    next: Cell<u64>,
    dropped: Rc<RefCell<Vec<u64>>>,
}
impl DropMemory {
    fn new() -> Self { Self { memory: Memory::new(), next: Cell::new(1), dropped: Rc::new(RefCell::new(Vec::new())) } }
    fn owner(&self, address: u64) -> DropOwner {
        let id = self.next.get(); self.next.set(id + 1);
        DropOwner { id, address, generation: self.memory.generation, dropped: self.dropped.clone() }
    }
}
impl LockedDeviceQueueMemory for DropMemory {
    type Error = &'static str;
    fn validate_unpublished_queue_storage(&self, address: u64) -> Result<(), Self::Error> { self.memory.validate_unpublished_queue_storage(address) }
    fn queue(&self, address: u64) -> Result<DeviceQueueSnapshot, Self::Error> { self.memory.queue(address) }
    fn entry(&self, address: u64) -> Result<DeviceQueueEntrySnapshot, Self::Error> { self.memory.entry(address) }
    fn apply(&mut self, edits: &DeviceQueueEdits) { self.memory.apply(edits); }
}
impl LockedStartIoMemory for DropMemory {
    type Owner = DropOwner;
    fn device(&self, address: u64) -> Result<Device<DropOwner>, Self::Error> {
        let d = self.memory.device(address)?;
        Ok(Device { address: d.address, queue: d.queue, extension: d.extension, current_irp: d.current_irp,
            start_io: d.start_io, count: d.count, key: d.key, flags: d.flags, owner: self.owner(address) })
    }
    fn validate_device_owner(&self, retained: &Device<DropOwner>) -> Result<(), Self::Error> {
        if retained.owner.address == D && retained.owner.generation == self.memory.generation { Ok(()) } else { Err("retired device generation") }
    }
    fn packet(&self, entry: u64, cancel: Option<u64>) -> Result<Packet<DropOwner>, Self::Error> {
        let p = self.memory.packet(entry, cancel)?;
        Ok(Packet { irp: p.irp, entry: p.entry, cancelled: p.cancelled, owner: self.owner(p.irp) })
    }
    fn commit_start_io(&mut self, writes: &[DeviceQueueWrite]) { self.memory.commit_start_io(writes); }
}

#[test]
fn queued_packet_outcome_retains_both_exact_owner_receipts() {
    let mut m = DropMemory::new();
    let _active = match start_packet(&mut m, D, A + 0x78, None, None, None::<CancelLock<u64>>) { Ok(out) => out, Err(_) => panic!() };
    let device_id = m.next.get(); let packet_id = device_id + 1;
    let _queued = match start_packet(&mut m, D, B + 0x78, None, None, None::<CancelLock<u64>>) { Ok(out) => out, Err(_) => panic!() };
    assert!(m.memory.entry(B + 0x78).unwrap().inserted);
    assert!(!m.dropped.borrow().contains(&device_id), "queued DEVICE_OBJECT ownership was discarded after insertion");
    assert!(!m.dropped.borrow().contains(&packet_id), "queued IRP generation ownership was discarded after insertion");
}

#[test]
fn deferred_finish_outcome_retains_original_device_receipt_while_current_remains() {
    let mut m = DropMemory::new(); set_attributes(&mut m, D, true, false).unwrap();
    let (retained, _packet) = match start_packet(&mut m, D, A + 0x78, None, None, None::<CancelLock<u64>>) {
        Ok(Outcome { action: Action::Start { device, packet, .. }, .. }) => (device, packet), _ => panic!(),
    };
    let original_id = retained.owner.id;
    let _finished = match finish_deferred(&mut m, retained) { Ok(out) => out, Err(_) => panic!() };
    assert_eq!(m.memory.u64(D + 0x20), A, "callback return is not CurrentIrp withdrawal");
    assert!(!m.dropped.borrow().contains(&original_id), "deferred finish discarded the original still-current device owner");
}

#[test]
fn queued_packet_preserves_receipts_when_deferred_next_is_also_ready() {
    let mut m = DropMemory::new();
    let _active = match start_packet(&mut m, D, A + 0x78, None, None, None::<CancelLock<u64>>) { Ok(out) => out, Err(_) => panic!() };
    set_attributes(&mut m, D, true, false).unwrap();
    m.memory.put32(X + 0x40, DEFERRED | REQUESTED_BY_KEY | CANCELABLE);
    m.memory.put32(X + 0x3c, 30);
    let device_id = m.next.get(); let packet_id = device_id + 1;
    let queued = match start_packet(&mut m, D, B + 0x78, Some(10), None, None::<CancelLock<u64>>) { Ok(out) => out, Err(_) => panic!() };
    match &queued.action {
        Action::Queued { device, packet, next } => {
            assert_eq!(device.owner.id, device_id); assert_eq!(packet.owner.id, packet_id);
            assert_eq!(*next, Some(NextRequest { key: Some(30), cancelable: true }));
        }
        _ => panic!("deferred scheduling cannot replace queued ownership"),
    }
    assert!(!m.dropped.borrow().contains(&device_id));
    assert!(!m.dropped.borrow().contains(&packet_id));
    assert!(m.memory.entry(B + 0x78).unwrap().inserted);
}
