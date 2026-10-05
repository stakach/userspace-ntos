//! StartIo policy over admitted, locked WDM storage. No callbacks or shadow queues.
//!
//! Owners are supplied by the native authority and retained in callback actions. They must cover
//! the exact device, IRP generation, pool allocation and callback image until the action settles.
use crate::device_queue::{self, DeviceQueueEdits, DeviceQueueEntrySnapshot, DeviceQueueError,
    DeviceQueueSnapshot, DeviceQueueWrite, LockedDeviceQueueMemory};

pub const REQUESTED: u32 = 0x20;
pub const REQUESTED_BY_KEY: u32 = 0x40;
pub const CANCELABLE: u32 = 0x80;
pub const DEFERRED: u32 = 0x100;
pub const NO_CANCEL: u32 = 0x200;
const REQUEST_MASK: u32 = REQUESTED | REQUESTED_BY_KEY | CANCELABLE;

pub struct Device<O> {
    pub address: u64,
    pub queue: u64,
    pub extension: u64,
    pub current_irp: u64,
    pub start_io: u64,
    pub count: u32,
    pub key: u32,
    pub flags: u32,
    pub owner: O,
}

pub struct Packet<O> {
    pub irp: u64,
    pub entry: u64,
    pub cancelled: bool,
    pub owner: O,
}

/// All reads and the final commit use the same exclusive device/queue ownership. Admission must
/// protect actual live storage, not infer authority from decoded bytes. `packet` must admit the
/// requested cancel callback too. Commit is infallible local stores, with no IPC or reentry.
pub trait LockedStartIoMemory: LockedDeviceQueueMemory {
    type Owner;
    fn device(&self, address: u64) -> Result<Device<Self::Owner>, Self::Error>;
    /// Revalidate the retained callback's exact device lifetime, not just its numeric address.
    fn validate_device_owner(&self, retained: &Device<Self::Owner>) -> Result<(), Self::Error>;
    fn packet(&self, entry: u64, cancel: Option<u64>) -> Result<Packet<Self::Owner>, Self::Error>;
    fn commit_start_io(&mut self, writes: &[DeviceQueueWrite]);
}

/// The native caller owns this real lock token; this policy never manufactures one.
pub struct CancelLock<L> {
    pub token: L,
    pub previous_irql: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NextRequest {
    pub key: Option<u32>,
    pub cancelable: bool,
}

/// Every successful path returns its admitted owners. Native integration must transfer queue and
/// CurrentIrp obligations into the existing canonical IRP/device owners, not drop them or create a
/// shadow queue. Callback return alone is neither completion nor CurrentIrp withdrawal.
pub enum Action<O, L> {
    Retained { device: Device<O> },
    Queued { device: Device<O>, packet: Packet<O>, next: Option<NextRequest> },
    Start { device: Device<O>, packet: Packet<O>, finish_deferred: bool },
    /// The driver cancel routine owns and must release this lock, even across nested completion.
    Cancel { device: Device<O>, packet: Packet<O>, routine: u64, lock: CancelLock<L>, finish_deferred: bool },
    /// Obtain any required cancel lock, then call `start_next`; no callback has started yet.
    NextRequested { device: Device<O>, key: Option<u32>, cancelable: bool },
}

pub struct Outcome<O, L> {
    pub action: Action<O, L>,
    /// Release this before invoking StartIo; never release the transferred Cancel token here.
    pub release_lock: Option<CancelLock<L>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error<E> {
    Memory(E), Queue(DeviceQueueError<E>), InvalidDevice, DuplicateCurrent,
    MissingCancelLock, UnexpectedCancelLock, CountOverflow, InvalidCount,
}

pub struct Refusal<E, L> {
    pub error: Error<E>,
    pub lock: Option<CancelLock<L>>,
}
pub struct FinishRefusal<E, O> {
    pub error: Error<E>,
    pub retained: Device<O>,
}

struct Writes { items: [DeviceQueueWrite; 20], len: usize }
impl Writes {
    fn new() -> Self { Self { items: [DeviceQueueWrite::U8 { address: 0, value: 0 }; 20], len: 0 } }
    fn push(&mut self, write: DeviceQueueWrite) { self.items[self.len] = write; self.len += 1; }
    fn u32(&mut self, address: u64, value: u32) { self.push(DeviceQueueWrite::U32 { address, value }); }
    fn u64(&mut self, address: u64, value: u64) { self.push(DeviceQueueWrite::U64 { address, value }); }
}
struct Staged<'a, M> { memory: &'a M, writes: &'a mut Writes }
impl<M: LockedDeviceQueueMemory> LockedDeviceQueueMemory for Staged<'_, M> {
    type Error = M::Error;
    fn validate_unpublished_queue_storage(&self, address: u64) -> Result<(), Self::Error> {
        self.memory.validate_unpublished_queue_storage(address)
    }
    fn queue(&self, address: u64) -> Result<DeviceQueueSnapshot, Self::Error> { self.memory.queue(address) }
    fn entry(&self, address: u64) -> Result<DeviceQueueEntrySnapshot, Self::Error> { self.memory.entry(address) }
    fn apply(&mut self, edits: &DeviceQueueEdits) {
        for write in edits.writes() { self.writes.push(*write); }
    }
}

fn device<M: LockedStartIoMemory>(memory: &M, address: u64) -> Result<Device<M::Owner>, Error<M::Error>> {
    let d = memory.device(address).map_err(Error::Memory)?;
    // DEVOBJ_EXTENSION.StartIoCount is LONG, not an unsigned wrapping counter.
    if d.count > i32::MAX as u32 { return Err(Error::InvalidCount); }
    if d.address != address || address == 0 || address & 15 != 0
        || address.checked_add(0x150).is_none() || d.queue != address + 0xa0
        || d.extension < address + 0x150 || d.extension & 15 != 0 || d.extension.checked_add(0x50).is_none()
        || d.start_io == 0 { return Err(Error::InvalidDevice); }
    Ok(d)
}
fn packet<M: LockedStartIoMemory>(memory: &M, entry: u64, cancel: Option<u64>) -> Result<Packet<M::Owner>, Error<M::Error>> {
    let p = memory.packet(entry, cancel).map_err(Error::Memory)?;
    // x64 IRP.Tail.Overlay.DeviceQueueEntry is at 0x78.
    if p.irp == 0 || p.irp & 7 != 0 || p.irp.checked_add(0xd0).is_none()
        || p.entry != entry || p.irp + 0x78 != entry { return Err(Error::InvalidDevice); }
    Ok(p)
}
fn finish<O>(d: &mut Device<O>, writes: &mut Writes) -> Result<Option<(Option<u32>, bool)>, Error<core::convert::Infallible>> {
    if d.count == 0 { return Err(Error::InvalidCount); }
    d.count -= 1;
    writes.u32(d.extension + 0x38, d.count);
    Ok(if d.count == 0 && d.flags & (REQUESTED | REQUESTED_BY_KEY) != 0 {
        Some((if d.flags & REQUESTED_BY_KEY != 0 { Some(d.key) } else { None }, d.flags & CANCELABLE != 0))
    } else { None })
}

pub fn set_attributes<M: LockedStartIoMemory>(memory: &mut M, address: u64, deferred: bool, no_cancel: bool) -> Result<(), Error<M::Error>> {
    let d = device(memory, address)?;
    let flags = d.flags | if deferred { DEFERRED } else { 0 } | if no_cancel { NO_CANCEL } else { 0 };
    memory.commit_start_io(&[DeviceQueueWrite::U32 { address: d.extension + 0x40, value: flags }]);
    Ok(())
}

pub fn start_packet<M: LockedStartIoMemory, L>(memory: &mut M, address: u64, entry: u64,
    key: Option<u32>, cancel: Option<u64>, mut lock: Option<CancelLock<L>>) -> Result<Outcome<M::Owner, L>, Refusal<M::Error, L>> {
    let result = (|| {
        if cancel.is_some_and(|routine| routine == 0) { return Err(Error::InvalidDevice); }
        if cancel.is_some() != lock.is_some() { return Err(if cancel.is_some() { Error::MissingCancelLock } else { Error::UnexpectedCancelLock }); }
        let mut d = device(memory, address)?;
        let p = packet(memory, entry, cancel)?;
        if d.current_irp == p.irp { return Err(Error::DuplicateCurrent); }
        let deferred = d.flags & DEFERRED != 0;
        let count = if deferred { Some(d.count.checked_add(1).filter(|count| *count <= i32::MAX as u32).ok_or(Error::CountOverflow)?) } else { None };
        let mut writes = Writes::new();
        let queued = device_queue::insert_device_queue(&mut Staged { memory, writes: &mut writes }, d.queue, entry, key).map_err(Error::Queue)?;
        if let Some(count) = count { d.count = count; writes.u32(d.extension + 0x38, count); }
        if let Some(routine) = cancel { writes.u64(p.irp + 0x68, routine); }
        if !queued {
            writes.u64(address + 0x20, p.irp);
            d.current_irp = p.irp;
            if cancel.is_some() && d.flags & NO_CANCEL != 0 { writes.u64(p.irp + 0x68, 0); }
            memory.commit_start_io(&writes.items[..writes.len]);
            return Ok(Action::Start { device: d, packet: p, finish_deferred: deferred });
        }
        if cancel.is_some() && p.cancelled {
            writes.u64(p.irp + 0x68, 0);
            writes.push(DeviceQueueWrite::U8 { address: p.irp + 0x45, value: lock.as_ref().unwrap().previous_irql });
            // Deferred count remains owned until the cancel callback returns, just as StartIo.
            memory.commit_start_io(&writes.items[..writes.len]);
            return Ok(Action::Cancel { device: d, packet: p, routine: cancel.unwrap(), lock: lock.take().unwrap(), finish_deferred: deferred });
        }
        let pending = if deferred { finish(&mut d, &mut writes).map_err(|_| Error::InvalidCount)? } else { None };
        memory.commit_start_io(&writes.items[..writes.len]);
        Ok(Action::Queued { device: d, packet: p, next: pending.map(|(key, cancelable)| NextRequest { key, cancelable }) })
    })();
    match result { Ok(action) => Ok(Outcome { action, release_lock: lock }), Err(error) => Err(Refusal { error, lock }) }
}

pub fn start_next<M: LockedStartIoMemory, L>(memory: &mut M, address: u64, key: Option<u32>,
    cancelable: bool, lock: Option<CancelLock<L>>) -> Result<Outcome<M::Owner, L>, Refusal<M::Error, L>> {
    let result = (|| {
        let mut d = device(memory, address)?;
        let deferred = d.flags & DEFERRED != 0;
        let request = if key.is_some() { REQUESTED_BY_KEY } else { REQUESTED } | if cancelable { CANCELABLE } else { 0 };
        let mut writes = Writes::new();
        if deferred && d.count != 0 {
            d.count.checked_add(1).filter(|count| *count <= i32::MAX as u32).ok_or(Error::CountOverflow)?;
            // NT5 coalesces request/cancelable bits with OR, but overwrites the key on every
            // nested request. A later unkeyed request therefore leaves BY_KEY set with key zero.
            writes.u32(d.extension + 0x40, d.flags | request);
            writes.u32(d.extension + 0x3c, key.unwrap_or(0));
            d.flags |= request;
            d.key = key.unwrap_or(0);
            memory.commit_start_io(&writes.items[..writes.len]);
            return Ok(Action::Retained { device: d });
        }
        if cancelable != lock.is_some() { return Err(if cancelable { Error::MissingCancelLock } else { Error::UnexpectedCancelLock }); }
        let selected = device_queue::remove_device_queue(&mut Staged { memory, writes: &mut writes }, d.queue, key).map_err(Error::Queue)?;
        let p = selected.map(|entry| packet(memory, entry, None)).transpose()?;
        d.current_irp = p.as_ref().map_or(0, |p| p.irp);
        writes.u64(address + 0x20, d.current_irp);
        if deferred {
            d.flags &= !REQUEST_MASK;
            d.key = 0;
            writes.u32(d.extension + 0x40, d.flags);
            writes.u32(d.extension + 0x3c, 0);
            d.count = u32::from(p.is_some());
            writes.u32(d.extension + 0x38, d.count);
        }
        if let Some(p) = p.as_ref() { if cancelable && d.flags & NO_CANCEL != 0 { writes.u64(p.irp + 0x68, 0); } }
        memory.commit_start_io(&writes.items[..writes.len]);
        Ok(match p { Some(packet) => Action::Start { device: d, packet, finish_deferred: deferred }, None => Action::Retained { device: d } })
    })();
    match result { Ok(action) => Ok(Outcome { action, release_lock: lock }), Err(error) => Err(Refusal { error, lock }) }
}

/// Called exactly once after an admitted deferred StartIo/cancel callback returns. No IRP access:
/// the callback may have completed or freed it. The native caller still owns its admitted packet
/// receipt; only canonical completion/withdrawal can release that obligation. This function returns
/// the original retained device receipt even when no deferred request remains.
pub fn finish_deferred<M: LockedStartIoMemory>(memory: &mut M, retained: Device<M::Owner>) -> Result<Action<M::Owner, core::convert::Infallible>, FinishRefusal<M::Error, M::Owner>> {
    let result = (|| {
        memory.validate_device_owner(&retained).map_err(Error::Memory)?;
        let mut d = device(memory, retained.address)?;
        if d.flags & DEFERRED == 0 { return Err(Error::InvalidCount); }
        let mut writes = Writes::new();
        let pending = finish(&mut d, &mut writes).map_err(|_| Error::InvalidCount)?;
        memory.commit_start_io(&writes.items[..writes.len]);
        Ok((d, pending))
    })();
    match result {
        Err(error) => Err(FinishRefusal { error, retained }),
        Ok((mut d, pending)) => {
            d.owner = retained.owner;
            Ok(match pending { Some((key, cancelable)) => Action::NextRequested { device: d, key, cancelable }, None => Action::Retained { device: d } })
        }
    }
}

#[cfg(test)]
#[path = "start_io_tests.rs"]
mod tests;
