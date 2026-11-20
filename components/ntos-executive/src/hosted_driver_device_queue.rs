//! Hosted driver `Ke*DeviceQueue` exports over the `nt_io_manager::device_queue` policy.
//!
//! A KDEVICE_QUEUE and its entries live in the calling driver's own memory, so each operation
//! applies the policy's edits directly while holding the queue's embedded KSPIN_LOCK at
//! DISPATCH_LEVEL, as NT does. The policy revalidates the whole reciprocal list on every
//! operation; a malformed queue is a driver fault, never a silent repair.

use super::*;
use nt_io_manager::device_queue::{
    self as policy, DeviceQueueEdits, DeviceQueueEntrySnapshot, DeviceQueueError,
    DeviceQueueSnapshot, DeviceQueueWrite, LockedDeviceQueueMemory, DEVICE_QUEUE_ENTRY_SIZE,
    DEVICE_QUEUE_SIZE,
};

const BUGCHECK_TAG: u64 = 0x4b44_5651; // "KDVQ"
const QUEUE_LOCK_OFFSET: u64 = 24;

fn invalid(queue: u64, detail: u64, phase: u64) -> ! {
    unsafe { crate::provider_bugcheck::report(0xc4, [BUGCHECK_TAG, queue, detail, phase]); }
}

/// The caller's own mapped memory, accessed only while the queue lock (or exclusive unpublished
/// construction) is held. Every store is an ordinary local write.
struct DriverQueueMemory;

unsafe fn bytes<'a>(address: u64, length: usize) -> &'a [u8] {
    unsafe { core::slice::from_raw_parts(address as *const u8, length) }
}

impl LockedDeviceQueueMemory for DriverQueueMemory {
    type Error = ();

    fn validate_unpublished_queue_storage(&self, _: u64) -> Result<(), ()> { Ok(()) }

    fn queue(&self, address: u64) -> Result<DeviceQueueSnapshot, ()> {
        DeviceQueueSnapshot::read(unsafe { bytes(address, DEVICE_QUEUE_SIZE) }).map_err(|_| ())
    }

    fn entry(&self, address: u64) -> Result<DeviceQueueEntrySnapshot, ()> {
        DeviceQueueEntrySnapshot::read(unsafe { bytes(address, DEVICE_QUEUE_ENTRY_SIZE) })
            .map_err(|_| ())
    }

    fn apply(&mut self, edits: &DeviceQueueEdits) {
        for edit in edits.writes() {
            unsafe {
                match *edit {
                    DeviceQueueWrite::U8 { address, value } => write_unaligned(address as *mut u8, value),
                    DeviceQueueWrite::U16 { address, value } => write_unaligned(address as *mut u16, value),
                    DeviceQueueWrite::U32 { address, value } => write_unaligned(address as *mut u32, value),
                    DeviceQueueWrite::U64 { address, value } => write_unaligned(address as *mut u64, value),
                }
            }
        }
    }
}

fn error_code(error: DeviceQueueError<()>) -> u64 {
    match error {
        DeviceQueueError::Memory(()) => 1,
        DeviceQueueError::InvalidAddress => 2,
        DeviceQueueError::InvalidQueue => 3,
        DeviceQueueError::MalformedList => 4,
        DeviceQueueError::AlreadyInserted => 5,
    }
}

/// Hold the queue lock at DISPATCH_LEVEL for one policy operation. A caller below DISPATCH_LEVEL
/// (for example a threaded DPC) is raised for the operation and restored afterwards.
fn locked<T>(
    queue: u64,
    phase: u64,
    operation: impl FnOnce(&mut DriverQueueMemory) -> Result<T, DeviceQueueError<()>>,
) -> T {
    if queue == 0 || queue & 7 != 0 || queue.checked_add(DEVICE_QUEUE_SIZE as u64).is_none() {
        invalid(queue, 0, phase);
    }
    let current = unsafe { hosted_current_irql() };
    if current > DISPATCH_LEVEL { invalid(queue, current as u64, phase); }
    let old = unsafe { hosted_raise_irql(DISPATCH_LEVEL) };
    let lock = queue + QUEUE_LOCK_OFFSET;
    hosted_driver_spin_lock::acquire_word(lock);
    let result = operation(&mut DriverQueueMemory);
    hosted_driver_spin_lock::release_word(lock);
    unsafe { hosted_lower_irql(old); }
    result.unwrap_or_else(|error| invalid(queue, error_code(error), phase))
}

/// `VOID KeInitializeDeviceQueue(PKDEVICE_QUEUE)`: fresh storage owned by the caller.
pub(super) extern "win64" fn initialize(queue: u64) {
    policy::initialize_device_queue(&mut DriverQueueMemory, queue)
        .unwrap_or_else(|error| invalid(queue, error_code(error), 1));
}

/// `BOOLEAN KeInsertDeviceQueue(PKDEVICE_QUEUE, PKDEVICE_QUEUE_ENTRY)`.
pub(super) extern "win64" fn insert(queue: u64, entry: u64) -> u8 {
    u8::from(locked(queue, 2, |memory| policy::insert_device_queue(memory, queue, entry, None)))
}

/// `BOOLEAN KeInsertByKeyDeviceQueue(PKDEVICE_QUEUE, PKDEVICE_QUEUE_ENTRY, ULONG)`.
pub(super) extern "win64" fn insert_by_key(queue: u64, entry: u64, key: u32) -> u8 {
    u8::from(locked(queue, 3, |memory| policy::insert_device_queue(memory, queue, entry, Some(key))))
}

/// `PKDEVICE_QUEUE_ENTRY KeRemoveDeviceQueue(PKDEVICE_QUEUE)`: NULL leaves the queue idle.
pub(super) extern "win64" fn remove(queue: u64) -> u64 {
    locked(queue, 4, |memory| policy::remove_device_queue(memory, queue, None)).unwrap_or(0)
}

/// `PKDEVICE_QUEUE_ENTRY KeRemoveByKeyDeviceQueue(PKDEVICE_QUEUE, ULONG)`.
pub(super) extern "win64" fn remove_by_key(queue: u64, key: u32) -> u64 {
    locked(queue, 5, |memory| policy::remove_device_queue(memory, queue, Some(key))).unwrap_or(0)
}

/// `BOOLEAN KeRemoveEntryDeviceQueue(PKDEVICE_QUEUE, PKDEVICE_QUEUE_ENTRY)`: FALSE when the
/// entry is not currently inserted (for example, it is the active packet).
pub(super) extern "win64" fn remove_entry(queue: u64, entry: u64) -> u8 {
    u8::from(locked(queue, 6, |memory| policy::remove_entry_device_queue(memory, queue, entry)))
}

pub(super) fn bind(reg: &mut DriverExportRegistry) {
    reg.bind("KeInitializeDeviceQueue", initialize as *const () as usize as u64);
    reg.bind("KeInsertDeviceQueue", insert as *const () as usize as u64);
    reg.bind("KeInsertByKeyDeviceQueue", insert_by_key as *const () as usize as u64);
    reg.bind("KeRemoveDeviceQueue", remove as *const () as usize as u64);
    reg.bind("KeRemoveByKeyDeviceQueue", remove_by_key as *const () as usize as u64);
    reg.bind("KeRemoveEntryDeviceQueue", remove_entry as *const () as usize as u64);
}
