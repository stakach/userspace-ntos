//! Bounded serial evidence for mounted-volume directory queries.
//!
//! One marker per completed native NtQueryDirectoryFile on a File of the live mounted volume,
//! inline or retained Pending, reporting the status and Information written to the caller's
//! IOSB and the record count of the delivered bytes. A pending query carries its information
//! class here, keyed by its exact IRP; this metadata never influences delivery.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::{driver_launch, mounted_volume, print_hex, print_str, print_u64};

const MARKER_BUDGET: u32 = 32;
const PENDING_SLOTS: usize = 8;
const NO_CLASS: u32 = u32::MAX;

static MARKERS: AtomicU32 = AtomicU32::new(0);
static PENDING_IRPS: [AtomicU64; PENDING_SLOTS] = [const { AtomicU64::new(0) }; PENDING_SLOTS];
static PENDING_CLASSES: [AtomicU32; PENDING_SLOTS] = [const { AtomicU32::new(NO_CLASS) }; PENDING_SLOTS];

fn mounted_file(file_id: u64) -> bool {
    let Some(volume) = mounted_volume::exec_volume_device() else { return false; };
    driver_launch::io_manager_mut()
        .file(nt_io_manager::FileId(file_id))
        .is_some_and(|file| file.device_id.raw() == volume)
}

fn budget_left() -> bool {
    MARKERS.load(Ordering::Relaxed) < MARKER_BUDGET
}

/// Remember the information class of a query that returned STATUS_PENDING.
pub(crate) fn pending(file_id: u64, irp_id: u64, class: u32) {
    if irp_id == 0 || !budget_left() || !mounted_file(file_id) { return; }
    for (irp, slot_class) in PENDING_IRPS.iter().zip(&PENDING_CLASSES) {
        if irp.compare_exchange(0, irp_id, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            slot_class.store(class, Ordering::Release);
            return;
        }
    }
}

fn take_pending_class(irp_id: u64) -> Option<u32> {
    PENDING_IRPS.iter().zip(&PENDING_CLASSES).find_map(|(irp, class)| {
        (irp.load(Ordering::Acquire) == irp_id).then(|| {
            let value = class.swap(NO_CLASS, Ordering::AcqRel);
            irp.store(0, Ordering::Release);
            value
        })
    })
}

fn report(path: &[u8], pi: u32, class: Option<u32>, entries: Option<usize>, status: u32, information: u64) {
    if MARKERS.fetch_add(1, Ordering::Relaxed) >= MARKER_BUDGET { return; }
    print_str(b"[mounted-query-directory] complete pi=");
    print_u64(u64::from(pi));
    print_str(b" path=");
    print_str(path);
    print_str(b" class=");
    match class {
        Some(class) => print_u64(u64::from(class)),
        None => print_str(b"unrecorded"),
    }
    print_str(b" entries=");
    match entries {
        Some(entries) => print_u64(entries as u64),
        None => print_str(b"malformed"),
    }
    print_str(b" status=0x");
    print_hex(status);
    print_str(b" info=");
    print_u64(information);
    print_str(b"\n");
}

fn delivered_entries(status: u32, information: u64, read: impl FnMut(usize) -> Option<u32>) -> Option<usize> {
    if !nt_io_completion::file_io_status_copies_output(status) { return Some(0); }
    nt_fs::directory_record_count(usize::try_from(information).ok()?, read)
}

/// An inline completion: `output` is exactly the bytes delivered to the caller.
pub(crate) fn complete_inline(file_id: u64, pi: u32, class: u32, output: &[u8], status: u32, information: u64) {
    if !budget_left() || !mounted_file(file_id) { return; }
    let entries = delivered_entries(status, information, |offset| {
        output.get(offset..offset.checked_add(4)?)
            .map(|field| u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
    });
    report(b"inline", pi, Some(class), entries, status, information);
}

/// A retained Pending completion after its IOSB is published. The exact completed IRP still
/// owns its output, so records are read from it rather than from caller memory.
pub(crate) unsafe fn complete_pending(file_id: u64, pi: u32, irp_id: u64, status: u32, information: u64) {
    let class = take_pending_class(irp_id);
    if !budget_left() || !mounted_file(file_id) { return; }
    let entries = delivered_entries(status, information, |offset| {
        let mut field = [0u8; 4];
        match unsafe { driver_launch::copy_completed_irp_output_exact(irp_id, offset as u64, &mut field) } {
            Ok(4) => Some(u32::from_le_bytes(field)),
            _ => None,
        }
    });
    report(b"pending", pi, class, entries, status, information);
}
