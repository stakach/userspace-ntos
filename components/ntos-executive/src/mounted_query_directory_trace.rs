//! Bounded serial evidence for mounted-volume directory queries.
//!
//! One marker per completed native NtQueryDirectoryFile on a File of the live mounted volume,
//! inline or retained Pending, reporting the status and Information written to the caller's
//! IOSB and the record count of the delivered bytes. A pending query carries its information
//! class here, keyed by its exact IRP; this metadata never influences delivery.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::{driver_launch, mounted_volume, print_hex, print_str, print_u64, MAX_PI};

const MARKER_BUDGET: u32 = 32;
// Keep sampled late desktop queries separate from the earlier boot's global markers even if
// some of those IRPs are still retained when an interactive child starts.
const PENDING_SLOTS: usize = 128;
const NO_CLASS: u32 = u32::MAX;

static MARKERS: AtomicU32 = AtomicU32::new(0);
const PATTERN_BUDGET_PER_GENERATION: u32 = 8;
static PATTERN_GENERATIONS: [AtomicU64; MAX_PI] = [const { AtomicU64::new(0) }; MAX_PI];
static PATTERN_COUNTS: [AtomicU32; MAX_PI] = [const { AtomicU32::new(0) }; MAX_PI];
static PENDING_IRPS: [AtomicU64; PENDING_SLOTS] = [const { AtomicU64::new(0) }; PENDING_SLOTS];
static PENDING_CLASSES: [AtomicU32; PENDING_SLOTS] = [const { AtomicU32::new(NO_CLASS) }; PENDING_SLOTS];
static PENDING_TRACED: [AtomicU32; PENDING_SLOTS] = [const { AtomicU32::new(0) }; PENDING_SLOTS];

/// Sample named FindFirst-style queries for each exact process generation. The older global
/// completion budget is usually exhausted long before an interactive desktop child runs.
pub(crate) fn sample_patterned(pi: usize, generation: Option<u64>, class: u32, named: bool) -> bool {
    if class != nt_fs::FILE_BOTH_DIRECTORY_INFORMATION || !named || pi >= MAX_PI { return false; }
    let Some(generation) = generation.filter(|value| *value != 0) else { return false; };
    if PATTERN_GENERATIONS[pi].load(Ordering::Acquire) != generation {
        PATTERN_COUNTS[pi].store(0, Ordering::Release);
        PATTERN_GENERATIONS[pi].store(generation, Ordering::Release);
    }
    PATTERN_COUNTS[pi].fetch_add(1, Ordering::Relaxed) < PATTERN_BUDGET_PER_GENERATION
}

pub(crate) fn patterned_stage(
    stage: &[u8], pi: usize, generation: Option<u64>, handle: u64,
    pattern: Option<&[u16]>, status: Option<u32>, information: u64, irp: u64,
) {
    print_str(b"[patterned-query] stage="); print_str(stage);
    print_str(b" pi="); print_u64(pi as u64);
    print_str(b" generation="); print_u64(generation.unwrap_or(0));
    print_str(b" handle=0x"); crate::print_hex_u64(handle);
    print_str(b" pattern=\"");
    for &unit in pattern.unwrap_or(&[]).iter().take(64) {
        crate::debug_put_char(if (0x20..0x7f).contains(&unit) { unit as u8 } else { b'?' });
    }
    print_str(b"\" status=0x"); print_hex(status.unwrap_or(u32::MAX));
    print_str(b" info="); print_u64(information);
    print_str(b" irp="); print_u64(irp);
    print_str(b"\n");
}

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
pub(crate) fn pending(file_id: u64, irp_id: u64, class: u32, traced: bool) {
    if irp_id == 0 || (!budget_left() && !traced) || !mounted_file(file_id) { return; }
    for ((irp, slot_class), slot_traced) in PENDING_IRPS.iter().zip(&PENDING_CLASSES).zip(&PENDING_TRACED) {
        if irp.compare_exchange(0, irp_id, Ordering::AcqRel, Ordering::Acquire).is_ok() {
            slot_class.store(class, Ordering::Release);
            slot_traced.store(u32::from(traced), Ordering::Release);
            return;
        }
    }
}

fn take_pending_class(irp_id: u64) -> Option<(u32, bool)> {
    PENDING_IRPS.iter().zip(&PENDING_CLASSES).zip(&PENDING_TRACED).find_map(|((irp, class), traced)| {
        (irp.load(Ordering::Acquire) == irp_id).then(|| {
            let value = class.swap(NO_CLASS, Ordering::AcqRel);
            let was_traced = traced.swap(0, Ordering::AcqRel) != 0;
            irp.store(0, Ordering::Release);
            (value, was_traced)
        })
    })
}

fn report(path: &[u8], pi: u32, class: Option<u32>, entries: Option<usize>, status: u32, information: u64, forced: bool) {
    if !forced && MARKERS.fetch_add(1, Ordering::Relaxed) >= MARKER_BUDGET { return; }
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
pub(crate) fn complete_inline(file_id: u64, pi: u32, class: u32, output: &[u8], status: u32, information: u64, traced: bool) {
    if (!budget_left() && !traced) || !mounted_file(file_id) { return; }
    let entries = delivered_entries(status, information, |offset| {
        output.get(offset..offset.checked_add(4)?)
            .map(|field| u32::from_le_bytes([field[0], field[1], field[2], field[3]]))
    });
    report(b"inline", pi, Some(class), entries, status, information, traced);
}

/// A retained Pending completion after its IOSB is published. The exact completed IRP still
/// owns its output, so records are read from it rather than from caller memory.
pub(crate) unsafe fn complete_pending(file_id: u64, pi: u32, irp_id: u64, status: u32, information: u64) {
    let recorded = take_pending_class(irp_id);
    let traced = recorded.is_some_and(|(_, traced)| traced);
    if (!budget_left() && !traced) || !mounted_file(file_id) { return; }
    let entries = delivered_entries(status, information, |offset| {
        let mut field = [0u8; 4];
        match unsafe { driver_launch::copy_completed_irp_output_exact(irp_id, offset as u64, &mut field) } {
            Ok(4) => Some(u32::from_le_bytes(field)),
            _ => None,
        }
    });
    report(b"pending", pi, recorded.map(|(class, _)| class), entries, status, information, traced);
}
