//! First-sighting budgets for steady per-event diagnostic streams.
//!
//! Each serial byte costs the root tens of thousands of TSC ticks, and these streams print the
//! same success line on every user callback, every win32k callback and every callback pump.
//! A line is reported the first time its shape is seen; later identical shapes are counted.
//! Callers pass only the stable fields of a success line. Any line that reports a failure, an
//! anomaly or a non-success status bypasses this filter and always prints.
//!
//! Root only: an isolated service maps this image read-only, so off the root executor every
//! line prints exactly as before.

use crate::diagnostic_repeat_filter::{fingerprint, RepeatReceipts};
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum Stream { UserCallback, Win32kInitPhase, CallbackPumpStage }

const NAMES: [&str; 3] = ["user-callback", "win32k-init-phase", "callback-pump-stage"];

static RECEIPTS: [RepeatReceipts; NAMES.len()] = [const { RepeatReceipts::new() }; NAMES.len()];
/// `[mounted-receive]` samples beyond their per-IRP budget.
static MOUNTED_RECEIVE_SUPPRESSED: AtomicU64 = AtomicU64::new(0);

/// Whether this success line, identified by its stable `shape`, should print.
pub(crate) fn admit(stream: Stream, shape: &[&[u8]]) -> bool {
    if !crate::serial_records::is_root_executor() { return true; }
    let mut fields = [&[][..]; 8];
    let site = (stream as u64).to_le_bytes();
    fields[0] = &site;
    let count = shape.len().min(fields.len() - 1);
    fields[1..=count].copy_from_slice(&shape[..count]);
    RECEIPTS[stream as usize]
        .admit(fingerprint(&fields[..=count]), crate::diagnostic_time_100ns)
        .is_some()
}

pub(crate) fn note_mounted_receive_suppressed() {
    MOUNTED_RECEIVE_SUPPRESSED.fetch_add(1, Ordering::Relaxed);
}

/// `name=first/repeats/untracked/untracked-suppressed` per stream.
pub(crate) fn print_census() {
    if !crate::serial_records::is_root_executor() { return; }
    use core::fmt::Write;
    let mut record = nt_printf::record::RecordBuffer::<256>::new();
    let _ = write!(record, "[census] steady-trace first/repeats/untracked/untracked-suppressed:");
    for (name, receipts) in NAMES.iter().zip(&RECEIPTS) {
        let _ = write!(record, " {name}=");
        let _ = receipts.write_counts(&mut record);
    }
    let _ = writeln!(record, " mounted-receive-suppressed={}",
        MOUNTED_RECEIVE_SUPPRESSED.load(Ordering::Relaxed));
    crate::print_str(record.bytes());
}
