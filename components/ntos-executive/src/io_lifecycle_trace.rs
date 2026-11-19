//! Serial observations of IOCP remover parks and hosted File releases. Observation only:
//! callers perform the park or release and own its result before reporting it here.
//! A thread pool re-parks on one port and Files close with one normal shape thousands of
//! times; only the first sighting of each shape is printed, repeats are counted.
use crate::diagnostic_repeat_filter::{fingerprint, RepeatReceipts};
use core::fmt::Write;

static PARKS: RepeatReceipts = RepeatReceipts::new();
static RELEASES: RepeatReceipts = RepeatReceipts::new();

/// The hosted File shape before its release was queued.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FileReleaseShape {
    pub(crate) state: u64,
    pub(crate) irp_refs: u64,
    pub(crate) deferred: bool,
}

pub(crate) fn io_completion_park(pi: usize, port: u64) {
    if PARKS.admit(fingerprint(&[&(pi as u64).to_le_bytes(), &port.to_le_bytes()]),
        crate::diagnostic_time_100ns).is_none() { return; }
    let mut record = nt_printf::record::RecordBuffer::<96>::new();
    let _ = writeln!(record, "[io-completion] pi={pi} port={port} -> PARK remover");
    crate::print_str(record.bytes());
}

pub(crate) fn hosted_file_release(provenance: &[u8], file_id: u64,
    before: Option<FileReleaseShape>, status: u32) {
    // The File identity is reported, not part of the shape.
    let shape = before.map_or([u64::MAX; 3], |shape|
        [shape.state, shape.irp_refs, u64::from(shape.deferred)]);
    if RELEASES.admit(fingerprint(&[provenance, &shape[0].to_le_bytes(),
        &shape[1].to_le_bytes(), &shape[2].to_le_bytes(), &status.to_le_bytes()]),
        crate::diagnostic_time_100ns).is_none() { return; }
    let mut record = nt_printf::record::RecordBuffer::<256>::new();
    let _ = record.write_str("[hosted-file-release] owner=");
    record.push_bytes(provenance);
    let _ = write!(record, " file=0x0x{file_id:016x}");
    let _ = match before {
        Some(shape) => write!(record, " state=0x{:016x} irp-refs=0x{:016x} deferred=0x{:016x}",
            shape.state, shape.irp_refs, u64::from(shape.deferred)),
        None => record.write_str(" state=missing"),
    };
    let _ = writeln!(record, " status=0x0x{:016x}", u64::from(status));
    crate::print_str(record.bytes());
}

pub(crate) fn print_census() {
    let mut record = nt_printf::record::RecordBuffer::<192>::new();
    let _ = record.write_str(
        "[census] io-lifecycle-repeats first/repeats/untracked/untracked-suppressed: iocp-park=");
    let _ = PARKS.write_counts(&mut record);
    let _ = record.write_str(" file-release=");
    let _ = RELEASES.write_counts(&mut record);
    let _ = writeln!(record);
    crate::print_str(record.bytes());
}
