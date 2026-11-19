//! Exercise the actual native IOCP-park and hosted-File-release observers: a thread pool
//! re-parking on its port, or a process closing many Files with the same normal outcome, must
//! not pay for a serial record on every call (#348), while each distinct shape stays visible.
use std::sync::Mutex;

static OUTPUT: Mutex<String> = Mutex::new(String::new());

fn diagnostic_time_100ns() -> Option<u64> { None }
fn print_str(bytes: &[u8]) { OUTPUT.lock().unwrap().push_str(std::str::from_utf8(bytes).unwrap()); }

#[path = "../../../components/ntos-executive/src/io_lifecycle_trace.rs"]
mod io_lifecycle_trace;
#[path = "../../../components/ntos-executive/src/diagnostic_receipt_budget.rs"]
mod diagnostic_receipt_budget;
#[path = "../../../components/ntos-executive/src/diagnostic_repeat_filter.rs"]
mod diagnostic_repeat_filter;

use io_lifecycle_trace::FileReleaseShape;

fn take_output() -> String { std::mem::take(&mut *OUTPUT.lock().unwrap()) }

const CLOSED: FileReleaseShape = FileReleaseShape { state: 3, irp_refs: 0, deferred: false };

/// The only test using the global observers, so their counters and output are exact.
#[test]
fn repeated_parks_and_releases_emit_one_record_per_distinct_shape() {
    for _ in 0..1000 {
        io_lifecycle_trace::io_completion_park(12, 3);
    }
    io_lifecycle_trace::io_completion_park(9, 3);
    io_lifecycle_trace::io_completion_park(12, 0);
    let parks = take_output();
    assert_eq!(parks.lines().count(), 3, "one serial record per process/port: {parks}");
    assert_eq!(parks.lines().next().unwrap(), "[io-completion] pi=12 port=3 -> PARK remover");

    for file in 0..1000u64 {
        io_lifecycle_trace::hosted_file_release(b"final-handle", 0x100_0000_0000 + file,
            Some(CLOSED), 0);
    }
    // A different provenance, File shape, missing File or status is a distinct observation.
    io_lifecycle_trace::hosted_file_release(b"unpublished", 1, Some(CLOSED), 0);
    io_lifecycle_trace::hosted_file_release(b"final-handle", 2,
        Some(FileReleaseShape { irp_refs: 1, ..CLOSED }), 0);
    io_lifecycle_trace::hosted_file_release(b"final-handle", 3,
        Some(FileReleaseShape { deferred: true, ..CLOSED }), 0);
    io_lifecycle_trace::hosted_file_release(b"final-handle", 4, None, 0);
    io_lifecycle_trace::hosted_file_release(b"final-handle", 5, Some(CLOSED), 0xc000_0056);
    let releases = take_output();
    assert_eq!(releases.lines().count(), 6, "one serial record per release shape: {releases}");
    assert_eq!(releases.lines().next().unwrap(),
        "[hosted-file-release] owner=final-handle file=0x0x0000010000000000 \
         state=0x0000000000000003 irp-refs=0x0000000000000000 deferred=0x0000000000000000 \
         status=0x0x0000000000000000");
    assert!(releases.contains(" file=0x0x0000000000000004 state=missing status=0x0x"));
    assert!(releases.contains("status=0x0x00000000c0000056"));

    io_lifecycle_trace::print_census();
    assert_eq!(take_output(),
        "[census] io-lifecycle-repeats first/repeats/untracked/untracked-suppressed: \
         iocp-park=3/999/0/0 file-release=6/999/0/0\n");
}
