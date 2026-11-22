//! Exercise the actual steady diagnostic-stream budget: a success line prints once per shape,
//! repeats are counted, and each stream keeps its own fingerprints.
use std::sync::Mutex;

static OUTPUT: Mutex<String> = Mutex::new(String::new());

fn diagnostic_time_100ns() -> Option<u64> { None }
fn print_str(bytes: &[u8]) { OUTPUT.lock().unwrap().push_str(std::str::from_utf8(bytes).unwrap()); }
mod serial_records { pub fn is_root_executor() -> bool { true } }

#[path = "../../../components/ntos-executive/src/steady_trace.rs"]
mod steady_trace;
#[path = "../../../components/ntos-executive/src/diagnostic_receipt_budget.rs"]
mod diagnostic_receipt_budget;
#[path = "../../../components/ntos-executive/src/diagnostic_repeat_filter.rs"]
mod diagnostic_repeat_filter;

use steady_trace::{admit, Stream};

/// The only test using the global receipts, so the census counts are exact.
#[test]
fn each_shape_prints_once_and_repeats_are_counted() {
    // A user-callback round trip repeated 1,000 times prints each of its lines once.
    let mut printed = 0;
    for _ in 0..1000 {
        for line in [&b"parked"[..], b"completed", b"yielded"] {
            printed += usize::from(admit(Stream::UserCallback, &[line]));
        }
    }
    assert_eq!(printed, 3);

    // A distinct shape (another window message) is a first sighting of its own.
    assert!(admit(Stream::UserCallback, &[b"selected", &0u32.to_le_bytes(), &0x10u32.to_le_bytes()]));
    assert!(admit(Stream::UserCallback, &[b"selected", &0u32.to_le_bytes(), &0x81u32.to_le_bytes()]));
    assert!(!admit(Stream::UserCallback, &[b"selected", &0u32.to_le_bytes(), &0x10u32.to_le_bytes()]));

    // The same fields in another stream are not the same observation.
    assert!(admit(Stream::Win32kInitPhase, &[b"parked"]));
    assert!(admit(Stream::CallbackPumpStage, &[b"enter"]));
    assert!(!admit(Stream::CallbackPumpStage, &[b"enter"]));
    steady_trace::note_mounted_receive_suppressed();

    steady_trace::print_census();
    let output = std::mem::take(&mut *OUTPUT.lock().unwrap());
    assert_eq!(output, "[census] steady-trace first/repeats/untracked/untracked-suppressed: \
        user-callback=5/2998/0/0 win32k-init-phase=1/0/0/0 callback-pump-stage=1/1/0/0 \
        mounted-receive-suppressed=1\n");
}
