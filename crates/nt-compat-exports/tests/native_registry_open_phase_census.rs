//! Exercise the actual native NtOpenKey/NtOpenKeyEx phase census (#348).
use std::sync::Mutex;

static OUTPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
fn print_str(bytes: &[u8]) { OUTPUT.lock().unwrap().extend_from_slice(bytes); }
fn disk_census_ticks() -> u64 { 0 }

#[path = "../../../components/ntos-executive/src/registry_open_phase_census.rs"]
mod census;

use census::{OpenPhaseCensus, OpenPhaseClock};

const M: u64 = 1_000_000;

#[test]
fn each_phase_owns_the_time_up_to_its_end_and_a_failed_phase_up_to_the_failure() {
    let census = OpenPhaseCensus::new();
    // A hit: capture 1M, target 3M, grant 1M, publish 2M, epilogue 1M.
    let mut hit = OpenPhaseClock::start(0);
    hit.captured(M);
    hit.target_bound(4 * M);
    hit.granted(5 * M);
    hit.published(7 * M);
    hit.settled(7 * M);
    census.record(&hit, 0, 8 * M);
    // A miss: the target lookup fails after 2M; its epilogue (diagnostics, rollback) is 5M.
    let mut miss = OpenPhaseClock::start(10 * M);
    miss.captured(11 * M);
    miss.settled(13 * M);
    census.record(&miss, 0xc000_0034, 18 * M);
    // A capture failure owns only capture and epilogue time.
    let mut refused = OpenPhaseClock::start(20 * M);
    refused.settled(24 * M);
    census.record(&refused, 0xc000_0005, 25 * M);

    let mut line = nt_printf::record::RecordBuffer::<256>::new();
    census.write_census(&mut line).unwrap();
    assert_eq!(std::str::from_utf8(line.bytes()).unwrap(),
        "[census] registry-open-phase ok/err=calls/capture/target/grant/publish/epilogue-Mtick: \
         ok=1/1/3/1/2/1 err=2/5/2/0/0/6\n");
    census::print_census();
    assert!(OUTPUT.lock().unwrap().starts_with(b"[census] registry-open-phase"));
}

#[test]
fn capture_steps_are_split_at_their_marks() {
    let capture = census::CaptureCensus::new();
    let mut clock = census::CaptureClock::start(0);
    for (step, at) in [1, 3, 6, 10, 11, 13].into_iter().enumerate() {
        clock.mark(step, at * M);
    }
    capture.record(&clock);
    let mut line = nt_printf::record::RecordBuffer::<256>::new();
    capture.write_census(&mut line).unwrap();
    assert_eq!(std::str::from_utf8(line.bytes()).unwrap(),
        "[census] registry-capture-phase calls/attributes/caller/name/subject/reserve/canon-Mtick=1/1/2/3/4/1/2\n");
}
