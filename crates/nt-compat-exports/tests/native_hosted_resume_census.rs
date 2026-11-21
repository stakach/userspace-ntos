//! Exercise the actual hosted-resume census arithmetic.
use std::sync::Mutex;

static OUTPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
fn print_str(bytes: &[u8]) { OUTPUT.lock().unwrap().extend_from_slice(bytes); }
fn disk_census_ticks() -> u64 { 0 }
fn root_dispatch_receive_ticks() -> u64 { 0 }
mod serial_records { pub fn is_root_executor() -> bool { true } }

#[allow(dead_code)] // The root glue is exercised only through its census print.
#[path = "../../../components/ntos-executive/src/hosted_resume_census.rs"]
mod census;

use census::{Kind, Marks, ResumeCensus, ResumeCost};

#[test]
fn a_resume_splits_into_claim_pump_blocked_and_settle() {
    let mut resumes = ResumeCensus::new();
    // Entered at 100, pumped 130..1_130 with the root blocked for 700 of it, returned at 1_150.
    resumes.record(Marks { entered: 100, pump: Some((Kind::Provider, 130, 5_000)),
        pumped: Some((1_130, 5_700)) }, 1_150);
    assert_eq!(resumes.cost(Kind::Provider),
        ResumeCost { resumes: 1, claim: 30, pump: 1_000, blocked: 700, settle: 20 });
}

#[test]
fn a_resume_refused_before_its_pump_is_not_counted() {
    let mut resumes = ResumeCensus::new();
    resumes.record(Marks { entered: 100, pump: None, pumped: None }, 120);
    resumes.record(Marks { entered: 100, pump: Some((Kind::Lpc, 110, 0)), pumped: None }, 130);
    assert_eq!(resumes.cost(Kind::Provider), ResumeCost::default());
    assert_eq!(resumes.cost(Kind::Lpc), ResumeCost::default());
}

#[test]
fn blocked_time_never_exceeds_the_pump() {
    // A nested resume's receive time is also counted by its own record; clamp to this pump.
    let mut resumes = ResumeCensus::new();
    resumes.record(Marks { entered: 0, pump: Some((Kind::ServiceWait, 0, 0)),
        pumped: Some((50, 80)) }, 50);
    assert_eq!(resumes.cost(Kind::ServiceWait).blocked, 50);
}

#[test]
fn the_census_names_only_kinds_that_resumed() {
    let mut resumes = ResumeCensus::new();
    resumes.record(Marks { entered: 0, pump: Some((Kind::Provider, 1_000_000, 0)),
        pumped: Some((4_000_000, 2_000_000)) }, 5_000_000);
    let mut out = String::new();
    resumes.write_census(&mut out).unwrap();
    assert_eq!(out, "[census] hosted-resume resumes/claim/pump/blocked/settle-Mtick: \
        provider=1/1/3/2/1\n");
}
