//! Exercise the actual native hot-service latency census with real NT service identities.
use nt_syscall::NativeService;
use std::sync::Mutex;

static OUTPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());
fn print_str(bytes: &[u8]) { OUTPUT.lock().unwrap().extend_from_slice(bytes); }
fn disk_census_ticks() -> u64 { 0 }
fn root_idle_receive_ticks() -> u64 { 0 }
mod serial_records { pub fn is_root_executor() -> bool { true } }

#[allow(dead_code)] // The root glue is exercised only through its census print.
#[path = "../../../components/ntos-executive/src/hot_service_latency_census.rs"]
mod census;

const EXPLORER: u64 = 45;
const OTHER: u64 = 30;

#[test]
fn a_call_is_split_into_ingress_handler_tail_and_return() {
    let mut latency = census::LatencyCensus::new();
    // Root received Explorer's Call at 100, dispatched 110..150, replied at 180 with 1,000
    // idle ticks so far; Explorer's next Call arrived at 400 after 120 more idle ticks.
    latency.ingress(EXPLORER, 100, 1_000);
    latency.dispatch_started(EXPLORER, Some(NativeService::NtOpenKeyEx), 110);
    latency.dispatch_finished(150);
    latency.replying(EXPLORER, 180, 1_000);
    latency.ingress(OTHER, 250, 1_060);
    latency.ingress(EXPLORER, 400, 1_120);
    let row = latency.latency(NativeService::NtOpenKeyEx).unwrap();
    assert_eq!(row, census::Latency { calls: 1, ingress: 10, handler: 40, tail: 30,
        returns: 1, return_idle: 120, return_other: 100 });
}

#[test]
fn unobserved_boundaries_are_not_counted() {
    let mut latency = census::LatencyCensus::new();
    // A dispatch whose ingress came from another badge, a cold service, a reply for another
    // badge, and a parked call replaced by the next dispatch are not attributed.
    latency.ingress(OTHER, 1, 0);
    latency.dispatch_started(EXPLORER, Some(NativeService::NtReadFile), 2);
    latency.dispatch_finished(3);
    latency.replying(EXPLORER, 4, 0);
    latency.ingress(EXPLORER, 5, 0);
    latency.dispatch_started(EXPLORER, Some(NativeService::NtCreateProcess), 6);
    latency.dispatch_finished(7);
    latency.replying(EXPLORER, 8, 0);
    latency.ingress(EXPLORER, 9, 0);
    latency.dispatch_started(EXPLORER, Some(NativeService::NtReadFile), 10);
    latency.dispatch_finished(11);
    latency.replying(OTHER, 12, 0);
    latency.ingress(EXPLORER, 13, 0);
    latency.dispatch_started(EXPLORER, Some(NativeService::NtReadFile), 14);
    latency.ingress(OTHER, 15, 0);
    latency.dispatch_started(OTHER, Some(NativeService::NtWriteFile), 16);
    latency.dispatch_finished(17);
    latency.replying(OTHER, 18, 0);
    // An out-of-table badge is measured for its call but has no return slot.
    latency.ingress(u64::MAX, 20, 0);
    latency.dispatch_started(u64::MAX, Some(NativeService::NtWriteFile), 21);
    latency.dispatch_finished(22);
    latency.replying(u64::MAX, 23, 0);
    latency.ingress(u64::MAX, 30, 0);
    assert_eq!(latency.latency(NativeService::NtReadFile).unwrap(), census::Latency::default());
    let write = latency.latency(NativeService::NtWriteFile).unwrap();
    assert_eq!((write.calls, write.returns), (2, 0));
    assert!(latency.latency(NativeService::NtCreateProcess).is_none());
}

#[test]
fn census_is_one_bounded_record() {
    let mut latency = census::LatencyCensus::new();
    latency.ingress(EXPLORER, 0, 0);
    latency.dispatch_started(EXPLORER, Some(NativeService::NtQueryValueKey), 1_000_000);
    latency.dispatch_finished(3_000_000);
    latency.replying(EXPLORER, 4_000_000, 0);
    latency.ingress(EXPLORER, 20_000_000, 5_000_000);
    let mut line = nt_printf::record::RecordBuffer::<1024>::new();
    latency.write_census(&mut line).unwrap();
    let line = std::str::from_utf8(line.bytes()).unwrap();
    assert!(line.starts_with("[census] hot-service-latency calls/ingress/handler/tail/returns/return-idle/return-other-Mtick:"));
    assert!(line.contains(" query-value=1/1/2/1/1/5/11 "), "{line}");
    assert!(line.ends_with(" create-key=0/0/0/0/0/0/0\n"), "{line}");
    census::print_census();
    assert!(String::from_utf8(OUTPUT.lock().unwrap().clone()).unwrap()
        .starts_with("[census] hot-service-latency"));
}
