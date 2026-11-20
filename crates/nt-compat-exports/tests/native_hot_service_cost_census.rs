//! Exercise the actual native hot-service cost census with real NT service identities.
use nt_syscall::NativeService;
use std::sync::Mutex;

static OUTPUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

fn print_str(bytes: &[u8]) {
    OUTPUT.lock().unwrap().extend_from_slice(bytes);
}

#[path = "../../../components/ntos-executive/src/hot_service_cost_census.rs"]
mod census;

const MISS: u32 = 0xc000_0034;

#[test]
fn errors_and_completions_are_costed_separately_with_their_serial_bytes() {
    let mut cost = census::HotServiceCost::new();
    cost.record(Some(NativeService::NtOpenKeyEx), 0, 2_000_000, 0);
    cost.record(Some(NativeService::NtOpenKeyEx), MISS, 6_000_000, 180);
    cost.record(Some(NativeService::NtOpenKeyEx), MISS, 4_000_000, 20);
    cost.record(Some(NativeService::NtReadFile), 0x103, 9_000_000, 7);
    // Warnings (0x8...) are not NT_ERROR; services outside the hot set are not counted.
    cost.record(Some(NativeService::NtReadFile), 0x8000_0005, 1_000_000, 0);
    cost.record(Some(NativeService::NtCreateProcess), MISS, 1, 1);
    cost.record(None, MISS, 1, 1);

    let open = cost.cost(NativeService::NtOpenKeyEx).unwrap();
    assert_eq!((open.completed.calls, open.completed.ticks, open.completed.serial_bytes),
        (1, 2_000_000, 0));
    assert_eq!((open.failed.calls, open.failed.ticks, open.failed.serial_bytes),
        (2, 10_000_000, 200));
    let read = cost.cost(NativeService::NtReadFile).unwrap();
    assert_eq!((read.completed.calls, read.completed.serial_bytes, read.failed.calls), (2, 7, 0));
    assert!(cost.cost(NativeService::NtCreateProcess).is_none());

    let mut line = nt_printf::record::RecordBuffer::<1024>::new();
    cost.write_census(&mut line).unwrap();
    let line = std::str::from_utf8(line.bytes()).unwrap();
    assert!(line.starts_with("[census] hot-service-cost ok/err=calls/Mtick/serial-bytes:"));
    assert!(line.contains(" open-key-ex=1/2/0:2/10/200 "), "{line}");
    assert!(line.contains(" read=2/10/7:0/0/0 "), "{line}");
    assert!(line.ends_with(" close=0/0/0:0/0/0\n"), "{line}");
    assert_eq!(line.lines().count(), 1);
}

#[test]
fn saturated_counters_still_fit_one_record() {
    let mut cost = census::HotServiceCost::new();
    for service in [NativeService::NtReadFile, NativeService::NtWriteFile,
        NativeService::NtOpenKey, NativeService::NtOpenKeyEx, NativeService::NtQueryValueKey,
        NativeService::NtCreateKey, NativeService::NtRemoveIoCompletion, NativeService::NtClose] {
        for status in [0, MISS] {
            cost.record(Some(service), status, u64::MAX, u64::MAX);
            cost.record(Some(service), status, u64::MAX, u64::MAX);
        }
    }
    let mut line = nt_printf::record::RecordBuffer::<1024>::new();
    cost.write_census(&mut line).unwrap();
    assert!(!line.overflowed());
    census::record_dispatch(Some(NativeService::NtClose), MISS, 3_000_000, 5);
    census::print_census();
    let printed = String::from_utf8(OUTPUT.lock().unwrap().clone()).unwrap();
    assert!(printed.starts_with("[census] hot-service-cost") && printed.ends_with('\n'));
    assert!(printed.ends_with(" close=0/0/0:1/3/5\n"), "{printed}");
}

/// Boot 44604646550: the tray thread issued ~714k NtWaitForMultipleObjects calls, each
/// returning within ~30 us. Which status they return decides between a stale signal, an
/// invalid queue-event handle and a mis-converted timeout.
#[test]
fn immediate_wait_statuses_are_counted_by_exact_value() {
    let mut waits = census::WaitStatusCensus::new();
    for _ in 0..5 { waits.record(Some(NativeService::NtWaitForMultipleObjects), 0x1); }
    for _ in 0..3 { waits.record(Some(NativeService::NtWaitForMultipleObjects), 0xc000_0008); }
    waits.record(Some(NativeService::NtWaitForMultipleObjects), 0x102);
    waits.record(Some(NativeService::NtReadFile), 0xc000_0008);
    waits.record(None, 0);
    let mut line = nt_printf::record::RecordBuffer::<512>::new();
    waits.write_census(&mut line).unwrap();
    let line = std::str::from_utf8(line.bytes()).unwrap();
    assert_eq!(line,
        "[census] wait-multiple-status calls=9 0x00000001=5 0xc0000008=3 0x00000102=1\n");
}
