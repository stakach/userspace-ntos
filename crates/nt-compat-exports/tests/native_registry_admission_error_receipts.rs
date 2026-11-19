//! Exercise the actual native registry admission-error observer: a polling guest's repeated
//! miss must not pay for a serial record on every call (#348), while each distinct
//! observation, the repeat count and genuine security failures stay visible.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Mutex;

static OUTPUT: Mutex<String> = Mutex::new(String::new());
static CLOCK_AVAILABLE: AtomicBool = AtomicBool::new(false);
static CLOCK_100NS: AtomicU64 = AtomicU64::new(0);

fn diagnostic_time_100ns() -> Option<u64> {
    CLOCK_AVAILABLE.load(Ordering::Acquire).then(|| CLOCK_100NS.load(Ordering::Relaxed))
}
fn print_str(bytes: &[u8]) { OUTPUT.lock().unwrap().push_str(std::str::from_utf8(bytes).unwrap()); }
fn print_u64(value: u64) { print_str(value.to_string().as_bytes()); }
fn print_hex(value: u32) { print_str(format!("0x{value:08x}").as_bytes()); }

#[allow(dead_code)] // Only the admission-error observer is exercised here.
#[path = "../../../components/ntos-executive/src/registry_security_audit.rs"]
mod registry_security_audit;
#[path = "../../../components/ntos-executive/src/diagnostic_receipt_budget.rs"]
mod diagnostic_receipt_budget;
#[path = "../../../components/ntos-executive/src/diagnostic_repeat_filter.rs"]
mod diagnostic_repeat_filter;

const NOT_FOUND: u32 = 0xc000_0034;
const DEVICE_CLASS: &str =
    "\\registry\\machine\\system\\controlset001\\control\\deviceclasses\\{3e227e76-690d-11d2-8161-0000f8775bf1}";

fn take_output() -> String { std::mem::take(&mut *OUTPUT.lock().unwrap()) }

/// The only test using the global observer, so its counters and output are exact.
#[test]
fn repeated_miss_emits_one_record_and_counts_every_repeat() {
    for _ in 0..1000 {
        registry_security_audit::admission_error(b"open", DEVICE_CLASS, NOT_FOUND, 23, 640);
    }
    let output = take_output();
    assert_eq!(output.lines().count(), 1, "one serial record per distinct miss: {output}");
    assert!(output.contains("pi=23 tid=640 operation=open status=0xc0000034"));
    assert!(output.contains(DEVICE_CLASS));

    // A different process, operation, status or path is a distinct observation.
    registry_security_audit::admission_error(b"open", DEVICE_CLASS, NOT_FOUND, 22, 1);
    registry_security_audit::admission_error(b"create", DEVICE_CLASS, NOT_FOUND, 23, 640);
    registry_security_audit::admission_error(b"open", DEVICE_CLASS, 0xc000_003a, 23, 640);
    registry_security_audit::admission_error(b"open", "\\registry\\machine\\x", NOT_FOUND, 23, 640);
    // A different thread of the same process repeating the same miss is not.
    registry_security_audit::admission_error(b"open", DEVICE_CLASS, NOT_FOUND, 23, 644);
    // Statuses outside the observed set are neither printed nor counted.
    registry_security_audit::admission_error(b"open", DEVICE_CLASS, 0xc000_0022, 23, 640);
    assert_eq!(take_output().lines().count(), 4);

    registry_security_audit::print_admission_census();
    let census = take_output();
    assert_eq!(census,
        "[census] registry-admission-error first/repeats/untracked/untracked-suppressed=5/1000/0/0\n");

    // Exhaust the fixed fingerprint table: later distinct paths fall back to the bounded
    // receipt budget instead of either printing without bound or vanishing uncounted.
    for index in 0..4096 {
        let path = format!("\\registry\\machine\\software\\probe{index}");
        registry_security_audit::admission_error(b"open", &path, NOT_FOUND, 23, 640);
    }
    let output = take_output();
    registry_security_audit::print_admission_census();
    let census = take_output();
    let fields: Vec<u64> = census.trim_end().rsplit('=').next().unwrap()
        .split('/').map(|value| value.parse().unwrap()).collect();
    let (first, repeats, untracked, suppressed) = (fields[0], fields[1], fields[2], fields[3]);
    assert_eq!(repeats, 1000);
    assert_eq!(first + untracked, 5 + 4096, "every observation is accounted for: {census}");
    assert!(untracked > 0 && first <= diagnostic_repeat_filter::REPEAT_FILTER_SLOTS as u64);
    assert_eq!(suppressed, untracked.saturating_sub(diagnostic_receipt_budget::RECEIPT_LIMIT));
    assert_eq!(output.lines().count() as u64, (first - 5) + (untracked - suppressed));
    assert_eq!(output.matches("sighting=untracked").count() as u64, untracked - suppressed);
}

#[test]
fn fingerprints_delimit_fields() {
    use diagnostic_repeat_filter::fingerprint;
    assert_ne!(fingerprint(&[b"ab", b"c"]), fingerprint(&[b"a", b"bc"]));
    assert_ne!(fingerprint(&[]), 0);
    let filter = diagnostic_repeat_filter::RepeatFilter::new();
    use diagnostic_repeat_filter::Sighting::*;
    assert_eq!(filter.observe(0), First, "zero is not the empty-slot marker for callers");
    assert_eq!(filter.observe(0), Repeat);
    assert_eq!(filter.observe(7), First);
    assert_eq!(filter.counts(), diagnostic_repeat_filter::RepeatCounts {
        first: 2, repeats: 1, untracked: 0 });
}
