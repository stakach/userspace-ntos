//! A retained process-image read may be ready while a nested provider pump keeps the outer
//! service loop parked. The timer may announce that readiness once; it cannot redrive the
//! retained owner or repeatedly count the same deadline as fresh work.

const SNAPSHOT: &str = include_str!("../../../components/ntos-executive/src/process_image_snapshot_work.rs");
const TIMER: &str = include_str!("../../../components/ntos-executive/src/timer_deadline.rs");
const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");

fn body<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).unwrap_or_else(|| panic!("missing {start}"));
    let rest = &source[start..];
    &rest[..rest.find(end).unwrap_or_else(|| panic!("missing {end}"))]
}

#[test]
fn retained_process_image_timer_announces_once_until_outer_redrive() {
    let deadline = body(SNAPSHOT, "pub(crate) fn next_deadline()", "/// Periodic read-only census");
    let wake = body(SNAPSHOT, "pub(crate) fn wake_due(", "enum Step");
    let redrive = body(SNAPSHOT, "pub(crate) unsafe fn redrive(", "unsafe fn advance(");

    assert!(SNAPSHOT.contains("nt_time::CoalescedRetryWake::new()"),
        "a retained image snapshot needs the same one-shot timer owner as Section metadata");
    assert!(deadline.contains("WAKE.next_deadline("),
        "the timer must not keep advertising an already delivered deadline");
    assert!(wake.contains("WAKE.wake_due("),
        "the due event must publish readiness only once while the outer owner is blocked");
    assert!(redrive.contains("WAKE.begin_redrive(") && redrive.contains("retry_at("),
        "only the outer owner may schedule another retry after attempting the retained work");
    assert!(!SNAPSHOT.contains("static NEXT:") && !redrive.contains("NEXT.store("),
        "remove the old unconditional deadline that remained due in nested pumps");
}

#[test]
fn new_image_publication_rearms_without_replaying_a_retained_reply() {
    let submit = body(SNAPSHOT, "pub(crate) unsafe fn submit_routed_process_image(",
        "pub(crate) fn take_transferred()");
    assert!(submit.contains("WAKE.publish("),
        "a new process image owner must publish its own wake before leaving the syscall");
    assert!(TIMER.contains("process_image_snapshot_work::next_deadline()"));
    assert!(MAIN.contains("process_image_snapshot_work::wake_due(now_100ns)"));
    assert!(SNAPSHOT.contains("REPLY_MAIN_SLOT.load(Ordering::Relaxed)"),
        "the work still retains its original physical Reply");
}
