//! A cancelled native file target lookup retains its Reply until cancellation is proven.

const WORK: &str = include_str!("../../../components/ntos-executive/src/native_file_target_open_work.rs");

#[test]
fn teardown_never_replies_through_an_uncertain_or_cancelled_reply() {
    let step = WORK.split_once("unsafe fn step(").unwrap().1
        .split_once("pub(crate) unsafe fn redrive(").unwrap().0;
    let abandoned = step.split_once("\n    match phase {").unwrap().0;
    assert!(abandoned.contains("if work.abandoned {")
        && abandoned.contains("return settle_abandoned_reply(handler, work);"),
        "abandoned lookup must settle cancellation before any ordinary reply path");

    let settle = WORK.split_once("unsafe fn settle_abandoned_reply(").unwrap().1
        .split_once("unsafe fn terminal(").unwrap().0;
    assert!(settle.contains("finish_acknowledged_hosted_reply")
        && settle.contains("Phase::Quarantined")
        && settle.contains("work.reference.release")
        && settle.contains("work.reply = 0"),
        "saved Reply and caller reference must retire only after hosted ACK or proven cancellation");
    assert!(!settle.contains("reply_parked_syscall"),
        "teardown cannot replay a Reply after uncertain cancellation");
}
