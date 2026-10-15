use nt_io_manager::hosted_forward_progress::{HostedForwardInlineHold, InlineHoldPhase};

#[test]
fn held_ack_is_not_terminal_and_never_authorizes_completion_replay() {
    let mut hold = HostedForwardInlineHold::new(41).unwrap();
    assert_eq!(hold.phase(), InlineHoldPhase::Unreported);
    assert!(!hold.retirement_ready(true, false));
    assert!(!hold.retire(41, true, false));
    assert!(hold.report_held(41));
    assert_eq!(hold.phase(), InlineHoldPhase::Held);
    assert!(!hold.retirement_ready(false, false));
    assert!(!hold.retire(41, false, false));
    assert_eq!(hold.phase(), InlineHoldPhase::Held);
    assert!(!hold.report_held(41), "the already-executed unwind cannot be re-admitted");
}

#[test]
fn later_genuine_terminal_receipt_retires_exactly_once() {
    let mut hold = HostedForwardInlineHold::new(53).unwrap();
    assert!(hold.report_held(53));
    assert!(hold.retirement_ready(true, false));
    assert!(hold.retire(53, true, false));
    assert_eq!(hold.phase(), InlineHoldPhase::Retired);
    assert!(!hold.retirement_ready(true, false));
    assert!(!hold.retire(53, true, false));
    assert!(!hold.report_held(53));
}

#[test]
fn zero_foreign_and_duplicate_tokens_never_mutate_the_phase() {
    assert!(HostedForwardInlineHold::new(0).is_none());
    let mut hold = HostedForwardInlineHold::new(67).unwrap();
    assert!(!hold.report_held(0));
    assert!(!hold.report_held(68));
    assert_eq!(hold.phase(), InlineHoldPhase::Unreported);
    assert!(hold.report_held(67));
    assert!(!hold.report_held(67));
    assert!(!hold.retire(68, true, false));
    assert_eq!(hold.phase(), InlineHoldPhase::Held);
    assert!(hold.retire(67, true, false));
}

#[test]
fn authenticated_stop_can_settle_held_owner_without_inventing_terminal_completion() {
    let mut hold = HostedForwardInlineHold::new(79).unwrap();
    assert!(hold.report_held(79));
    assert!(hold.retirement_ready(false, true));
    assert!(hold.retire(79, false, true));
    assert_eq!(hold.phase(), InlineHoldPhase::Retired);
    assert!(!hold.retire(79, true, true));
}
