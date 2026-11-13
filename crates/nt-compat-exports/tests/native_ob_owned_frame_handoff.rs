//! A completed owned Object Manager effect releases its shared frame, not its logical owner.

#[path = "../../../components/ntos-executive/src/ring_channel_completion.rs"]
mod ring_channel_completion;

use ring_channel_completion::CompletionInbox;

const EXEC: &str = include_str!("../../../components/ntos-executive/src/main.rs");

#[test]
fn native_object_channel_drains_owned_terminal_before_borrowed_submission() {
    let raw_owned = EXEC.split("    fn raw_owned(\n").nth(1).expect("retained raw call");
    let raw_owned = raw_owned.split("    /// Submit one owned request").next().unwrap();
    assert!(raw_owned.contains("self.owned_capture = Some(core::mem::take(&mut self.raw_capture))"),
        "an uncertain synchronous effect needs its reserved payload for later exact polling");
    let raw = EXEC.split("    fn raw(&mut self, opcode: u16").nth(1).expect("SURT raw call");
    let raw = raw.split("    unsafe fn wait_completion_timer_aware").next().unwrap();
    let drain = raw.find("self.park_owned_terminal_before_raw()")
        .expect("owned terminal must be copied before a borrowed SQE");
    let begin = raw.find("self.completion_inbox.begin(id)").expect("borrowed frame admission");
    assert!(drain < begin);
    let poll = EXEC.split("    fn poll_owned(\n        &mut self,\n        request_id: u64").nth(1).expect("owned poll");
    let poll = poll.split("    /// One synchronous request/reply:").next().unwrap();
    assert!(poll.contains("take_parked_owned(request_id)"),
        "old owner must consume its terminal while another frame may be active");
    let submit = EXEC.split("    fn submit_owned(\n").nth(1).expect("owned SURT submit");
    let submit = submit.split("    fn copy_owned_terminal").next().unwrap();
    let reserve = submit.find("capture.try_reserve_exact(REP_DATA_LEN)")
        .expect("pre-SQ reply capacity reservation");
    let acquire = submit.find("completion_inbox.begin_owned(request_id)")
        .expect("owned frame lease");
    let publish = submit.find("self.sq.try_push(sqe)").expect("owned SQ publication");
    assert!(reserve < acquire && acquire < publish);
    assert!(raw.contains("raw_capture.try_reserve_exact(REP_DATA_LEN)"),
        "foreign reply bytes need reserved storage before the borrowed SQE");
    assert!(raw.contains("quarantine_unexpected("));
    assert!(!raw.contains("completion_inbox.accept("),
        "a mismatched CQE must not allocate or silently discard its bytes");
}

#[test]
fn owned_close_terminal_is_parked_before_a_borrowed_create_uses_the_frame() {
    let mut inbox = CompletionInbox::<([u8; 4], u64)>::new();
    assert!(inbox.begin(130));
    assert!(!inbox.begin(131));
    assert_eq!(inbox.park_active_owned(130, ([1, 2, 3, 4], 0x2012)), Ok(()));
    assert_eq!(inbox.active_request(), None);
    assert!(inbox.has_parked_owned());
    assert!(inbox.begin(131));
    assert_eq!(inbox.take_parked_owned(130), Some(([1, 2, 3, 4], 0x2012)));
    assert_eq!(inbox.take_parked_owned(130), None);
    assert!(!inbox.has_parked_owned());
    assert_eq!(inbox.active_request(), Some(131));
    assert!(!inbox.begin_owned(132),
        "a second owned effect cannot replace the unconsumed terminal");
    inbox.finish(131);
}

#[test]
fn wrong_or_reversed_receipt_cannot_release_the_owned_frame() {
    let mut inbox = CompletionInbox::<u64>::new();
    assert!(inbox.begin(130));
    assert_eq!(inbox.park_active_owned(131, 131), Err(131));
    assert_eq!(inbox.active_request(), Some(130));
    assert_eq!(inbox.take_parked_owned(131), None);
    assert_eq!(inbox.quarantine_unexpected(131, 0xdead), Ok(()));
    assert_eq!(inbox.quarantine_unexpected(132, 0xbeef), Err(0xbeef));
    assert_eq!(inbox.unexpected_receipt(), Some((131, &0xdead)));
    assert_eq!(inbox.active_request(), Some(130));
    assert_eq!(inbox.park_active_owned(130, 130), Err(130),
        "an unexplained earlier receipt must block frame reuse");
    assert!(!inbox.begin(132));
}

#[test]
fn second_owned_effect_cannot_replace_an_active_or_parked_owner() {
    let mut inbox = CompletionInbox::<u64>::new();
    assert!(inbox.begin_owned(130));
    assert!(!inbox.begin_owned(131));
    assert_eq!(inbox.active_request(), Some(130));
    assert_eq!(inbox.park_active_owned(130, 0x2012), Ok(()));
    assert!(!inbox.begin_owned(131));
    assert_eq!(inbox.take_parked_owned(130), Some(0x2012));
    assert!(inbox.begin_owned(131));
}
