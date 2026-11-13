//! A previously parked native File CREATE Reply must not park the replacement main Reply again.

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const HANDOFF: &str = include_str!("../../../components/ntos-executive/src/file_dispatch_handoff.rs");
const PARK: &str = include_str!("../../../components/ntos-executive/src/parked_reply.rs");
const CALLER: &str = include_str!("../../../components/ntos-executive/src/pending_file_caller.rs");

#[test]
fn pending_file_handoff_accepts_one_validated_preparked_reply_without_a_second_park() {
    let transfer = SERVICE.split_once("unsafe fn pending_file_io_transfer(").unwrap().1
        .split_once("unsafe fn file_irp_drain_transfer(").unwrap().0;
    let preparked = transfer.find("if pending.reply_cap != 0")
        .expect("a prepared Reply needs an explicit transfer branch");
    assert!(transfer[..preparked].contains("if pending.reply_cap == 0 {\n        pending.native_call_transport = native_call_transport;"),
        "a timer redrive must preserve the original caller's native transport");
    let active = transfer.find("let stolen = REPLY_MAIN_SLOT.load")
        .expect("ordinary pending File calls still park the active Reply");
    assert!(preparked < active, "preparked ownership must be selected before the active Reply");
    let branch = &transfer[preparked..active];
    assert!(branch.contains("parked_reply::validate_saved(pending.reply_cap)"),
        "numeric capability equality is insufficient authority for a saved Reply");
    assert!(branch.contains("commit_or_panic") && branch.contains("return"),
        "the exact File owner must publish before bypassing the second RootReplyPark");
    assert!(!branch.contains("RootReplyPark::prepare"),
        "the replacement main Reply must remain available for the next ingress");
    assert!(PARK.contains("cap == REPLY_MAIN_SLOT.load(Ordering::Relaxed)"),
        "saved Reply validation must reject an alias of the current main Reply");
    assert!(HANDOFF.contains("pending_file_io_transfer("),
        "post-dispatch handoff must retain the existing exact File reservation");
    let finish = SERVICE.split_once("pub(crate) unsafe fn finish_preparked_file_target_dispatch(")
        .unwrap().1.split_once("fn checkpoint_boot_hives_at_quiesce").unwrap().0;
    assert!(finish.contains("pending.native_call_transport = native_call_transport;"),
        "the saved Reply's File owner must retain the original native transport");
    assert!(transfer.contains("crate::pending_file_caller::publish(reservation, pending)"),
        "the reply transfer must retain the caller captured before provider CREATE");
    assert!(CALLER.contains("get_reserved(identity.slot(), identity)"),
        "caller publication must reject a reused File owner generation");
}
