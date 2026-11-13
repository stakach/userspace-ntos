//! A retired hosted runtime may still have an IOCP waiter or wake packet. The exact Reply and
//! port reference remain owned until cancellation or completion is physically established.

const COMPLETION: &str = include_str!("../../nt-io-completion/src/lib.rs");
const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const HANDLER: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .unwrap_or_else(|| panic!("missing source boundary {start}"))
        .1
        .split_once(end)
        .unwrap_or_else(|| panic!("missing source boundary {end}"))
        .0
}

#[test]
fn waiters_keep_process_generation_and_survive_refused_cancellation() {
    let waiter = between(COMPLETION, "pub struct CompletionWaiter {", "pub struct CompletionWaiterTable {");
    assert!(waiter.contains("ProcessIdentity"),
        "a PI alone cannot distinguish the retired process from its replacement");

    for (start, end, destructive) in [
        ("unsafe fn io_completion_cancel_thread(", "unsafe fn io_completion_cancel_process(", ".pop_thread("),
        ("unsafe fn io_completion_cancel_process(", "/// ═══ Checkpoint B", ".pop_process("),
    ] {
        let cancellation = between(MAIN, start, end);
        assert!(cancellation.contains("cancel_io_completion_reply_transport("));
        assert!(!cancellation.contains(destructive),
            "a failed or uncertain Stop must leave the waiter, Reply and port reference owned");
    }
    let transport = between(
        MAIN,
        "unsafe fn cancel_io_completion_reply_transport(",
        "/// ═══ Checkpoint B",
    );
    assert!(transport.contains("stop_and_cancel_hosted(cap)"));
    assert!(transport.contains("cancel_parked_reply_transport(cap)"));
}

#[test]
fn runtime_retirement_waits_for_exact_generation_io_completion_owners() {
    let deletion = between(
        HANDLER,
        "fn try_delete_hosted_process_object_exact(",
        "pub(crate) fn drain_hosted_process_deletion_candidates(",
    );
    let barrier = deletion.find("io_completion_dependents_quiescent_exact(")
        .expect("runtime retirement must inspect parked IOCP owners");
    let retirement = deletion.find("retire_dynamic_hosted_identity_attachments(")
        .expect("dynamic runtime retirement");
    assert!(barrier < retirement, "the owner barrier must precede runtime retirement");
    assert!(deletion[barrier..retirement].contains("candidate.generation"),
        "a PI-only census cannot authorize reuse after retirement");
}
