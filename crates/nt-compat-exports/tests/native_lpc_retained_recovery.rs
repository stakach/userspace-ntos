//! LPC parked Calls retain their exact Reply across uncertain delivery and cancellation.

const TABLES: &str = include_str!("../../../crates/nt-lpc-continuation/src/lib.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const HANDLER: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source.split_once(start).expect("start boundary").1
        .split_once(end).expect("end boundary").0
}

#[test]
fn receive_and_request_tables_record_terminal_and_cancel_entry_before_native_effects() {
    let receive = section(TABLES, "pub struct ReceiveWaitTable<C>", "pub enum ConnectOperation");
    let request = section(TABLES, "pub struct RequestWaitTable<C>", "pub struct ConnectWaitTable");
    for table in [receive, request] {
        assert!(table.contains("begin_reply("));
        assert!(table.contains("finish_reply("));
        assert!(table.contains("begin_cancel("));
        assert!(table.contains("finish_cancel("));
    }
}

#[test]
fn redrive_and_abandon_never_take_a_waiter_before_reply_or_cancel_proof() {
    let receive = section(SERVICE, "unsafe fn lpc_receive_wait_redrive_all(", "pub(crate) unsafe fn lpc_endpoint_redrive_all(");
    let request = section(SERVICE, "unsafe fn lpc_request_wait_redrive_all(", "unsafe fn lpc_connect_wait_complete(");
    let abandon_receive = section(SERVICE, "pub(crate) unsafe fn lpc_receive_wait_abandon_thread(", "pub(crate) unsafe fn lpc_connect_wait_abandon_thread(");
    let abandon_request = section(SERVICE, "pub(crate) unsafe fn lpc_request_wait_abandon_thread(", "unsafe fn io_completion_park(");
    for body in [receive, request, abandon_receive, abandon_request] {
        assert!(!body.contains(".take(slot)"), "the exact Reply must stay in its table until proof");
    }
}

#[test]
fn process_retirement_checks_exact_lpc_waiters_before_reclaiming_layout() {
    let retirement = HANDLER.split_once("fn try_delete_hosted_process_object_exact(")
        .expect("exact process retirement").1;
    assert!(retirement.contains("lpc_wait_dependents_quiescent_exact"));
    assert!(SERVICE.contains("wait.continuation.process == process"));
}

#[test]
fn uncertain_hosted_reply_requires_one_physical_stop_before_retirement() {
    let receive = section(SERVICE, "pub(crate) unsafe fn lpc_receive_wait_abandon_thread(", "pub(crate) unsafe fn lpc_connect_wait_abandon_thread(");
    let request = section(SERVICE, "pub(crate) unsafe fn lpc_request_wait_abandon_thread(", "unsafe fn io_completion_park(");
    for body in [receive, request] {
        assert!(body.contains("begin_reconcile_stop(slot)"));
        assert!(body.contains("stop_and_cancel_hosted(cap)"));
        assert!(body.contains("finish_reconcile_stop(ticket, cancelled)"));
        assert!(body.contains("owns_hosted_reply(cap)"));
    }
}
