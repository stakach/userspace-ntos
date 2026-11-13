//! Native File IRP drain never releases an unresolved parked Reply or its File reference.

const TABLE: &str = include_str!("../../../crates/nt-io-manager/src/cancel_wait.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const EXEC: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");

#[test]
fn file_irp_drain_retains_reply_until_acknowledged_terminal_delivery() {
    assert!(TABLE.contains("pub fn begin_reply_exact("));
    assert!(TABLE.contains("pub fn finish_reply_exact("));
    let drain = SERVICE
        .split_once("unsafe fn file_irp_drain_redrive_all(")
        .expect("File IRP drain redrive")
        .1
        .split_once("unsafe fn ensure_client_copyin_dll_page(")
        .expect("File IRP drain boundary")
        .0;
    assert!(!drain.contains("claim_reply_cap_exact("));
    assert!(!drain.contains("let _ = reply_parked_syscall("));
    assert!(drain.contains("begin_reply_exact("));
    assert!(drain.contains("finish_reply_exact("));
    assert!(drain.contains("if !replied"), "uncertain Reply must preserve the exact row");
    assert!(drain.contains("capture_thread_process_identity"));
    assert!(SERVICE.contains("file_irp_drain_dependents_quiescent_exact("));
    assert!(EXEC.contains("self.file_irp_drain_dependents_quiescent_exact("));
}
