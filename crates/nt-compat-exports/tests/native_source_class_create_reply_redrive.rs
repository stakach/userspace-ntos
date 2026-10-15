//! A nested class CREATE can complete while its caller remains inside win32k.
//! Exact Reply acknowledgement must make the retained transaction locally runnable.

#[test]
fn acknowledged_class_create_reply_is_nested_ready_without_replaying_send() {
    let work = include_str!("../../../components/ntos-executive/src/hosted_io_create_file_work.rs");
    let ready = &work[work.find("fn ready_for_nested_step(&self) -> bool {").unwrap()..];
    let ready = &ready[..ready.find("    unsafe fn prepare(").unwrap()];
    assert!(ready.contains("runtime::retained_service_reply_acknowledged("));
    assert!(!ready.contains("if self.reply_entered { return false; }"));

    let advance = &work[work.find("unsafe fn advance(&mut self, handler:").unwrap()..];
    let advance = &advance[..advance.find("/// Drive one retained transaction per sweep").unwrap()];
    assert!(advance.contains("runtime::reconcile_retained_service_reply("));
    assert!(advance.contains("self.ack_backend()?"));
    assert!(advance.contains("runtime::retire_stopped_acknowledged_retained_service("));
    assert_eq!(advance.matches("runtime::wake_file_create_service(").count(), 1);
}
