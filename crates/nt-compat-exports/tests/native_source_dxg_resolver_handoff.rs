const WORK: &str = include_str!("../../../components/ntos-executive/src/hosted_internal_control_work.rs");
const CAPTURE: &str = include_str!("../../../components/ntos-executive/src/hosted_internal_control_capture.rs");

#[test]
fn successful_pointer_terminal_requires_typed_bridge_before_source_copyout() {
    assert!(CAPTURE.contains("fn target_registration("));
    assert!(CAPTURE.contains("fn write_typed_output(&self, caller_thunk_va: u64)"));

    let terminal = WORK
        .split("fn observe_terminal(")
        .nth(1)
        .expect("internal-control terminal observer")
        .split("unsafe fn poll_provider(")
        .next()
        .expect("terminal observer boundary");
    assert!(terminal.contains("information == 8"));
    assert!(terminal.contains("bridge_dxg_registration_entry("));
    assert!(terminal.contains("self.source.source_identity()"));
    assert!(terminal.contains("self.source.target_registration()"));

    let publish = WORK
        .split("unsafe fn publish_source_terminal(")
        .nth(1)
        .expect("source terminal publication")
        .split("unsafe fn retire_terminal(")
        .next()
        .expect("source terminal publication boundary");
    assert!(publish.contains("write_typed_output(caller_thunk_va)"));
    assert!(publish.contains("self.source.arm_callback_free()"));
    assert!(!publish.contains("opaque"));
}
