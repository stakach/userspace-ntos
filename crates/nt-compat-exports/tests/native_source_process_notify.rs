//! The released dxgkrnl eager init registers a process-exit callback. This regression keeps the
//! native import, authenticated broker, and terminal delivery hooked to the tested policy ledger.

#[test]
fn ps_process_exit_notify_is_bound_routed_and_drained_before_process_retirement() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let pump = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
    let terminal = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let receipt = include_str!("../../../components/ntos-executive/src/process_terminal_receipt.rs");
    let adapter = include_str!("../../../components/ntos-executive/src/hosted_driver_process_notify.rs");

    assert!(launch.contains("mod hosted_driver_process_notify;"));
    assert!(launch.contains("\"PsSetCreateProcessNotifyRoutineEx\""));
    assert!(launch.contains("hosted_driver_process_notify::ps_set_create_process_notify_routine_ex"));
    assert!(launch.contains("hosted_driver_process_notify::publish_image"));
    assert!(launch.contains("hosted_driver_process_notify::blocks_instance_retirement"));
    assert!(launch.contains("hosted_driver_process_notify::retire_instance_images"));
    assert!(pump.contains("hosted_driver_process_notify::LABEL"));
    assert!(pump.contains("hosted_driver_process_notify::service"));
    assert!(terminal.contains("process_terminal_receipt::drain_hosted_process_exit_notifications(self)"));
    assert!(receipt.contains("take_process_exit_notification"));
    assert!(receipt.contains("hosted_driver_process_notify::dispatch_exit_notification(ticket)"));
    assert!(receipt.contains("complete_process_exit_notification(ticket)"));
    assert!(adapter.contains("register_process_exit_notify"));
    assert!(adapter.contains("complete_process_exit_notification"));
    assert!(adapter.contains("dispatch_hosted_component_target"));
}
