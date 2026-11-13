#[test]
fn hosted_driver_cr8_is_emulated_from_exact_fault_source() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let pump = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
    let fault = include_str!("../../../components/ntos-executive/src/hosted_driver_cr8_fault.rs");
    assert!(launch.contains("mod hosted_driver_cr8_fault;"));
    assert!(!launch.contains("CR8 writes are\n    // nopped"));
    assert!(!launch.contains("a KeRaise/LowerIrql write to cr8 → neutralize to nops"));
    assert!(pump.contains("hosted_driver_cr8_fault::service"));
    assert!(fault.contains("fault_source_identity")
        && fault.contains("decode_cr8_write")
        && fault.contains("decode_cr8_read")
        && fault.contains("hosted_current_irql")
        && fault.contains("thread_context::write"));
}

#[test]
fn per_irp_pump_cr8_uses_retained_driver_image_not_disabled_wall_extent() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let fault = include_str!("../../../components/ntos-executive/src/hosted_driver_cr8_fault.rs");
    assert!(launch.contains("image_frames: 0, // per-IRP loop"));
    assert!(fault.contains("published_image_for_callback")
        && fault.contains("ExecVaWindow::try_for_instance")
        && !fault.contains("channel.image_frames.checked_mul"),
        "the authenticated #GP code read must use the published immutable driver image, even when the per-IRP pump disables in-image wall checks");
}
