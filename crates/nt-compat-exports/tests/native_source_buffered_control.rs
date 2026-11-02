//! The provider-facing contract is tested by nt-io-manager. These checks keep
//! its native foreign-lower entry and retained source completion wired.

use std::process::Command;

#[test]
fn foreign_lower_buffered_control_has_retained_source_route() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let start = source.find("extern \"win64\" fn s_iof_call_driver(").unwrap();
    let call = &source[start..source[start..].find("if major != IRP_MJ_PNP").unwrap() + start];
    assert!(call.contains("if major == IRP_MJ_DEVICE_CONTROL"));
    assert!(call.contains("forward_hosted_buffered_control("));
    assert!(source.contains("service_hosted_buffered_control_forward"));
    assert!(source.contains("redrive_hosted_buffered_control_forward"));

    let worker = include_str!("../../../components/ntos-executive/src/hosted_buffered_control_work.rs");
    let capture = include_str!("../../../components/ntos-executive/src/hosted_buffered_control_capture.rs");
    assert!(worker.contains("BufferedDeviceControlAtDevice"));
    assert!(worker.contains("completed_device_control_irp_exact"));
    assert!(worker.contains("copy_completed_irp_output_exact"));
    assert!(worker.contains("self.inline_held && self.source.completion_finished()"));
    assert!(capture.contains("pool_range_identity_unlocked"));
    assert!(capture.contains("write_refusal"));
    assert!(source.contains("HostedIrpUnwindOutcome::MoreProcessingRequired"));
}

#[test]
fn actual_native_source_stack_capture_rejects_stale_cursor() {
    let source = include_str!("../../../components/ntos-executive/src/hosted_buffered_control_capture.rs");
    let start = source.find("fn next_stack_address(").unwrap();
    let end = source[start..].find("\npub(super) unsafe fn capture(").unwrap() + start;
    let function = &source[start..end];
    syn::parse_str::<syn::ItemFn>(function).expect("complete native stack helper");
    let harness = format!(r#"
const WDM_X64_IO_TYPE_IRP: u16 = 6;
const WDM_X64_IRP_SIZE: usize = 0xd0;
const WDM_X64_IO_STACK_LOCATION_SIZE: usize = 0x48;
#[derive(Clone, Copy)] struct GuestAddr(u64);
#[derive(Clone, Copy)] struct Irp {{
    type_: i16, size: u16, stack_count: i8, current_location: i8,
    current_stack_location: GuestAddr,
}}
#[derive(Clone, Copy)] struct SourceIrpAllocation {{
    component_address: u64, bytes: u64, stack_count: u8,
}}
{function}
#[test] fn exact_source_stack() {{
    let allocation = SourceIrpAllocation {{ component_address: 0x1000, bytes: 0x160, stack_count: 2 }};
    let mut irp = Irp {{ type_: 6, size: 0x160, stack_count: 2, current_location: 3,
        current_stack_location: GuestAddr(0x1000 + 0xd0 + 2 * 0x48) }};
    assert_eq!(next_stack_address(allocation, &irp), Some(0x1000 + 0xd0 + 0x48));
    irp.current_stack_location = GuestAddr(0x1000 + 0xd0 + 0x48);
    assert_eq!(next_stack_address(allocation, &irp), None, "stale cursor cannot capture source stack");
    irp.current_stack_location = GuestAddr(0x1000 + 0xd0 + 2 * 0x48);
    irp.current_location = 1;
    assert_eq!(next_stack_address(allocation, &irp), None, "terminal cursor has no lower stack");
    irp.current_location = 4;
    assert_eq!(next_stack_address(allocation, &irp), None, "cursor beyond allocation");
}}
"#);
    let directory = std::env::temp_dir().join(format!("nt-buffered-control-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("fixture.rs");
    let output = directory.join("fixture-tests");
    std::fs::write(&input, harness).unwrap();
    let compiled = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input).arg("-o").arg(&output).output().unwrap();
    assert!(compiled.status.success(), "native helper fixture compile: {}", String::from_utf8_lossy(&compiled.stderr));
    let run = Command::new(&output).output().unwrap();
    assert!(run.status.success(), "native helper behavior: {}", String::from_utf8_lossy(&run.stdout));
}
