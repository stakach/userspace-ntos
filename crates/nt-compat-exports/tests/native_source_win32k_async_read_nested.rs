//! A class READ may complete while the Win32k syscall receiver retains its parent Reply.
//! Its exact completion must be redriven inside that receiver before the next blocking wait.

#[test]
fn win32k_async_read_has_exact_nested_completion_handoff() {
    let worker = include_str!(
        "../../../components/ntos-executive/src/hosted_kernel_win32k_async_read.rs"
    );
    assert!(worker.contains("unsafe fn ready_for_nested_step(&self) -> bool"));
    assert!(worker.contains("nested_file_irp_completion_ready_exact(irp.raw())"));
    assert!(worker.contains("pub(super) unsafe fn nested_work_ready() -> bool"));
    assert!(worker.contains("pub(super) unsafe fn redrive_nested_ready(handler: *mut ExecNtHandler) -> bool"));
    assert!(worker.contains("if nested_ready_only && !(&*core::ptr::addr_of!(WORK))[index]"));

    let receiver = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");
    assert!(receiver.contains("service_sec_image::nested_hosted_file_work_ready()"));
    let service = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    assert!(service.contains("nested_hosted_win32k_async_read_ready()"));
    assert!(service.contains("redrive_nested_hosted_win32k_async_read(handler)"));
}
