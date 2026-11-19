//! No routed Section or image read waits synchronously on a Pending provider READ (#322, #324).
//!
//! Every caller that can run after the native block handoff owns a page-in continuation. The
//! synchronous helpers dispatch only on the Boot inline route, so a Pending READ can no longer be
//! turned into STATUS_IO_DEVICE_ERROR.

const EXEC: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
const IO: &str = include_str!("../../../components/ntos-executive/src/routed_section_io.rs");
const TAIL: &str = include_str!("../../../components/ntos-executive/src/executor/syscall_tail.rs");
const SECTION: &str = include_str!("../../../components/ntos-executive/src/section_pagein_work.rs");

fn body<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source.split_once(start).unwrap().1.split_once(end).unwrap().0
}

#[test]
fn kernel_lock_and_sync_copy_residency_defer_routed_pages() {
    let residency = body(EXEC, "pub(crate) unsafe fn ensure_residency_page(",
        "pub(crate) unsafe fn capture_virtual_memory_lock_request(");
    let mapped = body(residency, "VmResidencySource::Mapped =>", "VmResidencySource::Image =>");
    assert!(mapped.contains("true,\n                    false,"), "mapped faults defer routed reads");
    assert!(mapped.contains("InputPageSource::Mapped"));
    let image = residency.split_once("VmResidencySource::Image =>").unwrap().1;
    assert!(image.contains("self.admit_native_image_copy_page(target_pi, plan.page, plan.access)"));
    assert!(!image.contains("service_native_image_page_residency("), "no Direct image read");
    assert!(image.contains("InputPageSource::Image"));
}

#[test]
fn a_named_mapped_input_page_parks_the_caller_on_the_section_worker() {
    let tail = body(TAIL, "InputPageInSettlement::PageInAndRetry(input)", "ControlFlow::Break(Turn::Next)");
    assert!(tail.contains("InputPageSource::Mapped =>"));
    assert!(tail.contains("crate::section_pagein_work::submit_syscall_retry("));
    assert!(SECTION.contains("SyscallRetry { retry, .. } => reply_parked_syscall_retry(work.reply, &retry)"));
    assert!(SECTION.contains("reply_parked_syscall(work.reply, u64::from(status))"));
}

#[test]
fn synchronous_routed_io_dispatches_only_on_the_boot_inline_route() {
    for (start, end) in [
        ("fn query_information(", "match result {"),
    ] {
        let prefix = body(IO, start, end);
        let gate = prefix.find("boot_inline_read_admitted").unwrap();
        let dispatch = prefix.find("build_and_dispatch_external_to_device").unwrap();
        assert!(gate < dispatch, "{start} gates before any dispatch");
    }
}
