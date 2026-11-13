//! Routed VM copy page-ins retain the syscall and completed prefix across provider Pending.

const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const COPY: &str = include_str!("../../../components/ntos-executive/src/vm_copy_work.rs");
const SECTION: &str = include_str!("../../../components/ntos-executive/src/section_pagein_work.rs");
const IMAGE: &str = include_str!("../../../components/ntos-executive/src/native_image_pagein_work.rs");

#[test]
fn read_and_write_vm_park_once_then_resume_exact_routed_page_owner() {
    assert!(SERVICE.contains("SSN_NT_READ_VM"));
    assert!(SERVICE.contains("SSN_NT_WRITE_VM"));
    assert!(SERVICE.contains("vm_copy_work::submit("),
        "copy ingress must park before source, destination or count-output residency effects");
    assert!(SERVICE.contains("vm_copy_work::redrive("));
    assert!(COPY.contains("RootReplyPark::prepare()"));
    assert!(COPY.contains("VmCopyContinuation"));
    assert!(COPY.contains("section_pagein_work::submit_for_vm_copy("));
    assert!(COPY.contains("native_image_pagein_work::submit_for_vm_copy("));
    assert!(SECTION.contains("vm_copy_work::page_completed("));
    assert!(IMAGE.contains("vm_copy_work::page_completed("));
    assert!(COPY.contains("reply_parked_syscall("));
    assert!(!COPY.contains("copy_virtual_memory("),
        "restarting the synchronous copy after Pending would replay completed writes");
}
