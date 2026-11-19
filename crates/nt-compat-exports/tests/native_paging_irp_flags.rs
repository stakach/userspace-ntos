//! Native wiring of request-wide IRP flags, file-pointer resolution and routed page writes
//! (#186). The contracts are proven behaviourally in nt-io-manager and nt-memory-manager; these
//! checks bind only the native call sites that have no host harness.

const PAGE_INS: [(&str, &str); 7] = [
    ("section_pagein_work.rs", include_str!("../../../components/ntos-executive/src/section_pagein_work.rs")),
    ("native_image_pagein_work.rs", include_str!("../../../components/ntos-executive/src/native_image_pagein_work.rs")),
    ("provider_section_map_work.rs", include_str!("../../../components/ntos-executive/src/provider_section_map_work.rs")),
    ("routed_section_io.rs", include_str!("../../../components/ntos-executive/src/routed_section_io.rs")),
    ("mounted_system_image_read.rs", include_str!("../../../components/ntos-executive/src/mounted_system_image_read.rs")),
    ("section_metadata_work.rs", include_str!("../../../components/ntos-executive/src/section_metadata_work.rs")),
    ("process_image_snapshot_work.rs", include_str!("../../../components/ntos-executive/src/process_image_snapshot_work.rs")),
];
const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const WRITEBACK: &str = include_str!("../../../components/ntos-executive/src/section_writeback_work.rs");
const INGRESS: &str = include_str!("../../../components/ntos-executive/src/executor/syscall_nt.rs");

#[test]
fn every_section_and_image_page_in_is_an_io_page_read() {
    for (name, source) in PAGE_INS {
        assert!(source.contains("build_and_dispatch_paging_to_device("), "{name} pages in");
        assert!(source.contains("PagingTransfer::Read"), "{name} uses IoPageRead");
        assert!(
            !source.contains("nt_io_abi::major::IRP_MJ_READ,\n"),
            "{name} issues no ordinary READ for page data"
        );
    }
}

#[test]
fn the_driver_host_carries_admitted_request_flags_into_irp_flags() {
    assert!(LAUNCH.contains("irp_flags: irp.request_flags.bits(),"));
    assert!(LAUNCH.contains("IrpRequestFlags::from_wire(\n            request.major, request.minor, request.irp_flags,"));
    assert!(LAUNCH.contains("flags: irp_flags | request.irp_flags,"));
    assert!(LAUNCH.contains("nt_io_manager::wdm_file_object_transfer_offset("));
}

#[test]
fn routed_dirty_pages_are_paging_writes_owned_through_strict_acknowledgement() {
    assert!(WRITEBACK.contains("build_and_dispatch_paging_to_device("));
    assert!(WRITEBACK.contains("acknowledge_completed_irp_strict(irp)"));
    assert!(WRITEBACK.contains("table.finish_page_write(job.write, outcome)"));
    assert!(INGRESS.contains("section_writeback_work::submit_vm_flush("));
    assert!(INGRESS.contains("section_writeback_work::submit_cache_flush("));
}

const READ_CAPTURE: &str = include_str!("../../../components/ntos-executive/src/hosted_read_capture.rs");
const WRITE_CAPTURE: &str = include_str!("../../../components/ntos-executive/src/hosted_write_capture.rs");
const READ_FORWARD: &str = include_str!("../../../components/ntos-executive/src/hosted_read_work.rs");
const WRITE_FORWARD: &str = include_str!("../../../components/ntos-executive/src/hosted_write_work.rs");
const DEVICE_FORWARD: &str = include_str!("../../../components/ntos-executive/src/hosted_device_forward_work.rs");

#[test]
fn driver_built_transfers_forward_their_own_irp_flags() {
    // The split of Irp->Flags is proven in nt-io-manager (from_driver_irp); these bind the
    // forwards of IRPs a driver built or passes down to the canonical request.
    assert!(READ_CAPTURE.contains("StackFlags::from_bits_retain(initial_stack.flags), initial_irp.flags,"));
    assert!(WRITE_CAPTURE.contains("StackFlags::from_bits_retain(initial_stack.flags), initial_irp.flags,"));
    assert!(READ_FORWARD.contains("request_flags: read.request_flags(),"));
    assert!(WRITE_FORWARD.contains("request_flags: write.request_flags(),"));
    assert!(DEVICE_FORWARD.contains("read.request_flags,"));
}

const PROVIDER_SECTIONS: &str = include_str!("../../../components/ntos-executive/src/provider_mm_section_objects.rs");

#[test]
fn provider_view_stores_reach_the_page_writer() {
    // The harvest itself is proven in nt-memory-manager (unmap_provider_view_exact,
    // harvest_provider_view_writes); these bind its native triggers.
    assert!(PROVIDER_SECTIONS.contains("unmap_provider_view_exact((*mapping).view) != Some((*mapping).view) {\n        return Err(INVALID);\n    }\n    // Removing a writable routed view marks the pages it could write modified.\n    crate::service_sec_image::section_writeback_work::request_scan();"));
    assert!(WRITEBACK.contains("    harvest_stream(table, device_id, fs_context);\n    if scope_tickets(table, scope)"));
}

const HANDLER: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
const SEC_IMAGE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const COHERENCE: &str = include_str!("../../../components/ntos-executive/src/routed_write_coherence.rs");

#[test]
fn routed_writes_reach_resident_section_pages() {
    // plan_stream_write/commit_stream_write are proven in nt-memory-manager; these bind the
    // inline and pended NtWriteFile completions to them.
    assert!(HANDLER.contains("routed_write_coherence::retain_pending(\n"));
    assert!(HANDLER.contains("routed_write_coherence::apply(\n"));
    assert!(SEC_IMAGE.contains("if finished.major == nt_io_abi::major::IRP_MJ_WRITE {\n            routed_write_coherence::settle_pending("));
    assert!(COHERENCE.contains("table.plan_stream_write(section, offset, data.len() as u64)"));
    assert!(COHERENCE.contains("if !copied || !table.commit_stream_write(plan) {"));
}
