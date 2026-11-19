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
