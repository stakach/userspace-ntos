//! Native partition reads must follow the caller's exact device stack and retain each IRP.

#[test]
fn partition_table_export_uses_live_geometry_and_sector_irps_before_pool_publication() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let native = include_str!("../../../components/ntos-executive/src/hosted_partition_table.rs");
    let builder = include_str!("../../../components/ntos-executive/src/hosted_synchronous_fsd_request.rs");
    let parser = include_str!("../../nt-fs/src/partition_layout.rs");

    assert!(launch.contains("hosted_partition_table::bind(reg);"));
    assert!(native.contains("IOCTL_DISK_GET_DRIVE_GEOMETRY_EX"));
    assert!(native.contains("hosted_driver_object_reference::ob_reference_object_by_pointer("));
    assert!(native.contains("s_obf_dereference_object(self.0)"));
    assert!(native.contains("build_control(\n            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, device,"));
    assert!(native.contains("hosted_synchronous_fsd_request::build(\n            u32::from(major::IRP_MJ_READ), device,"));
    assert!(native.contains("s_iof_call_driver(device, irp)"));
    assert!(native.contains("s_ke_wait_for_single_object(self.event"));
    assert!(native.contains("read_unaligned(self.iosb as *const i32)"));
    assert!(native.contains("nt_fs::read_drive_layout_ex(sector_bytes, sectors, |lba, out|"));
    assert!(native.contains("sector_io.read_sector(device, lba, out)"));
    assert!(native.contains("let result = pool_alloc(layout.len() as u64);"));
    assert!(native.contains("write_unaligned(output as *mut u64, result)"));
    assert!(!native.contains("native_storage_route()"));
    assert!(!native.contains("exec_expected_disk()"));
    assert!(!native.contains("STATUS_NOT_IMPLEMENTED"));

    assert!(builder.contains("plan_device_io_control_request("));
    assert!(builder.contains("request.publish(plan, event, iosb)"));
    assert!(builder.contains("(FSD_SERVICE_SOURCE_IRP_LABEL << 12) | 4,\n            4,"));
    assert!(parser.contains("crc.finish() != header.partition_entries_crc32"));
    assert!(parser.contains("read_gpt_layout(disk_sectors - 1"));
}
