//! Native partition reads must follow the caller's exact device stack and retain each IRP.

use std::cell::Cell;

#[test]
fn failed_partition_device_reference_never_constructs_a_drop_guard() {
    struct Guard<'a>(&'a Cell<usize>);

    impl Drop for Guard<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    // bool::then_some evaluates its argument before testing the condition. A failed
    // ObReferenceObjectByPointer followed by then_some(ReferencedDevice(device)) therefore
    // calls ObDereferenceObject on a reference the caller never acquired.
    let drops = Cell::new(0);
    let absent = false.then_some(Guard(&drops));
    assert!(absent.is_none());
    assert_eq!(drops.get(), 1, "then_some eagerly drops the unselected guard");

    let native = include_str!("../../../components/ntos-executive/src/hosted_partition_table.rs");
    let acquire = native
        .split("pub(super) fn acquire(device: u64) -> Result<Self, i32> {")
        .nth(1)
        .expect("partition device reference admission")
        .split("\n}\n\nimpl Drop for ReferencedDevice")
        .next()
        .expect("partition device reference admission body");
    assert!(acquire.contains("ob_reference_object_by_pointer(device, 0, 0, 0)"));
    assert!(
        !acquire.contains("then_some(Self(device))"),
        "failed reference admission must not construct a guard that drops into an unearned dereference"
    );
    assert!(
        acquire.contains(".then(|| Self(device))")
            || (acquire.contains("if status == STATUS_SUCCESS")
                && acquire.contains("Ok(Self(device))"))
            || (acquire.contains("if status != STATUS_SUCCESS")
                && acquire.contains("return Err(status)")
                && acquire.contains("Ok(Self(device))")),
        "guard construction must be inside the successful reference branch"
    );
}

#[test]
fn partition_table_export_uses_live_geometry_and_sector_irps_before_pool_publication() {
    let launch = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let native = include_str!("../../../components/ntos-executive/src/hosted_partition_table.rs");
    let builder = include_str!("../../../components/ntos-executive/src/hosted_synchronous_fsd_request.rs");
    let plan = include_str!("../../nt-io-manager/src/kernel_irp_builder.rs");
    let parser = include_str!("../../nt-fs/src/partition_layout.rs");
    let native_tokens: String = native.split_whitespace().collect();

    assert!(launch.contains("hosted_partition_table::bind(reg);"));
    assert!(native.contains("IOCTL_DISK_GET_DRIVE_GEOMETRY_EX"));
    assert!(native.contains("hosted_driver_object_reference::ob_reference_object_by_pointer("));
    assert!(native.contains("s_obf_dereference_object(self.0)"));
    assert!(native_tokens.contains("build_control(IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,device,"));
    assert!(native.contains("hosted_synchronous_fsd_request::build_disk_metadata_read("));
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
    assert!(builder.contains("plan_disk_metadata_read("));
    assert!(builder.contains("request.publish(plan, event, iosb)"));
    assert!(plan.contains("plan.stack.flags |= SL_OVERRIDE_VERIFY_VOLUME;"));
    assert!(builder.contains("(FSD_SERVICE_SOURCE_IRP_LABEL << 12) | 4,\n            4,"));
    assert!(parser.contains("crc.finish() != header.partition_entries_crc32"));
    assert!(parser.contains("read_gpt_layout(disk_sectors - 1"));
}
