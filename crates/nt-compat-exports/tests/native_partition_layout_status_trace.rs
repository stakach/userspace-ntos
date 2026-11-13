//! The exact disk geometry terminal and partition reader must expose failure provenance.

const DRIVER_LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const PARTITION_TABLE: &str = include_str!("../../../components/ntos-executive/src/hosted_partition_table.rs");

#[test]
fn geometry_completion_and_partition_reader_report_exact_status_without_changing_it() {
    let dispatch = DRIVER_LAUNCH
        .split_once("unsafe fn dispatch_irp_for_instance_exact(")
        .expect("canonical hosted dispatch")
        .1;
    let info = dispatch.find("let info = read_volatile((sh + SH_REQ_INFO)")
        .expect("exact hosted IoStatus.Information");
    let trace = dispatch.find("hosted_partition_table::trace_geometry_terminal(")
        .expect("disk-class geometry terminal trace");
    let returned = dispatch.find("HostedIrpTransportResult::Returned {")
        .expect("canonical terminal return");
    assert!(info < trace && trace < returned);
    assert!(dispatch.contains("fsctl == u64::from(hosted_partition_table::IOCTL_DISK_GET_DRIVE_GEOMETRY_EX)"));
    assert!(PARTITION_TABLE.contains("trace_geometry_terminal(irp: u64, device: u64, status: i32, information: u64)"));

    let read = PARTITION_TABLE
        .split_once("pub(super) extern \"win64\" fn read(device: u64, output: u64)")
        .expect("IoReadPartitionTableEx")
        .1
        .split_once("pub(super) fn bind(")
        .expect("read boundary")
        .0;
    for stage in [
        b"device-contract".as_slice(), b"device-reference", b"geometry",
        b"geometry-ready", b"layout", b"published",
    ] {
        let label = core::str::from_utf8(stage).unwrap();
        assert!(read.contains(&format!("trace_partition_read(device, b\"{label}\"")));
    }
    assert!(read.contains("write_unaligned(output as *mut u64, result);"));
}
