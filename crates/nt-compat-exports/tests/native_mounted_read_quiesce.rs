//! A retained installed-file READ remains a signaler while its caller waits.

const VOLUME: &str = include_str!("../../../components/ntos-executive/src/mounted_volume.rs");
const LAUNCH: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const SERVICE: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const READS: &str = include_str!("../../nt-fs/src/mounted_installed_read.rs");

#[test]
fn mounted_read_quiesce_observes_the_exact_completion_owner() {
    let start = VOLUME.find("pub(crate) fn mounted_read_outstanding()").expect("mounted read accessor");
    let accessor = &VOLUME[start..VOLUME[start..].find("\n}").unwrap() + start];
    assert!(accessor.contains("MOUNT_READ_QUEUE"));
    assert!(accessor.contains("has_outstanding()"));
    assert!(!accessor.contains("has_claimable_sector()"),
        "a claimed sector still retains the READ owner");

    let owner_start = READS.find("pub fn has_outstanding(&self)").expect("read queue owner");
    assert!(READS[owner_start..].starts_with("pub fn has_outstanding(&self) -> bool { !self.entries.is_empty() }"));
    for field in ["irp: u64", "mount: u64", "file: u64", "claimed: Option<ReadSectorClaim>"] {
        assert!(READS.contains(field), "READ entry must retain exact {field}");
    }
}

#[test]
fn no_signaler_gates_wait_for_retained_mounted_reads() {
    assert_eq!(SERVICE.matches("!crate::mounted_volume::mounted_read_outstanding()").count(), 3,
        "all-live-parked, all-live-waiting, and lsass-post-signal-fault must retain the mounted READ owner");
    assert_eq!(SERVICE.matches("driver_launch::print_mounted_native_block_quiesce_snapshot()").count(), 2);
    let start = LAUNCH.find("pub(crate) fn print_mounted_native_block_quiesce_snapshot()").expect("driver-launch bridge");
    assert!(LAUNCH[start..].starts_with("pub(crate) fn print_mounted_native_block_quiesce_snapshot() {\n    mounted_native_block::print_quiesce_snapshot();"));
}
