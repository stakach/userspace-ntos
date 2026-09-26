//! Executive-owned mount identities and mounted-volume device publication.
use nt_memory_manager::{SectionMountId, SectionMountIds};
use nt_status::NtStatus;

use crate::mounted_volume_backend::MountedVolumeBackend;

static mut MOUNT_IDS: SectionMountIds = SectionMountIds::new();

pub(crate) unsafe fn allocate_mount_id() -> Result<SectionMountId, u32> {
    (&mut *core::ptr::addr_of_mut!(MOUNT_IDS))
        .allocate()
        .ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
}

pub(crate) fn register_mounted_volume(fs: crate::Fat32) -> Result<(u64, bool), NtStatus> {
    let guid_bytes = nt_fs::format_gpt_guid(fs.partition_guid);
    let guid = core::str::from_utf8(&guid_bytes).expect("formatted GPT GUID is ASCII");
    let driver_path = alloc::format!("\\Driver\\MountedVolume{{{guid}}}");
    let device_path = alloc::format!("\\Device\\Volume{{{guid}}}");
    let backend = MountedVolumeBackend::new(fs)?;
    let device_id = crate::driver_launch::register_kernel_volume_device(
        &driver_path,
        &device_path,
        alloc::boxed::Box::new(backend),
        &[
            nt_io_abi::major::IRP_MJ_CREATE,
            nt_io_abi::major::IRP_MJ_READ,
            nt_io_abi::major::IRP_MJ_WRITE,
            nt_io_abi::major::IRP_MJ_QUERY_INFORMATION,
            nt_io_abi::major::IRP_MJ_CLEANUP,
            nt_io_abi::major::IRP_MJ_CLOSE,
        ],
    )?;
    crate::print_str(b"[mounted-volume] registered ");
    crate::print_str(device_path.as_bytes());
    crate::print_str(b" device=");
    crate::print_hex((device_id >> 32) as u32);
    crate::print_hex(device_id as u32);
    crate::print_str(b"\n");
    let probe_ok = crate::driver_launch::probe_kernel_volume_file(&device_path);
    crate::print_str(b"[mounted-volume] canonical font CREATE/QUERY/READ/CLOSE proof=");
    crate::print_u64(probe_ok as u64);
    crate::print_str(b"\n");
    Ok((device_id, probe_ok))
}
