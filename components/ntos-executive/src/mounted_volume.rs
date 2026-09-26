//! Executive-owned mount identities and mounted-volume device publication.
use alloc::{string::String, vec::Vec};

use nt_memory_manager::{SectionMountId, SectionMountIds};
use nt_status::NtStatus;

use crate::fs_loader::fat_visit_directory_checked;
use crate::mounted_volume_backend::MountedVolumeBackend;

static mut MOUNT_IDS: SectionMountIds = SectionMountIds::new();

pub(crate) unsafe fn allocate_mount_id() -> Result<SectionMountId, u32> {
    (&mut *core::ptr::addr_of_mut!(MOUNT_IDS))
        .allocate()
        .ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
}

fn discover_installed_root(fs: &crate::Fat32) -> Result<nt_fs::InstalledRoot, NtStatus> {
    nt_fs::discover_installed_root(fs.root_cl, |cluster| {
        let mut entries = Vec::new();
        let mut append_error = None;
        let end = unsafe {
            fat_visit_directory_checked(fs, cluster, |entry, first_cluster| {
                if entries.try_reserve(1).is_err() {
                    append_error = Some(nt_fs::STATUS_INSUFFICIENT_RESOURCES);
                    return false;
                }
                entries.push(nt_fs::FatDirectoryRecord {
                    entry,
                    first_cluster,
                });
                true
            })
        }?;
        if let Some(error) = append_error {
            return Err(error);
        }
        Ok(nt_fs::FatDirectorySnapshot { entries, end })
    })
    .map_err(|error| match error {
        nt_fs::InstalledRootError::Read(status) => NtStatus(status as i32),
        nt_fs::InstalledRootError::Missing => NtStatus::OBJECT_PATH_NOT_FOUND,
        nt_fs::InstalledRootError::Ambiguous => NtStatus::OBJECT_NAME_COLLISION,
        nt_fs::InstalledRootError::Incomplete | nt_fs::InstalledRootError::Corrupt => {
            NtStatus(nt_fs::STATUS_DATA_ERROR as i32)
        }
    })
}

pub(crate) fn register_mounted_volume(
    fs: crate::Fat32,
) -> Result<(u64, bool, nt_fs::InstalledRoot, String), NtStatus> {
    let installed_root = discover_installed_root(&fs)?;
    let root_name =
        String::from_utf16(&installed_root.name).map_err(|_| NtStatus::OBJECT_NAME_INVALID)?;
    crate::print_str(b"[mounted-volume] validated installation root ");
    crate::print_str(root_name.as_bytes());
    crate::print_str(b" cluster=");
    crate::print_u64(installed_root.first_cluster as u64);
    crate::print_str(b"\n");
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
            nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL,
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
    Ok((device_id, probe_ok, installed_root, device_path))
}
