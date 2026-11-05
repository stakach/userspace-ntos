//! Executive-owned mount identities and mounted-volume device publication.
use alloc::{rc::Rc, string::String, vec::Vec};
use core::cell::RefCell;

use nt_memory_manager::{SectionMountBindings, SectionMountId, SectionMountIds};
use nt_status::NtStatus;

use crate::fs_loader::fat_visit_directory_checked;
use crate::mounted_volume_backend::{MountedCreateQueue, MountedDirectoryQueue, MountedOverlayQueue, MountedReadQueue, MountedVolumeBackend};

#[path = "exec_volume_mount_pair.rs"]
mod exec_volume_mount_pair;
use exec_volume_mount_pair::ExecVolumeDevice;

static mut MOUNT_IDS: SectionMountIds = SectionMountIds::new();
static mut MOUNT_BINDINGS: SectionMountBindings<nt_io_manager::DeviceId> =
    SectionMountBindings::new();
static mut MOUNT_CREATE_QUEUE: Option<MountedCreateQueue> = None;
static mut MOUNT_OVERLAY_QUEUE: Option<MountedOverlayQueue> = None;
static mut MOUNT_READ_QUEUE: Option<MountedReadQueue> = None;
static mut MOUNT_DIRECTORY_QUEUE: Option<MountedDirectoryQueue> = None;

/// Only unentered sector work warrants an autonomous wake. A physical IRP already owns its
/// completion and must not be polled by the mounted-work timer.
pub(crate) fn mounted_sector_claimable() -> Option<bool> {
    unsafe {
        let create = match (&*core::ptr::addr_of!(MOUNT_CREATE_QUEUE)).as_ref() {
            Some(queue) => queue.try_borrow().ok()?.has_claimable_sector(),
            None => false,
        };
        let overlay = match (&*core::ptr::addr_of!(MOUNT_OVERLAY_QUEUE)).as_ref() {
            Some(queue) => queue.try_borrow().ok()?.has_claimable_sector(),
            None => false,
        };
        let read = match (&*core::ptr::addr_of!(MOUNT_READ_QUEUE)).as_ref() {
            Some(queue) => queue.try_borrow().ok()?.has_claimable_sector(),
            None => false,
        };
        let directory = match (&*core::ptr::addr_of!(MOUNT_DIRECTORY_QUEUE)).as_ref() {
            Some(queue) => queue.try_borrow().ok()?.has_claimable_sector(),
            None => false,
        };
        Some(create || overlay || read || directory)
    }
}
/// The published File device with both its physical FAT and logical File mount owners.
static mut EXEC_VOLUME_DEVICE: Option<ExecVolumeDevice> = None;

pub(crate) fn draining_exec_volume_device() -> Option<u64> {
    let physical = unsafe { crate::fs_loader::exec_fs_mount_identity() }?;
    if !matches!(
        crate::fs_loader::exec_block_route_kind(physical),
        Some(nt_fs::BlockSourceKind::Draining | nt_fs::BlockSourceKind::Native)
    ) {
        return None;
    }
    exec_volume_device_for_mount(physical)
}

fn exec_volume_device_for_mount(physical: SectionMountId) -> Option<u64> {
    let published = unsafe { *core::ptr::addr_of!(EXEC_VOLUME_DEVICE) }?;
    let device_id = published.device_id;
    published.exact_device(physical, mount_id_for_live_device(device_id))
}

/// The canonical File device for the exact mounted volume, including Boot-v2 journal ownership.
pub(crate) fn exec_volume_device() -> Option<u64> {
    exec_volume_device_for_mount(unsafe { crate::fs_loader::exec_fs_mount_identity() }?)
}

/// Catalog lookup alias for a routed File on the exact live installed-volume device.
/// The File's namespace identity must remain the original mounted-volume identity.
pub(crate) fn physical_exec_file_alias(
    device_id: u64,
    file: nt_memory_manager::SectionFileIdentity,
) -> Option<nt_memory_manager::SectionFileIdentity> {
    let physical = unsafe { crate::fs_loader::exec_fs_mount_identity() }?;
    let registered = draining_exec_volume_device()?;
    unsafe { (&*core::ptr::addr_of!(MOUNT_BINDINGS)).physical_file_alias(
        nt_io_manager::DeviceId(device_id),
        file,
        Some((physical, nt_io_manager::DeviceId(registered))),
        true,
    ) }
}


pub(crate) fn claim_mounted_directory_sector() -> Option<crate::mounted_volume_backend::mounted_directory_lookup::DirectorySectorClaim> {
    let queue = unsafe { (&*core::ptr::addr_of!(MOUNT_DIRECTORY_QUEUE)).as_ref()?.clone() };
    let claim = queue.borrow_mut().claim_next();
    claim
}

pub(crate) fn mounted_directory_outstanding() -> bool {
    unsafe { (&*core::ptr::addr_of!(MOUNT_DIRECTORY_QUEUE)).as_ref()
        .is_some_and(|queue| queue.borrow().has_outstanding()) }
}

pub(crate) fn complete_mounted_directory_sector(
    claim: crate::mounted_volume_backend::mounted_directory_lookup::DirectorySectorClaim,
    sector: Result<&[u8; 512], nt_fs::FatPathError>,
) -> Result<nt_fs::FatDirectoryProgress, crate::mounted_volume_backend::mounted_directory_lookup::DirectoryLookupError> {
    let queue = unsafe { (&*core::ptr::addr_of!(MOUNT_DIRECTORY_QUEUE)).as_ref().cloned() }
        .ok_or(crate::mounted_volume_backend::mounted_directory_lookup::DirectoryLookupError::Invalid)?;
    let result = queue.borrow_mut().complete(claim, sector);
    result
}

pub(crate) fn release_unentered_mounted_directory_sector(
    claim: crate::mounted_volume_backend::mounted_directory_lookup::DirectorySectorClaim,
) -> Result<(), crate::mounted_volume_backend::mounted_directory_lookup::DirectoryLookupError> {
    let queue = unsafe { (&*core::ptr::addr_of!(MOUNT_DIRECTORY_QUEUE)).as_ref().cloned() }
        .ok_or(crate::mounted_volume_backend::mounted_directory_lookup::DirectoryLookupError::Invalid)?;
    let result = queue.borrow_mut().release_unentered(claim);
    result
}

pub(crate) fn claim_mounted_read_sectors() -> Option<crate::mounted_volume_backend::mounted_installed_read::ReadSectorClaim> {
    let queue = unsafe { (&*core::ptr::addr_of!(MOUNT_READ_QUEUE)).as_ref()?.clone() };
    let claim = queue.borrow_mut().claim_next();
    claim
}

/// A retained installed READ can wake its parked caller even before it claims a sector or
/// enters the physical SCSI route. Keep the exact completion owner in the no-signaler gate.
pub(crate) fn mounted_read_outstanding() -> bool {
    unsafe { (&*core::ptr::addr_of!(MOUNT_READ_QUEUE)).as_ref()
        .is_some_and(|queue| queue.borrow().has_outstanding()) }
}

pub(crate) fn complete_mounted_read_sectors(
    claim: crate::mounted_volume_backend::mounted_installed_read::ReadSectorClaim,
    sectors: Result<&[u8], nt_fs::FatPathError>,
) -> Result<nt_fs::FatRangeProgress, crate::mounted_volume_backend::mounted_installed_read::ReadError> {
    let queue = unsafe { (&*core::ptr::addr_of!(MOUNT_READ_QUEUE)).as_ref().cloned() }
        .ok_or(crate::mounted_volume_backend::mounted_installed_read::ReadError::Invalid)?;
    let result = queue.borrow_mut().complete_sectors(claim, sectors);
    result
}

pub(crate) fn release_unentered_mounted_read_sector(
    claim: crate::mounted_volume_backend::mounted_installed_read::ReadSectorClaim,
) -> Result<(), crate::mounted_volume_backend::mounted_installed_read::ReadError> {
    let queue = unsafe { (&*core::ptr::addr_of!(MOUNT_READ_QUEUE)).as_ref().cloned() }
        .ok_or(crate::mounted_volume_backend::mounted_installed_read::ReadError::Invalid)?;
    let result = queue.borrow_mut().release_unentered(claim);
    result
}

/// The top-level native block owner claims these exact sector requests outside backend dispatch.
pub(crate) fn claim_mounted_create_sector() -> Option<crate::mounted_volume_backend::mounted_create_lookup::CreateSectorClaim> {
    let queue = unsafe { (&*core::ptr::addr_of!(MOUNT_CREATE_QUEUE)).as_ref()?.clone() };
    let claim = queue.borrow_mut().claim_next();
    claim
}

pub(crate) fn mounted_create_outstanding() -> bool {
    unsafe { (&*core::ptr::addr_of!(MOUNT_CREATE_QUEUE)).as_ref()
        .is_some_and(|queue| queue.borrow().has_outstanding())
        || (&*core::ptr::addr_of!(MOUNT_OVERLAY_QUEUE)).as_ref()
            .is_some_and(|queue| queue.borrow().has_outstanding()) }
}

pub(crate) fn mounted_overlay_outstanding() -> bool {
    unsafe { (&*core::ptr::addr_of!(MOUNT_OVERLAY_QUEUE)).as_ref()
        .is_some_and(|queue| queue.borrow().has_outstanding()) }
}

pub(crate) fn claim_mounted_overlay_sector() -> Option<nt_fs::OverlaySectorClaim> {
    let queue = unsafe { (&*core::ptr::addr_of!(MOUNT_OVERLAY_QUEUE)).as_ref()?.clone() };
    let claim = queue.borrow_mut().claim_next();
    claim
}

pub(crate) fn complete_mounted_overlay_sector(claim: nt_fs::OverlaySectorClaim,
    sector: Result<&[u8; 512], nt_fs::FatPathError>) -> Result<nt_fs::OverlayPrepareProgress, nt_fs::OverlayPrepareError> {
    let queue = unsafe { (&*core::ptr::addr_of!(MOUNT_OVERLAY_QUEUE)).as_ref().cloned() }
        .ok_or(nt_fs::OverlayPrepareError::Invalid)?;
    let result = queue.borrow_mut().complete_sector(claim, sector);
    result
}

pub(crate) fn release_unentered_mounted_overlay_sector(claim: nt_fs::OverlaySectorClaim)
    -> Result<(), nt_fs::OverlayPrepareError> {
    let queue = unsafe { (&*core::ptr::addr_of!(MOUNT_OVERLAY_QUEUE)).as_ref().cloned() }
        .ok_or(nt_fs::OverlayPrepareError::Invalid)?;
    let result = queue.borrow_mut().release_unentered(claim);
    result
}

pub(crate) fn print_mounted_create_census() {
    let state = unsafe { (&*core::ptr::addr_of!(MOUNT_CREATE_QUEUE)).as_ref()
        .and_then(|queue| queue.borrow().first_state()) };
    if let Some((irp, mount, phase)) = state {
        crate::print_str(b"[mounted-create-census] irp=");
        crate::print_u64(irp);
        crate::print_str(b" mount=");
        crate::print_u64(mount);
        crate::print_str(b" phase=");
        crate::print_str(phase);
        crate::print_str(b"\n");
    }
    let overlay = unsafe { (&*core::ptr::addr_of!(MOUNT_OVERLAY_QUEUE)).as_ref()
        .and_then(|queue| queue.borrow().first_state()) };
    if let Some((irp, mount, phase)) = overlay {
        crate::print_str(b"[mounted-overlay-census] irp=");
        crate::print_u64(irp);
        crate::print_str(b" mount=");
        crate::print_u64(mount);
        crate::print_str(b" phase=");
        crate::print_str(phase);
        crate::print_str(b"\n");
    }
}

pub(crate) fn complete_mounted_create_sector(
    claim: crate::mounted_volume_backend::mounted_create_lookup::CreateSectorClaim,
    sector: Result<&[u8; 512], nt_fs::FatPathError>,
) -> Result<nt_fs::FatPathProgress, crate::mounted_volume_backend::mounted_create_lookup::CreateLookupError> {
    let queue = unsafe { (&*core::ptr::addr_of!(MOUNT_CREATE_QUEUE)).as_ref().cloned() }
        .ok_or(crate::mounted_volume_backend::mounted_create_lookup::CreateLookupError::Invalid)?;
    let completed = queue.borrow_mut().complete(claim, sector);
    completed
}

pub(crate) fn complete_cached_mounted_create_sector(
    claim: crate::mounted_volume_backend::mounted_create_lookup::CreateSectorClaim,
    sector: &[u8; 512],
) -> Result<nt_fs::FatPathProgress, crate::mounted_volume_backend::mounted_create_lookup::CreateLookupError> {
    let queue = unsafe { (&*core::ptr::addr_of!(MOUNT_CREATE_QUEUE)).as_ref().cloned() }
        .ok_or(crate::mounted_volume_backend::mounted_create_lookup::CreateLookupError::Invalid)?;
    let completed = queue.borrow_mut().complete_cached(claim, Ok(sector));
    if !matches!(&completed, Err(crate::mounted_volume_backend::mounted_create_lookup::CreateLookupError::WrongClaim)) {
        let attribution = queue.borrow().attribution(claim.irp, claim.mount);
        if let Some(attribution) = attribution {
            crate::service_sec_image::mounted_create_owner_trace::lookup_progress(
                claim.irp, claim.mount, attribution);
        }
    }
    completed
}

pub(crate) fn complete_physical_mounted_create_sector(
    claim: crate::mounted_volume_backend::mounted_create_lookup::CreateSectorClaim,
    sector: Result<&[u8; 512], nt_fs::FatPathError>,
) -> Result<nt_fs::FatPathProgress, crate::mounted_volume_backend::mounted_create_lookup::CreateLookupError> {
    let queue = unsafe { (&*core::ptr::addr_of!(MOUNT_CREATE_QUEUE)).as_ref().cloned() }
        .ok_or(crate::mounted_volume_backend::mounted_create_lookup::CreateLookupError::Invalid)?;
    let completed = queue.borrow_mut().complete_physical(claim, sector);
    if !matches!(&completed, Err(crate::mounted_volume_backend::mounted_create_lookup::CreateLookupError::WrongClaim)) {
        let attribution = queue.borrow().attribution(claim.irp, claim.mount);
        if let Some(attribution) = attribution {
            crate::service_sec_image::mounted_create_owner_trace::lookup_progress(
                claim.irp, claim.mount, attribution);
        }
    }
    completed
}

pub(crate) fn release_unentered_mounted_create_sector(
    claim: crate::mounted_volume_backend::mounted_create_lookup::CreateSectorClaim,
) -> Result<(), crate::mounted_volume_backend::mounted_create_lookup::CreateLookupError> {
    let queue = unsafe { (&*core::ptr::addr_of!(MOUNT_CREATE_QUEUE)).as_ref().cloned() }
        .ok_or(crate::mounted_volume_backend::mounted_create_lookup::CreateLookupError::Invalid)?;
    let released = queue.borrow_mut().release_unentered(claim);
    released
}

pub(crate) unsafe fn allocate_mount_id() -> Result<SectionMountId, u32> {
    (&mut *core::ptr::addr_of_mut!(MOUNT_IDS))
        .allocate()
        .ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
}

pub(crate) fn mount_id_for_live_device(device_id: u64) -> Option<SectionMountId> {
    let device = nt_io_manager::DeviceId(device_id);
    if crate::driver_launch::io_manager_mut()
        .device(device)
        .is_none()
    {
        return None;
    }
    unsafe { (&*core::ptr::addr_of!(MOUNT_BINDINGS)).lookup(device) }
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
    let physical_mount = unsafe { crate::fs_loader::exec_fs_mount_identity() }
        .ok_or(NtStatus::DEVICE_NOT_READY)?;
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
    let create_queue = Rc::new(RefCell::new(crate::mounted_volume_backend::mounted_create_lookup::CreateLookupQueue::new()));
    let overlay_queue = Rc::new(RefCell::new(nt_fs::OverlayPreparations::new()));
    let read_queue = Rc::new(RefCell::new(crate::mounted_volume_backend::mounted_installed_read::ReadCompletions::new()));
    let directory_queue = Rc::new(RefCell::new(crate::mounted_volume_backend::mounted_directory_lookup::DirectoryLookupQueue::new()));
    let backend = MountedVolumeBackend::new(fs, create_queue.clone(), overlay_queue.clone(),
        read_queue.clone(), directory_queue.clone());
    let logical_mount = unsafe { allocate_mount_id() }.map_err(|status| NtStatus(status as i32))?;
    unsafe { (&mut *core::ptr::addr_of_mut!(MOUNT_BINDINGS)).reserve(logical_mount) }
        .map_err(|_| NtStatus::INSUFFICIENT_RESOURCES)?;
    let device_id = match crate::driver_launch::register_kernel_volume_device(
        &driver_path,
        &device_path,
        alloc::boxed::Box::new(backend),
        &[
            nt_io_abi::major::IRP_MJ_CREATE,
            nt_io_abi::major::IRP_MJ_READ,
            nt_io_abi::major::IRP_MJ_WRITE,
            nt_io_abi::major::IRP_MJ_QUERY_INFORMATION,
            nt_io_abi::major::IRP_MJ_QUERY_VOLUME_INFORMATION,
            nt_io_abi::major::IRP_MJ_FILE_SYSTEM_CONTROL,
            nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL,
            nt_io_abi::major::IRP_MJ_CLEANUP,
            nt_io_abi::major::IRP_MJ_CLOSE,
        ],
    ) {
        Ok(device_id) => device_id,
        Err(status) => {
            unsafe { (&mut *core::ptr::addr_of_mut!(MOUNT_BINDINGS)).cancel(logical_mount) }
                .expect("failed volume registration left a prepared mount binding");
            return Err(status);
        }
    };
    unsafe {
        (&mut *core::ptr::addr_of_mut!(MOUNT_BINDINGS))
            .publish(logical_mount, nt_io_manager::DeviceId(device_id))
    }
    .expect("newly registered volume has a unique prepared mount binding");
    unsafe { *core::ptr::addr_of_mut!(MOUNT_CREATE_QUEUE) = Some(create_queue); }
    unsafe { *core::ptr::addr_of_mut!(MOUNT_OVERLAY_QUEUE) = Some(overlay_queue); }
    unsafe { *core::ptr::addr_of_mut!(MOUNT_READ_QUEUE) = Some(read_queue); }
    unsafe { *core::ptr::addr_of_mut!(MOUNT_DIRECTORY_QUEUE) = Some(directory_queue); }
    unsafe { *core::ptr::addr_of_mut!(EXEC_VOLUME_DEVICE) = Some(ExecVolumeDevice {
        physical_mount, logical_mount, device_id,
    }); }
    crate::print_str(b"[mounted-volume] registered ");
    crate::print_str(device_path.as_bytes());
    crate::print_str(b" device=");
    crate::print_hex((device_id >> 32) as u32);
    crate::print_hex(device_id as u32);
    crate::print_str(b"\n");
    let probe_ok = crate::driver_launch::probe_kernel_volume_file(&device_path);
    crate::print_str(
        b"[mounted-volume] canonical font metadata/retained-after-close read proof=",
    );
    crate::print_u64(probe_ok as u64);
    crate::print_str(b"\n");
    Ok((device_id, probe_ok, installed_root, device_path))
}
