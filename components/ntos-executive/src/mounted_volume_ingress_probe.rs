//! Native proof for the provider-originated canonical File dispatch boundary.

use alloc::vec::Vec;

use nt_io_abi::major;
use nt_io_manager::{CreateParameters, ReadWriteParameters};
use nt_types::UnicodeString;

unsafe fn query_fat32_attributes(
    file: u64,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> bool {
    let mut volume = [0u8; 64];
    match crate::driver_launch::dispatch_hosted_file_query_volume_information_irp_result_exact(
        file,
        caller,
        nt_io_manager::QueryVolumeInformationParameters {
            information_class: nt_fs::FILE_FS_ATTRIBUTE_INFORMATION,
            length: volume.len() as u32,
        },
        &mut volume,
    ) {
        Ok((status, information, pending, _)) => status == 0
            && pending.is_none()
            && information == 22
            && u32::from_le_bytes(volume[0..4].try_into().unwrap())
                == (nt_fs::FILE_CASE_PRESERVED_NAMES | nt_fs::FILE_UNICODE_ON_DISK)
            && u32::from_le_bytes(volume[4..8].try_into().unwrap()) == 255
            && u32::from_le_bytes(volume[8..12].try_into().unwrap()) == 10
            && volume[12..22] == [b'F', 0, b'A', 0, b'T', 0, b'3', 0, b'2', 0],
        Err(_) => false,
    }
}

unsafe fn retire_probe_file(file: u64, published: bool) -> bool {
    let released = if published {
        crate::driver_launch::release_hosted_file(file)
    } else {
        crate::driver_launch::abandon_unpublished_hosted_file(file)
    }
    .is_ok();
    for _ in 0..4 {
        crate::driver_launch::pump_registered_file_lifecycle();
        if !crate::driver_launch::hosted_file_exists(file) {
            break;
        }
    }
    released && !crate::driver_launch::hosted_file_exists(file)
}

pub(crate) unsafe fn run(device_id: u64) -> (bool, bool) {
    let caller = crate::initial_system_driver_caller();
    let name = UnicodeString::from_str(crate::installed_layout::ARIAL_STR);
    let file = match crate::driver_launch::allocate_hosted_file(
        device_id,
        nt_types::AccessMask::GENERIC_READ.bits(),
        nt_io_manager::ShareAccess::READ.bits(),
        0,
        name.as_units(),
    ) {
        Ok(file) => file,
        Err(_) => return (false, false),
    };
    let opened = (|| -> Result<(bool, bool), u32> {
        let mut input = Vec::new();
        input
            .try_reserve_exact(name.as_units().len() * 2)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw() as u32)?;
        for unit in name.as_units() {
            input.extend_from_slice(&unit.to_le_bytes());
        }
        let (status, _, pending, context) =
            crate::driver_launch::dispatch_hosted_file_create_irp_result_exact(
                file,
                major::IRP_MJ_CREATE,
                caller,
                CreateParameters {
                    desired_access: nt_types::AccessMask::GENERIC_READ,
                    share_access: nt_io_manager::ShareAccess::READ,
                    create_disposition: nt_fs::FILE_OPEN,
                    ..CreateParameters::default()
                },
                &input,
            )?;
        if status != 0 || pending.is_some() || context.is_none() {
            return Ok((false, false));
        }
        let mut standard = [0u8; 24];
        let (status, information, pending, _) =
            crate::driver_launch::dispatch_hosted_file_irp_result_exact(
                file,
                major::IRP_MJ_QUERY_INFORMATION as u64,
                nt_fs::FILE_STANDARD_INFORMATION as u64,
                caller,
                &[],
                &mut standard,
                0,
            )?;
        if status != 0
            || information != standard.len() as u64
            || pending.is_some()
            || u64::from_le_bytes(standard[8..16].try_into().unwrap()) < 4
        {
            return Ok((false, false));
        }
        let volume_attribute = query_fat32_attributes(file, caller);
        let mut signature = [0u8; 4];
        let (status, information, pending, _) =
            crate::driver_launch::dispatch_hosted_file_read_write_irp_result_exact(
                file,
                major::IRP_MJ_READ,
                caller,
                ReadWriteParameters {
                    length: signature.len() as u32,
                    key: 0,
                    offset: 0,
                },
                &[],
                &mut signature,
            )?;
        Ok((status == 0
            && information == signature.len() as u64
            && pending.is_none()
            && signature == [0, 1, 0, 0],
            volume_attribute))
    })()
    .unwrap_or((false, false));
    let retired = retire_probe_file(file, true);
    (opened.0 && retired, opened.1 && retired)
}

unsafe fn conflicting_volume_open(device_id: u64, caller: nt_process::native_handle::NativeHandleCaller) -> bool {
    const FILE_GENERIC_READ: u32 = 0x0012_0089;
    let file = match crate::driver_launch::allocate_hosted_file(
        device_id, FILE_GENERIC_READ, 0, nt_fs::FILE_SYNCHRONOUS_IO_ALERT, &[],
    ) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let denied = matches!(
        crate::driver_launch::dispatch_hosted_file_create_irp_result_exact(
            file,
            major::IRP_MJ_CREATE,
            caller,
            CreateParameters {
                opened_case_sensitive: true,
                desired_access: nt_types::AccessMask::from_bits_retain(FILE_GENERIC_READ),
                share_access: nt_io_manager::ShareAccess::empty(),
                create_options: nt_io_manager::CreateOptions::from_bits_retain(
                    nt_fs::FILE_SYNCHRONOUS_IO_ALERT,
                ),
                create_disposition: nt_fs::FILE_OPEN,
                ..CreateParameters::default()
            },
            &[],
        ),
        Ok((status, 0, None, None)) if status as u32 == nt_fs::STATUS_SHARING_VIOLATION
    );
    let retired = retire_probe_file(file, false);
    denied && retired
}

unsafe fn query_volume_dirty(
    file: u64,
    caller: nt_process::native_handle::NativeHandleCaller,
    expected_dirty: bool,
) -> bool {
    let mut mask = [0xa5; 4];
    matches!(
        crate::driver_launch::dispatch_hosted_file_irp_result_exact(
            file,
            major::IRP_MJ_FILE_SYSTEM_CONTROL as u64,
            nt_fs::FSCTL_IS_VOLUME_DIRTY as u64,
            caller,
            &[],
            &mut mask,
            0,
        ),
        Ok((0, 4, None, _))
    ) && u32::from_le_bytes(mask) == u32::from(expected_dirty)
}

/// The empty FileName is a volume File; a single backslash is the root directory instead.
/// Autochk opens the former without OBJ_CASE_INSENSITIVE before querying and controlling it.
pub(crate) unsafe fn run_volume_open(device_id: u64, expected_dirty: bool) -> (bool, bool) {
    const FILE_GENERIC_READ: u32 = 0x0012_0089;
    let caller = crate::initial_system_driver_caller();
    let file = match crate::driver_launch::allocate_hosted_file(
        device_id,
        FILE_GENERIC_READ,
        (nt_io_manager::ShareAccess::READ | nt_io_manager::ShareAccess::WRITE).bits(),
        nt_fs::FILE_SYNCHRONOUS_IO_ALERT,
        &[],
    ) {
        Ok(file) => file,
        Err(_) => return (false, false),
    };
    let mut published = false;
    let tested = (|| -> Result<(bool, bool), u32> {
        let (status, information, pending, context) =
            crate::driver_launch::dispatch_hosted_file_create_irp_result_exact(
                file,
                major::IRP_MJ_CREATE,
                caller,
                CreateParameters {
                    opened_case_sensitive: true,
                    desired_access: nt_types::AccessMask::from_bits_retain(FILE_GENERIC_READ),
                    share_access: nt_io_manager::ShareAccess::READ
                        | nt_io_manager::ShareAccess::WRITE,
                    create_options: nt_io_manager::CreateOptions::from_bits_retain(
                        nt_fs::FILE_SYNCHRONOUS_IO_ALERT,
                    ),
                    create_disposition: nt_fs::FILE_OPEN,
                    ..CreateParameters::default()
                },
                &[],
            )?;
        published = status == 0 && pending.is_none() && context.is_some();
        if !published || information != nt_fs::FILE_OPENED as u64 {
            return Ok((false, false));
        }
        let dirty = query_volume_dirty(file, caller, expected_dirty);
        Ok((query_fat32_attributes(file, caller)
            && conflicting_volume_open(device_id, caller), dirty))
    })()
    .unwrap_or((false, false));
    let retired = retire_probe_file(file, published);
    (tested.0 && retired, tested.1 && retired)
}

pub(crate) unsafe fn run_directory(device_id: u64) -> bool {
    let caller = crate::initial_system_driver_caller();
    let name = UnicodeString::from_str(crate::installed_layout::FONTS_STR);
    let access = nt_types::AccessMask::GENERIC_READ;
    let share = nt_io_manager::ShareAccess::READ;
    let options = nt_io_manager::CreateOptions::DIRECTORY_FILE;
    let file = match crate::driver_launch::allocate_hosted_file(
        device_id,
        access.bits(),
        share.bits(),
        options.bits(),
        name.as_units(),
    ) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let tested = (|| -> Result<bool, u32> {
        let mut input = Vec::new();
        input
            .try_reserve_exact(name.as_units().len() * 2)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw() as u32)?;
        for unit in name.as_units() {
            input.extend_from_slice(&unit.to_le_bytes());
        }
        let (status, information, pending, context) =
            crate::driver_launch::dispatch_hosted_file_create_irp_result_exact(
                file,
                major::IRP_MJ_CREATE,
                caller,
                CreateParameters {
                    desired_access: access,
                    share_access: share,
                    create_options: options,
                    create_disposition: nt_fs::FILE_OPEN,
                    ..CreateParameters::default()
                },
                &input,
            )?;
        if status != 0
            || information != nt_fs::FILE_OPENED as u64
            || pending.is_some()
            || context.is_none()
        {
            return Ok(false);
        }
        let mut standard = [0u8; 24];
        let (status, information, pending, _) =
            crate::driver_launch::dispatch_hosted_file_irp_result_exact(
                file,
                major::IRP_MJ_QUERY_INFORMATION as u64,
                nt_fs::FILE_STANDARD_INFORMATION as u64,
                caller,
                &[],
                &mut standard,
                0,
            )?;
        if status != 0
            || information != standard.len() as u64
            || pending.is_some()
            || standard[21] != 1
        {
            return Ok(false);
        }
        let pattern = UnicodeString::from_str("arial.ttf");
        let parameters = nt_io_manager::DirectoryQueryParameters {
            length: 512,
            information_class: nt_fs::FILE_NAMES_INFORMATION,
            file_index: 0,
            pattern: Some(pattern),
        };
        let mut entries = [0u8; 512];
        let query = |flags, entries: &mut [u8; 512]| {
            crate::driver_launch::dispatch_hosted_file_directory_query_result_exact(
                file,
                caller,
                parameters.clone(),
                flags,
                entries,
            )
        };
        let flags = nt_io_manager::StackFlags::RESTART_SCAN
            | nt_io_manager::StackFlags::RETURN_SINGLE_ENTRY;
        let (status, information, pending) = query(flags, &mut entries)?;
        let expected: Vec<u16> = "arial.ttf".encode_utf16().collect();
        let actual_len = u32::from_le_bytes(entries[8..12].try_into().unwrap()) as usize;
        if status != 0
            || pending.is_some()
            || actual_len != expected.len() * 2
            || information < (12 + actual_len) as u64
            || entries[12..12 + actual_len]
                .chunks_exact(2)
                .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
                .collect::<Vec<_>>()
                != expected
        {
            return Ok(false);
        }
        let (status, information, pending) = query(
            nt_io_manager::StackFlags::RETURN_SINGLE_ENTRY,
            &mut entries,
        )?;
        if status as u32 != nt_fs::STATUS_NO_MORE_FILES || information != 0 || pending.is_some() {
            return Ok(false);
        }
        let (status, information, pending) = query(flags, &mut entries)?;
        Ok(status == 0 && information >= (12 + actual_len) as u64 && pending.is_none())
    })()
    .unwrap_or(false);
    let released = crate::driver_launch::release_hosted_file(file).is_ok();
    for _ in 0..4 {
        crate::driver_launch::pump_registered_file_lifecycle();
        if !crate::driver_launch::hosted_file_exists(file) {
            break;
        }
    }
    tested && released && !crate::driver_launch::hosted_file_exists(file)
}

pub(crate) unsafe fn run_overlay(device_id: u64) -> bool {
    let caller = crate::initial_system_driver_caller();
    let name = UnicodeString::from_str("ntos-mount-probe.tmp");
    let access = nt_types::AccessMask::GENERIC_READ
        | nt_types::AccessMask::GENERIC_WRITE
        | nt_types::AccessMask::DELETE;
    let share = nt_io_manager::ShareAccess::READ
        | nt_io_manager::ShareAccess::WRITE
        | nt_io_manager::ShareAccess::DELETE;
    let options = nt_io_manager::CreateOptions::DELETE_ON_CLOSE;
    let file = match crate::driver_launch::allocate_hosted_file(
        device_id,
        access.bits(),
        share.bits(),
        options.bits(),
        name.as_units(),
    ) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let tested = (|| -> Result<bool, u32> {
        let mut input = Vec::new();
        input
            .try_reserve_exact(name.as_units().len() * 2)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw() as u32)?;
        for unit in name.as_units() {
            input.extend_from_slice(&unit.to_le_bytes());
        }
        let (status, _, pending, context) =
            crate::driver_launch::dispatch_hosted_file_create_irp_result_exact(
                file,
                major::IRP_MJ_CREATE,
                caller,
                CreateParameters {
                    desired_access: access,
                    share_access: share,
                    create_options: options,
                    create_disposition: nt_fs::FILE_OVERWRITE_IF,
                    ..CreateParameters::default()
                },
                &input,
            )?;
        if status != 0 || pending.is_some() || context.is_none() {
            return Ok(false);
        }
        let bytes = b"mounted-overlay";
        let (status, information, pending, _) =
            crate::driver_launch::dispatch_hosted_file_read_write_irp_result_exact(
                file,
                major::IRP_MJ_WRITE,
                caller,
                ReadWriteParameters {
                    length: bytes.len() as u32,
                    key: 0,
                    offset: 0,
                },
                bytes,
                &mut [],
            )?;
        if status != 0 || pending.is_some() || information != bytes.len() as u64 {
            return Ok(false);
        }
        let mut standard = [0u8; 24];
        let (status, information, pending, _) =
            crate::driver_launch::dispatch_hosted_file_irp_result_exact(
                file,
                major::IRP_MJ_QUERY_INFORMATION as u64,
                nt_fs::FILE_STANDARD_INFORMATION as u64,
                caller,
                &[],
                &mut standard,
                0,
            )?;
        if status != 0
            || information != standard.len() as u64
            || pending.is_some()
            || u64::from_le_bytes(standard[8..16].try_into().unwrap()) != bytes.len() as u64
        {
            return Ok(false);
        }
        let mut read = [0u8; 15];
        let (status, information, pending, _) =
            crate::driver_launch::dispatch_hosted_file_read_write_irp_result_exact(
                file,
                major::IRP_MJ_READ,
                caller,
                ReadWriteParameters {
                    length: read.len() as u32,
                    key: 0,
                    offset: 0,
                },
                &[],
                &mut read,
            )?;
        Ok(status == 0 && pending.is_none() && information == bytes.len() as u64 && read == *bytes)
    })()
    .unwrap_or(false);
    let released = crate::driver_launch::release_hosted_file(file).is_ok();
    for _ in 0..4 {
        crate::driver_launch::pump_registered_file_lifecycle();
        if !crate::driver_launch::hosted_file_exists(file) {
            break;
        }
    }
    tested && released && !crate::driver_launch::hosted_file_exists(file)
}

pub(crate) unsafe fn run_copy_up(device_id: u64) -> bool {
    let relative = crate::installed_layout::VERSION_DLL;
    if !matches!(
        crate::writable_fs::query_metadata_relative(relative),
        Ok(None)
    ) {
        return false;
    }
    let caller = crate::initial_system_driver_caller();
    let name = UnicodeString::from_str(crate::installed_layout::VERSION_DLL_STR);
    let access = nt_types::AccessMask::GENERIC_READ
        | nt_types::AccessMask::GENERIC_WRITE
        | nt_types::AccessMask::DELETE;
    let share = nt_io_manager::ShareAccess::READ
        | nt_io_manager::ShareAccess::WRITE
        | nt_io_manager::ShareAccess::DELETE;
    let options = nt_io_manager::CreateOptions::DELETE_ON_CLOSE;
    let file = match crate::driver_launch::allocate_hosted_file(
        device_id,
        access.bits(),
        share.bits(),
        options.bits(),
        name.as_units(),
    ) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let tested = (|| -> Result<bool, u32> {
        let mut input = Vec::new();
        input
            .try_reserve_exact(name.as_units().len() * 2)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw() as u32)?;
        for unit in name.as_units() {
            input.extend_from_slice(&unit.to_le_bytes());
        }
        let (status, _, pending, context) =
            crate::driver_launch::dispatch_hosted_file_create_irp_result_exact(
                file,
                major::IRP_MJ_CREATE,
                caller,
                CreateParameters {
                    desired_access: access,
                    share_access: share,
                    create_options: options,
                    create_disposition: nt_fs::FILE_OPEN,
                    ..CreateParameters::default()
                },
                &input,
            )?;
        if status != 0 || pending.is_some() || context.is_none() {
            return Ok(false);
        }
        let Some(metadata) = crate::writable_fs::query_metadata_relative(relative)? else {
            return Ok(false);
        };
        if metadata.end_of_file < 0x4000 {
            return Ok(false);
        }
        let mut signature = [0u8; 2];
        let (status, information, pending, _) =
            crate::driver_launch::dispatch_hosted_file_read_write_irp_result_exact(
                file,
                major::IRP_MJ_READ,
                caller,
                ReadWriteParameters {
                    length: 2,
                    key: 0,
                    offset: 0,
                },
                &[],
                &mut signature,
            )?;
        if status != 0 || information != 2 || pending.is_some() || signature != *b"MZ" {
            return Ok(false);
        }
        let (status, information, pending, _) =
            crate::driver_launch::dispatch_hosted_file_read_write_irp_result_exact(
                file,
                major::IRP_MJ_WRITE,
                caller,
                ReadWriteParameters {
                    length: 2,
                    key: 0,
                    offset: 0,
                },
                b"NT",
                &mut [],
            )?;
        if status != 0 || information != 2 || pending.is_some() {
            return Ok(false);
        }
        let (status, information, pending, _) =
            crate::driver_launch::dispatch_hosted_file_read_write_irp_result_exact(
                file,
                major::IRP_MJ_READ,
                caller,
                ReadWriteParameters {
                    length: 2,
                    key: 0,
                    offset: 0,
                },
                &[],
                &mut signature,
            )?;
        Ok(status == 0 && information == 2 && pending.is_none() && signature == *b"NT")
    })()
    .unwrap_or(false);
    let released = crate::driver_launch::release_hosted_file(file).is_ok();
    for _ in 0..4 {
        crate::driver_launch::pump_registered_file_lifecycle();
        if !crate::driver_launch::hosted_file_exists(file) {
            break;
        }
    }
    tested
        && released
        && !crate::driver_launch::hosted_file_exists(file)
        && matches!(
            crate::writable_fs::query_metadata_relative(relative),
            Ok(None)
        )
}
