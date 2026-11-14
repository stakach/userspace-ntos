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

/// Rename the open overlay probe File the way the I/O Manager does for `MoveFileExW`: open the
/// directory that holds the new name with `SL_OPEN_TARGET_DIRECTORY`, then send the source File
/// `FileRenameInformation` naming that target File. The source is delete-on-close, so the
/// renamed entry leaves with it.
unsafe fn rename_overlay_file(
    device_id: u64,
    file: u64,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> bool {
    const OLD_RELATIVE: &[u8] = b"ntos-mount-probe.tmp";
    const NEW_RELATIVE: &[u8] = b"ntos-mount-probe.bak";
    const FILE_WRITE_DATA: u32 = 0x0000_0002;
    let name = UnicodeString::from_str("ntos-mount-probe.bak");
    let access = nt_types::AccessMask::from_bits_retain(FILE_WRITE_DATA)
        | nt_types::AccessMask::SYNCHRONIZE;
    let share = nt_io_manager::ShareAccess::READ | nt_io_manager::ShareAccess::WRITE;
    let options = nt_io_manager::CreateOptions::OPEN_FOR_BACKUP_INTENT;
    let target = match crate::driver_launch::allocate_hosted_file(
        device_id,
        access.bits(),
        share.bits(),
        options.bits(),
        name.as_units(),
    ) {
        Ok(target) => target,
        Err(_) => return false,
    };
    let renamed = (|| -> Result<bool, u32> {
        let mut input = Vec::new();
        input
            .try_reserve_exact(name.as_units().len() * 2)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw() as u32)?;
        for unit in name.as_units() {
            input.extend_from_slice(&unit.to_le_bytes());
        }
        let (status, information, pending, context) =
            crate::driver_launch::dispatch_hosted_target_directory_create_irp_result_exact(
                target,
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
        // A missing final component is reported, never failed. A leftover from an interrupted
        // earlier probe is reported as existing and replaced below.
        if status != 0
            || pending.is_some()
            || context.is_none()
            || !matches!(information as u32, nt_fs::FILE_EXISTS | nt_fs::FILE_DOES_NOT_EXIST)
        {
            return Ok(false);
        }
        // x64 FILE_RENAME_INFORMATION: ReplaceIfExists, RootDirectory, FileNameLength, FileName.
        let mut rename = Vec::new();
        rename
            .try_reserve_exact(20 + input.len())
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw() as u32)?;
        rename.resize(20, 0);
        rename[0] = 1;
        rename[16..20].copy_from_slice(&(input.len() as u32).to_le_bytes());
        rename.extend_from_slice(&input);
        let (status, _, pending, _) =
            crate::driver_launch::dispatch_hosted_file_set_information_irp_result_exact(
                file,
                caller,
                nt_io_manager::SetInformationParameters {
                    info_class: nt_fs::FILE_RENAME_INFORMATION,
                    length: rename.len() as u32,
                    target_file: Some(nt_io_manager::FileId(target)),
                    control: nt_io_manager::SetInformationControl::ReplaceIfExists(true),
                },
                &rename,
            )?;
        if status != 0 || pending.is_some() {
            return Ok(false);
        }
        Ok(matches!(crate::writable_fs::query_metadata_relative(OLD_RELATIVE), Ok(None))
            && matches!(
                crate::writable_fs::query_metadata_relative(NEW_RELATIVE),
                Ok(Some(metadata)) if !metadata.is_directory && metadata.end_of_file == 7
            ))
    })()
    .unwrap_or(false);
    // The target File is the I/O Manager's own: retire it whatever the rename returned.
    let retired = retire_probe_file(target, false);
    renamed && retired
}

unsafe fn set_file_information(
    file: u64,
    caller: nt_process::native_handle::NativeHandleCaller,
    info_class: u32,
    payload: &[u8],
) -> Result<bool, u32> {
    let (status, _, pending, _) =
        crate::driver_launch::dispatch_hosted_file_set_information_irp_result_exact(
            file,
            caller,
            nt_io_manager::SetInformationParameters {
                info_class,
                length: payload.len() as u32,
                target_file: None,
                control: nt_io_manager::SetInformationControl::None,
            },
            payload,
        )?;
    Ok(status == 0 && pending.is_none())
}

unsafe fn query_file_information(
    file: u64,
    caller: nt_process::native_handle::NativeHandleCaller,
    info_class: u32,
    output: &mut [u8],
) -> Result<bool, u32> {
    let (status, information, pending, _) =
        crate::driver_launch::dispatch_hosted_file_irp_result_exact(
            file,
            major::IRP_MJ_QUERY_INFORMATION as u64,
            info_class as u64,
            caller,
            &[],
            output,
            0,
        )?;
    Ok(status == 0 && pending.is_none() && information == output.len() as u64)
}

/// The classes `CopyFileW`, `SetFileAttributesW`, `SetFilePointer` and `DeleteFileW` set must
/// reach the opened File through the device stack and read back from it: position, a
/// timestamp and attributes, and a delete disposition that any handle can withdraw.
unsafe fn set_and_read_back_file_information(
    file: u64,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> Result<bool, u32> {
    const LAST_WRITE_TIME: u64 = 0x01DA_0000_0000_0000;
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x02;
    const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

    let mut position = [0u8; 8];
    if !set_file_information(file, caller, nt_fs::FILE_POSITION_INFORMATION, &3u64.to_le_bytes())?
        || !query_file_information(file, caller, nt_fs::FILE_POSITION_INFORMATION, &mut position)?
        || u64::from_le_bytes(position) != 3
    {
        return Ok(false);
    }

    // Zero times stay as they are; NORMAL beside another attribute means nothing.
    let mut basic = [0u8; 40];
    basic[16..24].copy_from_slice(&LAST_WRITE_TIME.to_le_bytes());
    basic[32..36].copy_from_slice(&(FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NORMAL).to_le_bytes());
    let mut stored = [0u8; 40];
    if !set_file_information(file, caller, nt_fs::FILE_BASIC_INFORMATION, &basic)?
        || !query_file_information(file, caller, nt_fs::FILE_BASIC_INFORMATION, &mut stored)?
        || u64::from_le_bytes(stored[16..24].try_into().unwrap()) != LAST_WRITE_TIME
        || u32::from_le_bytes(stored[32..36].try_into().unwrap()) != FILE_ATTRIBUTE_HIDDEN
    {
        return Ok(false);
    }

    let mut standard = [0u8; 24];
    for delete in [true, false] {
        if !set_file_information(
            file,
            caller,
            nt_fs::FILE_DISPOSITION_INFORMATION,
            &[delete as u8],
        )? || !query_file_information(
            file,
            caller,
            nt_fs::FILE_STANDARD_INFORMATION,
            &mut standard,
        )? || standard[20] != delete as u8
        {
            return Ok(false);
        }
    }
    Ok(true)
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
        if status != 0 || pending.is_some() || information != bytes.len() as u64 || read != *bytes {
            return Ok(false);
        }
        // SET_INFORMATION and FLUSH_BUFFERS must reach the opened File too: truncate it through
        // the device stack, read the new size back, and flush.
        let end_of_file = 7u64.to_le_bytes();
        let (status, _, pending, _) =
            crate::driver_launch::dispatch_hosted_file_set_information_irp_result_exact(
                file,
                caller,
                nt_io_manager::SetInformationParameters {
                    info_class: nt_fs::FILE_END_OF_FILE_INFORMATION,
                    length: end_of_file.len() as u32,
                    target_file: None,
                    control: nt_io_manager::SetInformationControl::None,
                },
                &end_of_file,
            )?;
        if status != 0 || pending.is_some() {
            return Ok(false);
        }
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
            || u64::from_le_bytes(standard[8..16].try_into().unwrap()) != 7
        {
            return Ok(false);
        }
        let (status, _, pending, _) = crate::driver_launch::dispatch_hosted_file_irp_result_exact(
            file,
            major::IRP_MJ_FLUSH_BUFFERS as u64,
            0,
            caller,
            &[],
            &mut [],
            0,
        )?;
        if status != 0 || pending.is_some() {
            return Ok(false);
        }
        if !set_and_read_back_file_information(file, caller)? {
            return Ok(false);
        }
        Ok(rename_overlay_file(device_id, file, caller))
    })()
    .unwrap_or(false);
    let released = crate::driver_launch::release_hosted_file(file).is_ok();
    for _ in 0..4 {
        crate::driver_launch::pump_registered_file_lifecycle();
        if !crate::driver_launch::hosted_file_exists(file) {
            break;
        }
    }
    // The File was opened delete-on-close and this was its only handle: its entry, under the
    // name the rename gave it, left the namespace with it.
    tested
        && released
        && !crate::driver_launch::hosted_file_exists(file)
        && matches!(
            crate::writable_fs::query_metadata_relative(b"ntos-mount-probe.bak"),
            Ok(None)
        )
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
