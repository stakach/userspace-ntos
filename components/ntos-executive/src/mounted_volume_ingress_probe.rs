//! Native proof for the provider-originated canonical File dispatch boundary.

use alloc::vec::Vec;

use nt_io_abi::major;
use nt_io_manager::{CreateParameters, ReadWriteParameters};
use nt_types::UnicodeString;

pub(crate) unsafe fn run(device_id: u64) -> bool {
    let caller = crate::initial_system_driver_caller();
    let name = UnicodeString::from_str("reactos\\Fonts\\arial.ttf");
    let file = match crate::driver_launch::allocate_hosted_file(
        device_id,
        nt_types::AccessMask::GENERIC_READ.bits(),
        nt_io_manager::ShareAccess::READ.bits(),
        0,
        name.as_units(),
    ) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let opened = (|| -> Result<bool, u32> {
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
            || u64::from_le_bytes(standard[8..16].try_into().unwrap()) < 4
        {
            return Ok(false);
        }
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
        Ok(status == 0
            && information == signature.len() as u64
            && pending.is_none()
            && signature == [0, 1, 0, 0])
    })()
    .unwrap_or(false);
    let released = crate::driver_launch::release_hosted_file(file).is_ok();
    for _ in 0..4 {
        crate::driver_launch::pump_registered_file_lifecycle();
        if !crate::driver_launch::hosted_file_exists(file) {
            break;
        }
    }
    opened && released && !crate::driver_launch::hosted_file_exists(file)
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
    let relative = b"reactos\\system32\\version.dll";
    if !matches!(
        crate::writable_fs::query_metadata_relative(relative),
        Ok(None)
    ) {
        return false;
    }
    let caller = crate::initial_system_driver_caller();
    let name = UnicodeString::from_str("reactos\\system32\\version.dll");
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
