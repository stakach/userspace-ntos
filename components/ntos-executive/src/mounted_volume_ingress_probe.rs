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
