//! Capture a provider-mutated FILE_OBJECT name before retiring a reparsed CREATE.

use super::*;

const STATUS_IO_REPARSE_DATA_INVALID: u32 = 0xc000_0278;
const FILE_NAME_OFFSET: u64 = 0x58;

#[repr(C)]
#[derive(Clone, Copy)]
struct UnicodeString64 {
    length: u16,
    maximum_length: u16,
    _padding: u32,
    buffer: u64,
}

const _: () = assert!(core::mem::size_of::<UnicodeString64>() == 16);

unsafe fn copy_live_name(
    instance: DriverInstance,
    file_object: u64,
) -> Result<Vec<u16>, u32> {
    let object = hosted_instance_pool_allocation_exec_if_live(
        instance,
        file_object,
        WDM_X64_FILE_OBJECT_SIZE as u64,
    )
    .ok_or(STATUS_IO_REPARSE_DATA_INVALID)?;
    if read_unaligned(object as *const i16) != nt_io_manager::WDM_X64_IO_TYPE_FILE
        || read_unaligned((object + 2) as *const u16) != WDM_X64_FILE_OBJECT_SIZE as u16
    {
        return Err(STATUS_IO_REPARSE_DATA_INVALID);
    }
    let name = read_unaligned((object + FILE_NAME_OFFSET) as *const UnicodeString64);
    if name.length == 0
        || name.length & 1 != 0
        || name.maximum_length & 1 != 0
        || name.length > name.maximum_length
        || name.buffer == 0
        || name.buffer & 1 != 0
    {
        return Err(STATUS_IO_REPARSE_DATA_INVALID);
    }
    let buffer = hosted_instance_pool_allocation_exec_if_live(
        instance,
        name.buffer,
        u64::from(name.length),
    )
    .ok_or(STATUS_IO_REPARSE_DATA_INVALID)?;
    let mut units = Vec::new();
    units
        .try_reserve_exact(usize::from(name.length / 2))
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES as u32)?;
    for offset in (0..u64::from(name.length)).step_by(2) {
        units.push(read_unaligned((buffer + offset) as *const u16));
    }
    if units.first() != Some(&(b'\\' as u16)) || units.contains(&0) {
        return Err(STATUS_IO_REPARSE_DATA_INVALID);
    }
    Ok(units)
}

/// The File binding and physical domain identify the only provider allocation authorized for
/// this reparse. A publication lease pins it while the mutable name is copied into executive
/// memory; no provider pointer escapes this call.
pub(super) unsafe fn capture(file_id: u64, device_id: u64) -> Result<Vec<u16>, u32> {
    let file = FileId(file_id);
    io_manager_mut()
        .file(file)
        .filter(|record| {
            record.client_id == ClientId(IO_MANAGER_COMPONENT_ID)
                && record.device_id == nt_io_manager::DeviceId(device_id)
        })
        .ok_or(STATUS_INVALID_HANDLE as u32)?;
    let (route_instance, _, _) =
        hosted_driver_device_route_by_device_id(device_id).ok_or(STATUS_INVALID_HANDLE as u32)?;
    let projection_instance = hosted_device_binding_by_device_id(device_id)
        .map_or(route_instance, |binding| binding.projection_instance);
    let instance = instance(projection_instance).ok_or(STATUS_INVALID_HANDLE as u32)?;
    let domain = instance_domain_identity(instance).ok_or(STATUS_INVALID_HANDLE as u32)?;
    let identities = io_manager_mut()
        .hosted_file_identities(file)
        .map_err(|status| status.raw() as u32)?;
    let mut matching = identities.into_iter().filter(|identity| identity.domain() == domain);
    let identity = matching.next().ok_or(STATUS_INVALID_HANDLE as u32)?;
    if matching.next().is_some() {
        return Err(STATUS_IO_REPARSE_DATA_INVALID);
    }
    let mut lease = io_manager_mut()
        .lease_hosted_file_identity(identity)
        .map_err(|status| status.raw() as u32)?;
    let result = copy_live_name(instance, identity.address());
    io_manager_mut()
        .release_hosted_file_publication(&mut lease)
        .expect("reparse capture lost its exact File projection lease");
    result
}
