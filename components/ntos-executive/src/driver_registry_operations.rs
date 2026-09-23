//! Owned registry results shared by native driver and Win32k transports.

use super::{driver_registry_live_handler, DriverRegistryHandleTarget};
use alloc::{string::String, vec::Vec};

pub(crate) unsafe fn query_value(
    target: DriverRegistryHandleTarget,
    name: &str,
) -> Result<(u32, Vec<u8>), i32> {
    match target {
        DriverRegistryHandleTarget::Hosted { key, .. } => driver_registry_live_handler()?
            .registry_value_with_result(key, name, |ty, bytes| (ty, bytes.to_vec()))
            .map_err(|status| status as i32)?
            .ok_or(0xc000_0034u32 as i32),
        DriverRegistryHandleTarget::System { lease, .. } => {
            crate::config_manager_query_leased_system_hive_value(lease, name)
                .map(|value| (value.value_type, value.data))
        }
        DriverRegistryHandleTarget::Generic { key, .. } => {
            crate::config_manager_runtime_key_operation(
                key,
                nt_config_abi::runtime_key_op::VALUE,
                0,
                name,
                0,
                &[],
            )
            .and_then(|(reply, data)| {
                Ok((
                    u32::try_from(reply.detail0).map_err(|_| 0xc000_000du32 as i32)?,
                    data,
                ))
            })
        }
    }
}

pub(crate) unsafe fn query_key(
    target: DriverRegistryHandleTarget,
    class: u32,
) -> Result<(Vec<u8>, usize), i32> {
    let (path, stats, class_name) = match target {
        DriverRegistryHandleTarget::Hosted { key, path } => {
            let handler = driver_registry_live_handler()?;
            (
                String::from(path.as_str()),
                handler
                    .registry_key_stats(key)
                    .map_err(|status| status as i32)?,
                handler
                    .registry_key_class(key)
                    .map_err(|status| status as i32)?,
            )
        }
        DriverRegistryHandleTarget::System {
            lease,
            physical_path,
        } => {
            let information =
                crate::config_manager_query_leased_system_hive_key_information(lease)?;
            (
                String::from(physical_path.as_str()),
                crate::exec_handler::RegistryKeyStats::from_leased_key(&information),
                information.class_name,
            )
        }
        DriverRegistryHandleTarget::Generic { key, path } => {
            let (_, data) = crate::config_manager_runtime_key_operation(
                key,
                nt_config_abi::runtime_key_op::INFO,
                0,
                "",
                0,
                &[],
            )?;
            if data.len() != core::mem::size_of::<nt_config_abi::CmRuntimeKeyInfo>() {
                return Err(0xc000_000du32 as i32);
            }
            let info =
                core::ptr::read_unaligned(data.as_ptr() as *const nt_config_abi::CmRuntimeKeyInfo);
            (
                String::from(path.as_str()),
                crate::exec_handler::RegistryKeyStats::from_runtime_key(info),
                crate::config_manager_runtime_key_class(key)?,
            )
        }
    };
    crate::exec_handler::build_registry_key_query_info(class, &path, stats, class_name.as_deref())
        .map_err(|status| status as i32)
}

pub(crate) unsafe fn enumerate_value(
    target: DriverRegistryHandleTarget,
    index: u32,
    class: u64,
) -> Result<(Vec<u8>, usize), i32> {
    let (name, ty, data) = match target {
        DriverRegistryHandleTarget::Hosted { key, .. } => driver_registry_live_handler()?
            .registry_value_by_index_with(key, index as usize, |name, ty, bytes, _| {
                (String::from(name), ty, bytes.to_vec())
            })
            .map_err(|status| status as i32)?
            .ok_or(0x8000_001au32 as i32)?,
        DriverRegistryHandleTarget::System { lease, .. } => {
            let value = crate::config_manager_enumerate_leased_system_hive_value(lease, index)?;
            (value.name, value.value_type, value.data)
        }
        DriverRegistryHandleTarget::Generic { key, .. } => {
            let (reply, data) = crate::config_manager_runtime_key_operation(
                key,
                nt_config_abi::runtime_key_op::ENUM_VALUE,
                index,
                "",
                0,
                &[],
            )?;
            let length = usize::try_from(reply.detail1).map_err(|_| 0xc000_000du32 as i32)?;
            if length > data.len() {
                return Err(0xc000_000du32 as i32);
            }
            (
                decode_name(&data[..length])?,
                u32::try_from(reply.detail0).map_err(|_| 0xc000_000du32 as i32)?,
                data[length..].to_vec(),
            )
        }
    };
    crate::exec_handler::build_registry_value_query_info(class, &name, ty, &data)
        .map_err(|status| status as i32)
}

pub(crate) unsafe fn set_value(
    target: DriverRegistryHandleTarget,
    name: &str,
    ty: u32,
    data: &[u8],
) -> Result<(), i32> {
    match target {
        DriverRegistryHandleTarget::Hosted { key, .. } => {
            let status =
                driver_registry_live_handler()?.registry_target_set_value(key, name, ty, data);
            if status == 0 {
                Ok(())
            } else {
                Err(status as i32)
            }
        }
        DriverRegistryHandleTarget::System { .. } => {
            unreachable!("SYSTEM value SET requires retained mutation work")
        }
        DriverRegistryHandleTarget::Generic { key, .. } => {
            crate::config_manager_runtime_key_operation(
                key,
                nt_config_abi::runtime_key_op::SET_VALUE,
                0,
                name,
                ty,
                data,
            )
            .map(|_| ())
        }
    }
}

pub(crate) unsafe fn delete_value(
    target: DriverRegistryHandleTarget,
    name: &str,
) -> Result<(), i32> {
    match target {
        DriverRegistryHandleTarget::Hosted { key, .. } => {
            let status = driver_registry_live_handler()?.registry_target_delete_value(key, name);
            if status == 0 {
                Ok(())
            } else {
                Err(status as i32)
            }
        }
        DriverRegistryHandleTarget::System { .. } => {
            unreachable!("SYSTEM value DELETE requires retained mutation work")
        }
        DriverRegistryHandleTarget::Generic { key, .. } => {
            crate::config_manager_runtime_key_operation(
                key,
                nt_config_abi::runtime_key_op::DELETE_VALUE,
                0,
                name,
                0,
                &[],
            )
            .map(|_| ())
        }
    }
}

pub(crate) fn decode_name(data: &[u8]) -> Result<String, i32> {
    if data.len() % 2 != 0 {
        return Err(0xc000_000du32 as i32);
    }
    let units: Vec<u16> = data
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect();
    String::from_utf16(&units).map_err(|_| 0xc000_000du32 as i32)
}
