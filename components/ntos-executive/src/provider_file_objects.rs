//! Provider File-object service operations.

use super::*;

unsafe fn service_win32k_retained_file_object_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    op: u64,
    object: u64,
    access: u64,
    mode: u64,
) -> (i32, u64, u64, u64) {
    use crate::win32k_subsystem::{
        W32_FILE_OBJECT_DEREFERENCE_POINTER, W32_FILE_OBJECT_LABEL,
        W32_FILE_OBJECT_REFERENCE_POINTER, W32_FILE_OBJECT_RELATED_DEVICE,
        W32_FILE_OBJECT_RELEASE_WAIT, W32_FILE_OBJECT_WAIT_IDENTITY,
    };
    let (route, dispatch) = match crate::provider_service_ingress::authenticate(
        channel,
        reply_cap,
        badge,
        mi,
        (W32_FILE_OBJECT_LABEL << 12) | 4,
    ) {
        Ok(owner) => owner,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    let source =
        match crate::provider_service_ingress::physical_win32k_provider(channel, route, dispatch) {
            Ok(source) => source,
            Err(status) => return (status as i32, 0, 0, 0),
        };
    let spawn_hosts::shared_ingress::owner::runtime::PhysicalDomain::Provider {
        catalog,
        domain: provider,
    } = source.domain
    else {
        return (nt_process::STATUS_INVALID_HANDLE as i32, 0, 0, 0);
    };
    let domain = match crate::driver_launch::win32k_device_consumer::retained_consumer_domain(
        catalog,
        provider,
        source.pml4,
    ) {
        Ok(domain) => domain,
        Err(status) => return (status, 0, 0, 0),
    };
    if SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) == 0 {
        return (0xC000_00A3u32 as i32, 0, 0, 0);
    }
    match op {
        W32_FILE_OBJECT_REFERENCE_POINTER if access == 0 && mode == 0 => {
            if crate::video_device::video_file_projection_contains(object) {
                return match crate::video_device::reference_video_file_pointer(domain, object) {
                    Ok(count) => (0, count, 0, 0),
                    Err(status) => (status, 0, 0, 0),
                };
            }
            match crate::driver_launch::win32k_file_owners::reference_pointer(domain, object) {
                Ok(count) => (0, count, 0, 0),
                Err(status) => (status, 0, 0, 0),
            }
        }
        W32_FILE_OBJECT_DEREFERENCE_POINTER if access == 0 && mode == 0 => {
            if crate::video_device::video_file_projection_contains(object) {
                return match crate::video_device::release_video_file_projection(domain, object) {
                    Ok(count) => (0, count, 0, 0),
                    Err(status) => (status, 0, 0, 0),
                };
            }
            match crate::driver_launch::win32k_file_owners::dereference_pointer(domain, object) {
                Ok(count) => (0, count, 0, 0),
                Err(status) => (status, 0, 0, 0),
            }
        }
        W32_FILE_OBJECT_RELATED_DEVICE if access == 0 && mode == 0 => {
            if crate::video_device::video_file_projection_contains(object) {
                return match crate::video_device::video_related_device_object(domain, object) {
                    Ok(device) => (0, device, 0, 0),
                    Err(status) => (status.raw(), 0, 0, 0),
                };
            }
            match crate::driver_launch::win32k_file_owners::related_device_address(domain, object) {
                Ok(device) => (0, device, 0, 0),
                Err(status) => (status, 0, 0, 0),
            }
        }
        W32_FILE_OBJECT_WAIT_IDENTITY if access == 0 && mode == 0 => {
            match crate::driver_launch::win32k_file_owners::acquire_wait_identity_for_event(
                domain, object,
            ) {
                Ok((identity, token)) => (
                    0,
                    identity.file_id().raw(),
                    identity.binding_generation(),
                    token,
                ),
                Err(status) => (status, 0, 0, 0),
            }
        }
        W32_FILE_OBJECT_RELEASE_WAIT if access == 0 && mode == 0 => {
            match crate::driver_launch::win32k_file_owners::release_wait_identity(domain, object) {
                Ok(()) => (0, 0, 0, 0),
                Err(status) => (status, 0, 0, 0),
            }
        }
        _ => (nt_process::STATUS_INVALID_PARAMETER as i32, 0, 0, 0),
    }
}

pub(crate) unsafe fn service_win32k_file_object_request(
    channel: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    op: u64,
    object: u64,
    access: u64,
    mode: u64,
) -> (i32, u64, u64, u64) {
    use crate::win32k_subsystem::{
        W32_FILE_OBJECT_DEREFERENCE_POINTER, W32_FILE_OBJECT_DEVICE_NAME, W32_FILE_OBJECT_LABEL,
        W32_FILE_OBJECT_OPEN_DEVICE, W32_FILE_OBJECT_REFERENCE_HANDLE,
        W32_FILE_OBJECT_REFERENCE_POINTER, W32_FILE_OBJECT_RELATED_DEVICE,
        W32_FILE_OBJECT_RELEASE_WAIT, W32_FILE_OBJECT_WAIT_IDENTITY,
    };
    if matches!(
        op,
        W32_FILE_OBJECT_REFERENCE_POINTER
            | W32_FILE_OBJECT_DEREFERENCE_POINTER
            | W32_FILE_OBJECT_RELATED_DEVICE
            | W32_FILE_OBJECT_WAIT_IDENTITY
            | W32_FILE_OBJECT_RELEASE_WAIT
    ) {
        return service_win32k_retained_file_object_request(
            channel, reply_cap, badge, mi, op, object, access, mode,
        );
    }
    let caller = match authenticate_win32k_service_request(
        channel,
        reply_cap,
        badge,
        mi,
        (W32_FILE_OBJECT_LABEL << 12) | 4,
    ) {
        Ok((_, _, caller)) => caller,
        Err(status) => return (status as i32, 0, 0, 0),
    };
    if SERVICE_DELAY_DRAIN_HANDLER.load(Ordering::Acquire) == 0 {
        return (0xC000_00A3u32 as i32, 0, 0, 0);
    }
    match op {
        W32_FILE_OBJECT_REFERENCE_HANDLE => {
            let (Ok(access), Ok(mode)) = (u32::try_from(access), u8::try_from(mode)) else {
                return (nt_process::STATUS_INVALID_PARAMETER as i32, 0, 0, 0);
            };
            let (status, pointer, granted, attributes) =
                crate::driver_launch::win32k_file_owners::reference_handle(
                    caller, object, access, mode,
                );
            (status, pointer, granted as u64, attributes as u64)
        }
        W32_FILE_OBJECT_OPEN_DEVICE => {
            let Ok(length) = usize::try_from(mode) else {
                return (nt_process::STATUS_INVALID_PARAMETER as i32, 0, 0, 0);
            };
            if access > u32::MAX as u64 || length == 0 || length & 1 != 0 {
                return (nt_process::STATUS_INVALID_PARAMETER as i32, 0, 0, 0);
            }
            let (_lease, packet) =
                match crate::win32k_subsystem::capture_provider_pool_packet(object, length) {
                    Ok(packet) => packet,
                    Err(status) => return (status as i32, 0, 0, 0),
                };
            let mut name = Vec::new();
            if name.try_reserve_exact(length / 2).is_err() {
                return (nt_process::STATUS_INSUFFICIENT_RESOURCES as i32, 0, 0, 0);
            }
            for unit in packet.chunks_exact(2) {
                name.push(u16::from_le_bytes([unit[0], unit[1]]));
            }
            match crate::video_device::video_get_device_object_pointer(&name, access as u32) {
                Ok((file, device)) => (0, file, device, 0),
                Err(status) => (status, 0, 0, 0),
            }
        }
        W32_FILE_OBJECT_DEVICE_NAME => {
            let Ok(length) = usize::try_from(access) else {
                return (nt_process::STATUS_INVALID_PARAMETER as i32, 0, 0, 0);
            };
            if length != nt_io_manager::file_object_name::FILE_OBJECT_NAME_SCRATCH_BYTES {
                return (nt_process::STATUS_INVALID_PARAMETER as i32, 0, 0, 0);
            }
            let (lease, mut packet) =
                match crate::win32k_subsystem::capture_provider_pool_packet(object, length) {
                    Ok(packet) => packet,
                    Err(status) => return (status as i32, 0, 0, 0),
                };
            let target = with_provider_process_manager(|pm| {
                pm.validate_native_handle_caller(caller)?;
                let (file_id, device_id) = pm.lookup_native_routed_file_handle(caller, mode, 0)?;
                let close = pm.inspect_native_close_target(caller, mode)?;
                if close.object() != (nt_process::HandleObject::RoutedFile { file_id, device_id }) {
                    return Err(nt_process::STATUS_INVALID_HANDLE);
                }
                Ok((file_id, device_id))
            });
            let (file_id, device_id) = match target {
                Ok(target) => target,
                Err(status) => return (status as i32, 0, 0, 0),
            };
            let io = crate::driver_launch::io_manager_mut();
            let name = match io.file(nt_io_manager::FileId(file_id)) {
                Some(file) if file.device_id.raw() == device_id => io
                    .device(file.device_id)
                    .map(|device| device.name.as_ref().map(|path| path.to_unicode_string())),
                _ => None,
            };
            let Some(name) = name else {
                return (nt_process::STATUS_INVALID_HANDLE as i32, 0, 0, 0);
            };
            let name = name.as_ref().map_or(&[][..], |name| name.as_units());
            let required = name.len().saturating_mul(2);
            if required > length - 4 || required > u16::MAX as usize - 1 {
                return (0x8000_0005u32 as i32, required as u64, 0, 0);
            }
            packet[..4].copy_from_slice(&(required as u32).to_le_bytes());
            for (index, unit) in name.iter().enumerate() {
                packet[4 + index * 2..6 + index * 2].copy_from_slice(&unit.to_le_bytes());
            }
            if !crate::win32k_subsystem::publish_provider_pool_packet(lease, &packet) {
                return (nt_process::STATUS_INVALID_HANDLE as i32, 0, 0, 0);
            }
            (0, required as u64, file_id, 0)
        }
        _ => (nt_process::STATUS_INVALID_PARAMETER as i32, 0, 0, 0),
    }
}
