//! Bounded buffered device controls issued by win32k's keyboard initialization.

use super::*;
use core::sync::atomic::AtomicBool;
use nt_io_abi::ioctl;
use nt_io_manager::win32k_buffered_ioctl_wire::{
    self as wire, BufferedIoctlRequest, BufferedIoctlResponse,
};
use nt_provider_wait::ProviderStackLanePin;

struct PendingIoctl {
    local_id: u64,
    token: u64,
    handle: u64,
    activation: ProviderStackEventActivation,
    iosb_pin: Option<ProviderStackLanePin>,
    output_pin: Option<file_ioctl_target::PinnedIoctlOutput>,
}

const MAX_PENDING_IOCTL: usize = 64;
static IOCTLS_BUSY: AtomicBool = AtomicBool::new(false);
static mut PENDING_IOCTLS: [Option<PendingIoctl>; MAX_PENDING_IOCTL] =
    [const { None }; MAX_PENDING_IOCTL];
static mut NEXT_IOCTL_ID: u64 = 1;

struct IoctlsGuard;

impl IoctlsGuard {
    fn acquire() -> Self {
        while IOCTLS_BUSY
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }
}

impl Drop for IoctlsGuard {
    fn drop(&mut self) {
        IOCTLS_BUSY.store(false, Ordering::Release);
    }
}

unsafe fn reserve_ioctl(
    handle: u64,
    activation: ProviderStackEventActivation,
    iosb: u64,
    output: u64,
    output_length: u32,
) -> Result<u64, i32> {
    let _guard = IoctlsGuard::acquire();
    let ioctls = &mut *core::ptr::addr_of_mut!(PENDING_IOCTLS);
    let slot = ioctls
        .iter()
        .position(Option::is_none)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES_I32)?;
    let local_id = *core::ptr::addr_of!(NEXT_IOCTL_ID);
    let next = local_id
        .checked_add(1)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES_I32)?;
    let (_, iosb_pin) = {
        let mut metadata = ProviderMetadataGuard::acquire();
        provider_input::stack_catalog_mut(&mut metadata)
            .ok_or(STATUS_NOT_SUPPORTED_I32)?
            .pin_active_range(activation, iosb, 16)
            .map_err(|_| STATUS_ACCESS_VIOLATION_I32)?
    };
    let output_pin = match file_ioctl_target::pin_output(
        activation,
        if output_length == 0 { 0 } else { output },
        output_length as u64,
    ) {
        Ok(pin) => pin,
        Err(status) => {
            provider_input::release_stack_pin(iosb_pin, W32_FILE_IOCTL_LABEL);
            return Err(status);
        }
    };
    ioctls[slot] = Some(PendingIoctl {
        local_id,
        token: 0,
        handle,
        activation,
        iosb_pin: Some(iosb_pin),
        output_pin: Some(output_pin),
    });
    *core::ptr::addr_of_mut!(NEXT_IOCTL_ID) = next;
    Ok(local_id)
}

unsafe fn retire_ioctl(local_id: u64) {
    let _guard = IoctlsGuard::acquire();
    let ioctls = &mut *core::ptr::addr_of_mut!(PENDING_IOCTLS);
    let Some(index) = ioctls.iter().position(|ioctl| {
        ioctl
            .as_ref()
            .is_some_and(|ioctl| ioctl.local_id == local_id)
    }) else {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_IOCTL_LABEL, local_id, 0, 2]);
    };
    let ioctl = ioctls[index].take().unwrap();
    if let Some(pin) = ioctl.output_pin {
        file_ioctl_target::release_output(pin);
    }
    if let Some(pin) = ioctl.iosb_pin {
        provider_input::release_stack_pin(pin, W32_FILE_IOCTL_LABEL);
    }
}

unsafe fn release_pins(local_id: u64) {
    let _guard = IoctlsGuard::acquire();
    let ioctls = &mut *core::ptr::addr_of_mut!(PENDING_IOCTLS);
    let Some(ioctl) = ioctls
        .iter_mut()
        .filter_map(Option::as_mut)
        .find(|ioctl| ioctl.local_id == local_id)
    else {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_IOCTL_LABEL, local_id, 0, 3]);
    };
    let output_pin = ioctl.output_pin.take().unwrap_or_else(|| {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_IOCTL_LABEL, local_id, 0, 4])
    });
    let iosb_pin = ioctl.iosb_pin.take().unwrap_or_else(|| {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_IOCTL_LABEL, local_id, 0, 5])
    });
    file_ioctl_target::release_output(output_pin);
    provider_input::release_stack_pin(iosb_pin, W32_FILE_IOCTL_LABEL);
}

unsafe fn retain_token(local_id: u64, token: u64) {
    let _guard = IoctlsGuard::acquire();
    let ioctls = &mut *core::ptr::addr_of_mut!(PENDING_IOCTLS);
    let Some(ioctl) = ioctls
        .iter_mut()
        .filter_map(Option::as_mut)
        .find(|ioctl| ioctl.local_id == local_id)
    else {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_IOCTL_LABEL, local_id, token, 6]);
    };
    if token == 0 || ioctl.token != 0 {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_IOCTL_LABEL, local_id, token, 7]);
    }
    ioctl.token = token;
}

unsafe fn release_completed(activation: ProviderStackEventActivation, handle: Option<u64>) {
    let mut cursor = 0;
    loop {
        let next = {
            let _guard = IoctlsGuard::acquire();
            (&*core::ptr::addr_of!(PENDING_IOCTLS))
                .iter()
                .filter_map(Option::as_ref)
                .filter(|ioctl| {
                    ioctl.local_id > cursor
                        && ioctl.token != 0
                        && ioctl.activation == activation
                        && handle.is_none_or(|handle| ioctl.handle == handle)
                })
                .min_by_key(|ioctl| ioctl.local_id)
                .map(|ioctl| {
                    (
                        ioctl.local_id,
                        ioctl.token,
                        ioctl.handle,
                        ioctl.iosb_pin.is_some(),
                    )
                })
        };
        let Some((local_id, token, file, pinned)) = next else {
            return;
        };
        cursor = local_id;
        if pinned {
            let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
                (W32_FILE_IOCTL_COMPLETION_LABEL << 12) | 4,
                token,
                file,
                0,
                0,
            );
            if words != 1 || (raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64) {
                crate::provider_bugcheck::report(
                    0xc4,
                    [W32_FILE_IOCTL_COMPLETION_LABEL, token, words, raw],
                );
            }
            match raw as u32 {
                nt_process::STATUS_SUCCESS => release_pins(local_id),
                wire::STATUS_PENDING if raw == wire::STATUS_PENDING as u64 => continue,
                _ => crate::provider_bugcheck::report(
                    0xc4,
                    [W32_FILE_IOCTL_COMPLETION_LABEL, token, file, raw],
                ),
            }
        }
        let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
            (W32_FILE_IOCTL_RELEASE_LABEL << 12) | 4,
            token,
            file,
            0,
            0,
        );
        if words != 1
            || (raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64)
            || (raw != nt_process::STATUS_SUCCESS as u64
                && raw as u32 != nt_process::STATUS_INVALID_PARAMETER)
        {
            crate::provider_bugcheck::report(
                0xc4,
                [W32_FILE_IOCTL_RELEASE_LABEL, token, words, raw],
            );
        }
        retire_ioctl(local_id);
    }
}

pub(super) unsafe fn release_completed_for_handle(handle: u64) {
    if let Some(activation) = active_provider_stack_event_activation() {
        release_completed(activation, Some(handle));
    }
}

pub(super) unsafe fn release_completed_for_activation(activation: ProviderStackEventActivation) {
    release_completed(activation, None);
}

pub(super) extern "win64" fn device_io_control_file(
    handle: u64,
    event: u64,
    apc_routine: u64,
    apc_context: u64,
    iosb: u64,
    code: u32,
    input: u64,
    input_length: u32,
    output: u64,
    output_length: u32,
) -> i32 {
    if event != 0
        || apc_routine != 0
        || apc_context != 0
        || ioctl::method(code) != ioctl::METHOD_BUFFERED
    {
        return STATUS_NOT_SUPPORTED_I32;
    }
    if iosb == 0 || (input_length != 0 && input == 0) || (output_length != 0 && output == 0) {
        return STATUS_INVALID_PARAMETER_I32;
    }
    let total = match wire::packet_len(input_length, output_length) {
        Ok(total) if (total as u64) < WIN32K_POOL_FRAMES * 0x1000 => total,
        _ => return 0xC000_0206u32 as i32,
    };
    unsafe {
        let Some(activation) = active_provider_stack_event_activation() else {
            return STATUS_NOT_SUPPORTED_I32;
        };
        release_completed(activation, Some(handle));
        let local_id = match reserve_ioctl(handle, activation, iosb, output, output_length) {
            Ok(id) => id,
            Err(status) => return status,
        };
        let mut input_copy = Vec::new();
        if input_copy.try_reserve_exact(input_length as usize).is_err() {
            retire_ioctl(local_id);
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        input_copy.resize(input_length as usize, 0);
        if let Err(status) = provider_input::copy_validated_input(
            activation,
            input,
            input_length,
            &mut input_copy,
            W32_FILE_IOCTL_LABEL,
        ) {
            retire_ioctl(local_id);
            return status;
        }
        let packet = pool_alloc(total as u64);
        if packet == 0 {
            retire_ioctl(local_id);
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        let bytes = core::slice::from_raw_parts_mut(packet as *mut u8, total);
        if wire::encode_request(
            BufferedIoctlRequest {
                code,
                input: &input_copy,
                output_capacity: output_length,
                output_va: output,
                iosb_va: iosb,
            },
            bytes,
        )
        .is_err()
        {
            retire_ioctl(local_id);
            if !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_FILE_IOCTL_LABEL, packet, 0, 10]);
            }
            return STATUS_INVALID_PARAMETER_I32;
        }
        let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
            (W32_FILE_IOCTL_LABEL << 12) | 4,
            packet,
            total as u64,
            handle,
            0,
        );
        if words != 1 || (raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64) {
            crate::provider_bugcheck::report(0xc4, [W32_FILE_IOCTL_LABEL, packet, words, raw]);
        }
        let response =
            wire::decode_response(core::slice::from_raw_parts(packet as *const u8, total));
        let status = match response {
            Ok(BufferedIoctlResponse::Pending { token }) if raw as u32 == wire::STATUS_PENDING => {
                retain_token(local_id, token);
                wire::STATUS_PENDING
            }
            Ok(BufferedIoctlResponse::Inline {
                token: _,
                status,
                information,
                output: bytes,
            }) if raw as u32 == status => {
                if nt_io_completion::file_io_status_copies_output(status) && !bytes.is_empty() {
                    core::ptr::copy_nonoverlapping(bytes.as_ptr(), output as *mut u8, bytes.len());
                }
                write_unaligned(iosb as *mut u32, status);
                write_unaligned((iosb + 8) as *mut u64, information);
                retire_ioctl(local_id);
                status
            }
            Err(_)
                if raw as u32 & 0xC000_0000 == 0xC000_0000
                    && wire::decode_request(core::slice::from_raw_parts(
                        packet as *const u8,
                        total,
                    ))
                    .is_ok() =>
            {
                retire_ioctl(local_id);
                raw as u32
            }
            _ => crate::provider_bugcheck::report(0xc4, [W32_FILE_IOCTL_LABEL, packet, raw, 11]),
        };
        if !provider_pool_free(packet) {
            crate::provider_bugcheck::report(
                0xc4,
                [W32_FILE_IOCTL_LABEL, packet, status as u64, 12],
            );
        }
        status as i32
    }
}
