//! Pending kernel-mode reads issued by win32k's raw-input thread.

use super::*;
use core::sync::atomic::AtomicBool;
use nt_io_manager::win32k_async_read_wire::{self as wire, AsyncReadRequest, AsyncReadResponse};
use nt_io_manager::ReadWriteParameters;
use nt_provider_wait::ProviderStackLanePin;

struct PendingRead {
    local_id: u64,
    token: u64,
    handle: u64,
    activation: ProviderStackEventActivation,
    iosb_pin: Option<ProviderStackLanePin>,
    output_pin: Option<ProviderStackLanePin>,
}

static READS_BUSY: AtomicBool = AtomicBool::new(false);
const MAX_PENDING_READS: usize = 64;
static mut PENDING_READS: [Option<PendingRead>; MAX_PENDING_READS] =
    [const { None }; MAX_PENDING_READS];
static mut NEXT_READ_ID: u64 = 1;

struct ReadsGuard;

impl ReadsGuard {
    fn acquire() -> Self {
        while READS_BUSY
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }
}

impl Drop for ReadsGuard {
    fn drop(&mut self) {
        READS_BUSY.store(false, Ordering::Release);
    }
}

unsafe fn release_pin(pin: ProviderStackLanePin) {
    let released = {
        let mut metadata = ProviderMetadataGuard::acquire();
        provider_input::stack_catalog_mut(&mut metadata)
            .is_some_and(|catalog| catalog.release_pin(pin).is_ok())
    };
    if !released {
        crate::provider_bugcheck::report(
            0xc4,
            [W32_FILE_READ_LABEL, pin.range().0, pin.range().1, 1],
        );
    }
}

unsafe fn reserve_read(
    handle: u64,
    activation: ProviderStackEventActivation,
    iosb: u64,
    output: u64,
    length: u32,
) -> Result<u64, i32> {
    let _guard = ReadsGuard::acquire();
    let reads = &mut *core::ptr::addr_of_mut!(PENDING_READS);
    let slot = reads
        .iter()
        .position(Option::is_none)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES_I32)?;
    let local_id = *core::ptr::addr_of!(NEXT_READ_ID);
    let next = local_id
        .checked_add(1)
        .ok_or(STATUS_INSUFFICIENT_RESOURCES_I32)?;
    let (iosb_pin, output_pin) = {
        let mut metadata = ProviderMetadataGuard::acquire();
        let catalog = provider_input::stack_catalog_mut(&mut metadata)
            .ok_or(STATUS_NOT_SUPPORTED_I32)?;
        let (_, iosb_pin) = catalog
            .pin_active_range(activation, iosb, 16)
            .map_err(|_| STATUS_ACCESS_VIOLATION_I32)?;
        let (_, output_pin) = match catalog.pin_active_range(activation, output, length as u64) {
            Ok(pinned) => pinned,
            Err(_) => {
                if catalog.release_pin(iosb_pin).is_err() {
                    crate::provider_bugcheck::report(
                        0xc4,
                        [W32_FILE_READ_LABEL, iosb_pin.range().0, iosb_pin.range().1, 1],
                    );
                }
                return Err(STATUS_ACCESS_VIOLATION_I32);
            }
        };
        (iosb_pin, output_pin)
    };
    reads[slot] = Some(PendingRead {
        local_id,
        token: 0,
        handle,
        activation,
        iosb_pin: Some(iosb_pin),
        output_pin: Some(output_pin),
    });
    *core::ptr::addr_of_mut!(NEXT_READ_ID) = next;
    Ok(local_id)
}

unsafe fn retire_read(local_id: u64) {
    let _guard = ReadsGuard::acquire();
    let reads = &mut *core::ptr::addr_of_mut!(PENDING_READS);
    let Some(index) = reads
        .iter()
        .position(|read| read.as_ref().is_some_and(|read| read.local_id == local_id))
    else {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_READ_LABEL, local_id, 0, 2]);
    };
    let read = reads[index].take().unwrap();
    if let Some(pin) = read.output_pin {
        release_pin(pin);
    }
    if let Some(pin) = read.iosb_pin {
        release_pin(pin);
    }
}

unsafe fn release_pins(local_id: u64) {
    let _guard = ReadsGuard::acquire();
    let reads = &mut *core::ptr::addr_of_mut!(PENDING_READS);
    let Some(read) = reads
        .iter_mut()
        .filter_map(Option::as_mut)
        .find(|read| read.local_id == local_id)
    else {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_READ_LABEL, local_id, 0, 8]);
    };
    let Some(output_pin) = read.output_pin.take() else {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_READ_LABEL, local_id, 0, 9]);
    };
    let Some(iosb_pin) = read.iosb_pin.take() else {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_READ_LABEL, local_id, 0, 10]);
    };
    release_pin(output_pin);
    release_pin(iosb_pin);
}

unsafe fn retain_token(local_id: u64, token: u64) {
    let _guard = ReadsGuard::acquire();
    let reads = &mut *core::ptr::addr_of_mut!(PENDING_READS);
    let Some(read) = reads
        .iter_mut()
        .filter_map(Option::as_mut)
        .find(|read| read.local_id == local_id)
    else {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_READ_LABEL, local_id, token, 3]);
    };
    if token == 0 || read.token != 0 {
        crate::provider_bugcheck::report(0xc4, [W32_FILE_READ_LABEL, local_id, token, 4]);
    }
    read.token = token;
}

unsafe fn release_completed(activation: ProviderStackEventActivation, handle: Option<u64>) {
    let mut cursor = 0;
    loop {
        let next = {
            let _guard = ReadsGuard::acquire();
            (&*core::ptr::addr_of!(PENDING_READS))
                .iter()
                .filter_map(Option::as_ref)
                .filter(|read| {
                    read.local_id > cursor
                        && read.token != 0
                        && read.activation == activation
                        && handle.is_none_or(|handle| read.handle == handle)
                })
                .min_by_key(|read| read.local_id)
                .map(|read| {
                    (
                        read.local_id,
                        read.token,
                        read.handle,
                        read.iosb_pin.is_some(),
                    )
                })
        };
        let Some((local_id, token, file, pinned)) = next else {
            return;
        };
        cursor = local_id;
        if pinned {
            let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
                (W32_FILE_READ_COMPLETION_LABEL << 12) | 4,
                token,
                file,
                0,
                0,
            );
            if words != 1 {
                crate::provider_bugcheck::report(
                    0xc4,
                    [W32_FILE_READ_COMPLETION_LABEL, token, words, raw],
                );
            }
            if raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64 {
                crate::provider_bugcheck::report(
                    0xc4,
                    [W32_FILE_READ_COMPLETION_LABEL, token, file, raw],
                );
            }
            match raw as u32 {
                nt_process::STATUS_SUCCESS => release_pins(local_id),
                wire::STATUS_PENDING if raw == wire::STATUS_PENDING as u64 => continue,
                _ => crate::provider_bugcheck::report(
                    0xc4,
                    [W32_FILE_READ_COMPLETION_LABEL, token, file, raw],
                ),
            }
        }
        let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
            (W32_FILE_READ_RELEASE_LABEL << 12) | 4,
            token,
            file,
            0,
            0,
        );
        // Once this provider has observed terminal publication and released its exact pins,
        // an uncertain prior release can be retried: a missing globally unique token then
        // denotes that prior release, not a generic success for an unknown operation.
        if words != 1
            || (raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64)
            || (raw != nt_process::STATUS_SUCCESS as u64
                && raw as u32 != nt_process::STATUS_INVALID_PARAMETER)
        {
            crate::provider_bugcheck::report(
                0xc4,
                [W32_FILE_READ_RELEASE_LABEL, token, words, raw],
            );
        }
        retire_read(local_id);
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

pub(super) extern "win64" fn read(
    handle: u64,
    event: u64,
    apc_routine: u64,
    apc_context: u64,
    iosb: u64,
    output: u64,
    length: u32,
    byte_offset: u64,
    key: u64,
) -> i32 {
    if event != 0 || apc_routine != 0 || apc_context != 0 || key != 0 || byte_offset == 0 {
        return STATUS_NOT_SUPPORTED_I32;
    }
    if iosb == 0 || output == 0 || length == 0 {
        return STATUS_INVALID_PARAMETER_I32;
    }
    let total = match wire::packet_len(length) {
        Ok(total) if (total as u64) < WIN32K_POOL_FRAMES * 0x1000 => total,
        _ => return 0xC000_0206u32 as i32,
    };
    unsafe {
        let Some(activation) = active_provider_stack_event_activation() else {
            return STATUS_NOT_SUPPORTED_I32;
        };
        let offset_live = {
            let mut metadata = ProviderMetadataGuard::acquire();
            provider_input::stack_catalog_mut(&mut metadata).is_some_and(|catalog| {
                catalog
                    .resolve(byte_offset, 8)
                    .is_ok_and(|(binding, _)| binding.handle == activation.lane)
            })
        };
        if !offset_live {
            return STATUS_ACCESS_VIOLATION_I32;
        }
        let offset = read_unaligned(byte_offset as *const u64);
        if offset != 0 {
            return STATUS_NOT_SUPPORTED_I32;
        }
        release_completed(activation, Some(handle));
        let local_id = match reserve_read(handle, activation, iosb, output, length) {
            Ok(id) => id,
            Err(status) => return status,
        };
        let packet = pool_alloc(total as u64);
        if packet == 0 {
            retire_read(local_id);
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        let bytes = core::slice::from_raw_parts_mut(packet as *mut u8, total);
        if wire::encode_request(
            AsyncReadRequest {
                parameters: ReadWriteParameters {
                    length,
                    key: 0,
                    offset,
                },
                output_va: output,
                iosb_va: iosb,
            },
            bytes,
        )
        .is_err()
        {
            retire_read(local_id);
            if !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_FILE_READ_LABEL, packet, 0, 5]);
            }
            return STATUS_INVALID_PARAMETER_I32;
        }
        let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
            (W32_FILE_READ_LABEL << 12) | 4,
            packet,
            total as u64,
            handle,
            0,
        );
        if words != 1 || (raw != raw as u32 as u64 && raw != raw as u32 as i32 as i64 as u64) {
            crate::provider_bugcheck::report(0xc4, [W32_FILE_READ_LABEL, packet, words, raw]);
        }
        let response =
            wire::decode_response(core::slice::from_raw_parts(packet as *const u8, total));
        let status = match response {
            Ok(AsyncReadResponse::Pending { token }) if raw as u32 == wire::STATUS_PENDING => {
                retain_token(local_id, token);
                wire::STATUS_PENDING
            }
            Ok(AsyncReadResponse::Inline {
                token: _,
                status,
                information,
                bytes,
            }) if raw as u32 == status => {
                if nt_io_completion::file_io_status_copies_output(status) && information != 0 {
                    core::ptr::copy_nonoverlapping(
                        bytes.as_ptr(),
                        output as *mut u8,
                        information as usize,
                    );
                }
                if nt_io_completion::file_io_status_publishes_completion(status, true) {
                    write_unaligned(iosb as *mut u32, status);
                    write_unaligned((iosb + 8) as *mut u64, information);
                }
                retire_read(local_id);
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
                // A rejected request has no root operation token and no caller-visible effect.
                retire_read(local_id);
                raw as u32
            }
            _ => crate::provider_bugcheck::report(0xc4, [W32_FILE_READ_LABEL, packet, raw, 6]),
        };
        if !provider_pool_free(packet) {
            crate::provider_bugcheck::report(0xc4, [W32_FILE_READ_LABEL, packet, status as u64, 7]);
        }
        status as i32
    }
}
