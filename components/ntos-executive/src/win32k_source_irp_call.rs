//! Component-side call and retained packet lifecycle for file-less source IOCTLs.

use super::*;
use core::sync::atomic::{AtomicBool, AtomicU64};
use nt_io_manager::win32k_source_irp_ioctl_wire::{
    self as wire, SourceIrpIoctlRequest, SourceIrpIoctlResponse,
};

struct PendingSourceIoctl {
    kind: SourceRequestKind,
    activation: ProviderStackEventActivation,
    source_irp: u64,
    token: u64,
    packet: u64,
    packet_length: usize,
    packet_pin: source_irp::PinnedSystemBuffer,
}

#[derive(Clone, Copy)]
pub(super) enum SourceRequestKind {
    Ioctl,
    Pnp,
    Fsd,
}

impl SourceRequestKind {
    fn completion_label(self) -> u64 {
        match self {
            Self::Ioctl => W32_SOURCE_IOCTL_COMPLETION_LABEL,
            Self::Pnp => W32_SOURCE_PNP_COMPLETION_LABEL,
            Self::Fsd => W32_SOURCE_FSD_COMPLETION_LABEL,
        }
    }

    fn release_label(self) -> u64 {
        match self {
            Self::Ioctl => W32_SOURCE_IOCTL_RELEASE_LABEL,
            Self::Pnp => W32_SOURCE_PNP_RELEASE_LABEL,
            Self::Fsd => W32_SOURCE_FSD_RELEASE_LABEL,
        }
    }
}

const MAX_PENDING_SOURCE_IOCTL: usize = 64;
static SOURCE_IOCTL_BUSY: AtomicBool = AtomicBool::new(false);
static NEXT_SOURCE_IOCTL_NONCE: AtomicU64 = AtomicU64::new(1);
static mut PENDING_SOURCE_IOCTL: [Option<PendingSourceIoctl>; MAX_PENDING_SOURCE_IOCTL] =
    [const { None }; MAX_PENDING_SOURCE_IOCTL];

struct SourceIoctlGuard;

impl SourceIoctlGuard {
    fn acquire() -> Self {
        while SOURCE_IOCTL_BUSY
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }
}

impl Drop for SourceIoctlGuard {
    fn drop(&mut self) {
        SOURCE_IOCTL_BUSY.store(false, Ordering::Release);
    }
}

pub(super) unsafe fn reserve_packet(
    kind: SourceRequestKind,
    activation: ProviderStackEventActivation,
    source_irp: u64,
    packet: u64,
    packet_length: usize,
    packet_pin: source_irp::PinnedSystemBuffer,
) -> Result<usize, source_irp::PinnedSystemBuffer> {
    let _guard = SourceIoctlGuard::acquire();
    let rows = &mut *core::ptr::addr_of_mut!(PENDING_SOURCE_IOCTL);
    let Some(index) = rows.iter().position(Option::is_none) else {
        return Err(packet_pin);
    };
    rows[index] = Some(PendingSourceIoctl {
        kind,
        activation,
        source_irp,
        token: 0,
        packet,
        packet_length,
        packet_pin,
    });
    Ok(index)
}

pub(super) unsafe fn packet_live(index: usize, packet: u64, length: usize) -> bool {
    let _guard = SourceIoctlGuard::acquire();
    (&*core::ptr::addr_of!(PENDING_SOURCE_IOCTL))[index]
        .as_ref()
        .is_some_and(|row| {
            row.packet == packet
                && row.packet_length == length
                && source_irp::system_buffer_live(&row.packet_pin)
        })
}

pub(super) unsafe fn retire_packet(index: usize) {
    let row = {
        let _guard = SourceIoctlGuard::acquire();
        (&mut *core::ptr::addr_of_mut!(PENDING_SOURCE_IOCTL))[index].take()
    }
    .unwrap_or_else(|| {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, index as u64, 0, 1])
    });
    if !source_irp::release_system_buffer(row.packet_pin) || !provider_pool_free(row.packet) {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, row.packet, 0, 2]);
    }
}

pub(super) unsafe fn retain_token(index: usize, token: u64) {
    let _guard = SourceIoctlGuard::acquire();
    let row = (&mut *core::ptr::addr_of_mut!(PENDING_SOURCE_IOCTL))[index]
        .as_mut()
        .unwrap_or_else(|| {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, index as u64, 0, 3])
        });
    if row.token != 0 || token == 0 {
        crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, row.packet, token, 4]);
    }
    row.token = token;
}

pub(super) fn valid_status_word(words: u64, raw: u64) -> bool {
    words == 1 && (raw == raw as u32 as u64 || raw == raw as u32 as i32 as i64 as u64)
}

pub(super) unsafe fn release_completed_for_activation(activation: ProviderStackEventActivation) {
    let mut cursor = 0usize;
    while cursor < MAX_PENDING_SOURCE_IOCTL {
        let pending = {
            let _guard = SourceIoctlGuard::acquire();
            (&*core::ptr::addr_of!(PENDING_SOURCE_IOCTL))[cursor]
                .as_ref()
                .filter(|row| row.token != 0 && row.activation == activation)
                .map(|row| (row.token, row.source_irp))
        };
        if let Some((token, source_irp)) = pending {
            complete_and_release(cursor, token, source_irp);
        }
        cursor += 1;
    }
}

pub(super) unsafe fn complete_and_release(index: usize, token: u64, source_irp: u64) {
    let kind = {
        let _guard = SourceIoctlGuard::acquire();
        (&*core::ptr::addr_of!(PENDING_SOURCE_IOCTL))[index]
            .as_ref()
            .filter(|row| row.token == token && row.source_irp == source_irp)
            .map(|row| row.kind)
    }
    .unwrap_or_else(|| crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, token, 0, 40]));
    let completion_label = kind.completion_label();
    let release_label = kind.release_label();
    // Completion is a retained root wait. It replies only after terminal
    // publication, canonical Event signal, strict IRP ACK, and source retirement.
    let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
        (completion_label << 12) | 4,
        token,
        source_irp,
        0,
        0,
    );
    if !valid_status_word(words, raw) || raw as u32 != nt_process::STATUS_SUCCESS {
        crate::provider_bugcheck::report(
            0xc4,
            [completion_label, token, words, raw],
        );
    }
    let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
        (release_label << 12) | 4,
        token,
        source_irp,
        0,
        0,
    );
    if !valid_status_word(words, raw) || raw as u32 != nt_process::STATUS_SUCCESS {
        crate::provider_bugcheck::report(
            0xc4,
            [release_label, token, words, raw],
        );
    }
    retire_packet(index);
}

/// Dormant until the authenticated root path has passed native validation.
pub(super) extern "win64" fn iof_call_driver(device: u64, irp: u64) -> i32 {
    unsafe {
        let Some(activation) = active_provider_stack_event_activation() else {
            return STATUS_NOT_SUPPORTED_I32;
        };
        let stack_pointer = current_stack_pointer();
        let mut admission = match source_irp::admit_buffered_dispatch(irp, device, stack_pointer, None) {
            Ok(lease) => lease,
            Err(status) => return status,
        };
        let input_length = admission.input.len() as u32;
        let total = match wire::packet_len(admission.code, input_length, admission.output_capacity) {
            Ok(total) if (total as u64) < WIN32K_POOL_FRAMES * 0x1000 => total,
            _ => {
                if !source_irp::release_buffered_dispatch(&mut admission) {
                    crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, 0, 5]);
                }
                return STATUS_INVALID_PARAMETER_I32;
            }
        };
        let packet = pool_alloc(total as u64);
        if packet == 0 {
            if !source_irp::release_buffered_dispatch(&mut admission) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, 0, 6]);
            }
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        }
        let Some(packet_pin) = source_irp::pin_system_buffer(packet, total as u64) else {
            if !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, packet, 0, 7]);
            }
            if !source_irp::release_buffered_dispatch(&mut admission) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, 0, 8]);
            }
            return STATUS_INSUFFICIENT_RESOURCES_I32;
        };
        let nonce = match NEXT_SOURCE_IOCTL_NONCE.fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |n| n.checked_add(1),
        ) {
            Ok(value) if value != 0 => value,
            _ => crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, 0, 9]),
        };
        let source_ticket = admission.source_ticket_serial();
        let source_generation = admission.source_native_generation();
        let system_identity = admission.system_buffer_native_identity();
        let encoded = wire::encode_request(
            SourceIrpIoctlRequest {
                nonce,
                source_irp_va: admission.source_address(),
                source_ticket_serial: source_ticket,
                native_allocation_generation: source_generation,
                device_object_va: device,
                code: admission.code,
                input: &admission.input,
                output_initial: &admission.output_initial,
                output_capacity: admission.output_capacity,
                event: admission.event,
            },
            core::slice::from_raw_parts_mut(packet as *mut u8, total),
        );
        if encoded.is_err() {
            if !source_irp::release_system_buffer(packet_pin) || !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, packet, 0, 10]);
            }
            if !source_irp::release_buffered_dispatch(&mut admission) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, 0, 11]);
            }
            return STATUS_INVALID_PARAMETER_I32;
        }
        let index = match reserve_packet(SourceRequestKind::Ioctl, activation, irp, packet, total, packet_pin) {
            Ok(index) => index,
            Err(packet_pin) => {
            if !source_irp::release_system_buffer(packet_pin) || !provider_pool_free(packet) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, packet, 0, 12]);
            }
            if !source_irp::release_buffered_dispatch(&mut admission) {
                crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, 0, 13]);
            }
            return STATUS_INSUFFICIENT_RESOURCES_I32;
            }
        };
        if !source_irp::release_buffered_admission(&mut admission) {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, irp, 0, 14]);
        }
        let (words, raw, _, _, _) = crate::driver_launch::call_on4_raw(
            (W32_SOURCE_IOCTL_LABEL << 12) | 4,
            packet,
            total as u64,
            stack_pointer,
            0,
        );
        if !valid_status_word(words, raw) || !packet_live(index, packet, total) {
            crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, packet, words, raw]);
        }
        let response = wire::decode_response(core::slice::from_raw_parts(packet as *const u8, total));
        match response {
            Ok(SourceIrpIoctlResponse::Pending { token }) if raw as u32 == wire::STATUS_PENDING => {
                retain_token(index, token);
                wire::STATUS_PENDING as i32
            }
            Ok(SourceIrpIoctlResponse::Inline { token, status, .. }) if raw as u32 == status => {
                retain_token(index, token);
                complete_and_release(index, token, irp);
                status as i32
            }
            Err(_)
                if raw as u32 & 0xc000_0000 == 0xc000_0000
                    && wire::decode_request(core::slice::from_raw_parts(packet as *const u8, total))
                        .is_ok() =>
            {
                retire_packet(index);
                let mut source = source_irp::admit_buffered_dispatch(irp, device, stack_pointer, None)
                    .unwrap_or_else(|_| {
                        crate::provider_bugcheck::report(
                            0xc4,
                            [W32_SOURCE_IOCTL_LABEL, irp, raw, 16],
                        )
                    });
                if source.source_ticket_serial() != source_ticket
                    || source.source_native_generation() != source_generation
                    || source.system_buffer_native_identity() != system_identity
                    || !source_irp::release_buffered_dispatch(&mut source)
                {
                    crate::provider_bugcheck::report(
                        0xc4,
                        [W32_SOURCE_IOCTL_LABEL, irp, raw, 17],
                    );
                }
                raw as u32 as i32
            }
            _ => crate::provider_bugcheck::report(0xc4, [W32_SOURCE_IOCTL_LABEL, packet, raw, 15]),
        }
    }
}
