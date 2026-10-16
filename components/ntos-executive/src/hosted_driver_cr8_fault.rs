//! Authenticated inline CR8 access from a stopped hosted driver primary lane.

use super::*;
use nt_kernel_exec::x86_cr8::{
    decode_cr8_read, decode_cr8_write, project_cr8_read, project_cr8_write,
};

pub(crate) enum Cr8FaultOutcome { Unrelated, Applied, Rejected }

/// The executive mirror of the component's IRQL byte is selected through the
/// admitted physical instance. A component-supplied address is never authority.
unsafe fn hosted_current_irql(inst: DriverInstance) -> Option<(u64, u8)> {
    let address = inst.exec_shared_va.checked_add(SH_HOSTED_CURRENT_IRQL)?;
    let value = read_volatile(address as *const u8);
    (value <= 15).then_some((address, value))
}

pub(crate) unsafe fn service(
    channel: &crate::spawn_hosts::PumpChannel,
    active_reply_cap: u64,
    badge: u64,
    words: [u64; 5],
) -> Cr8FaultOutcome {
    use crate::spawn_hosts::ReqKind;
    if channel.caps.kind != ReqKind::Irp || words[3] != 13 {
        return Cr8FaultOutcome::Unrelated;
    }
    if words[4] != 0 || channel.tcb == 0 || active_reply_cap == 0 {
        return Cr8FaultOutcome::Rejected;
    }
    let source = crate::driver_launch::hosted_exception_stack::fault_source_identity(
        channel, active_reply_cap, badge,
    );
    let Some(crate::driver_launch::hosted_exception_stack::FaultSourceIdentity::Driver(_)) = source
    else { return Cr8FaultOutcome::Rejected; };
    let Some((index, inst)) = instance_for_pump_channel(channel, active_reply_cap) else {
        return Cr8FaultOutcome::Rejected;
    };
    let Some(caller) = hosted_driver_caller(index, inst, badge) else {
        return Cr8FaultOutcome::Rejected;
    };
    // The primary's shared IRQL byte is exact. Worker/IRQ lanes use distinct
    // scheduling authority and must not alias that primary state.
    if caller.runtime.is_some() || channel.tcb != inst.tcb
        || channel.ingress_route != Some(caller.route)
    { return Cr8FaultOutcome::Rejected; }
    // Per-IRP pumps deliberately set code_va/image_frames to zero to disable
    // demand-fault wall checks. Resolve code only after physical source
    // authentication, against the exact image generation published before
    // DriverEntry and the instance's root alias of its immutable frames.
    let Some(image) = hosted_driver_process_notify::published_image_for_callback(
        index, inst, words[0],
    ) else { return Cr8FaultOutcome::Rejected; };
    let Some(image_offset) = words[0].checked_sub(image.run_base) else {
        return Cr8FaultOutcome::Rejected;
    };
    if image_offset.checked_add(4).is_none_or(|end| end > image.image_len) {
        return Cr8FaultOutcome::Rejected;
    }
    let Some(offset) = words[0].checked_sub(FSD_CODE_VA) else {
        return Cr8FaultOutcome::Rejected;
    };
    let Some(image_bytes) = inst.image_frames.checked_mul(4096) else {
        return Cr8FaultOutcome::Rejected;
    };
    if offset.checked_add(4).is_none_or(|end| end > image_bytes) {
        return Cr8FaultOutcome::Rejected;
    }
    let Some(exec_window) = ExecVaWindow::try_for_instance(index) else {
        return Cr8FaultOutcome::Rejected;
    };
    let Some(alias) = exec_window.code_va.checked_add(offset) else {
        return Cr8FaultOutcome::Rejected;
    };
    let mut bytes = [0u8; 4];
    for (byte_index, byte) in bytes.iter_mut().enumerate() {
        *byte = read_volatile((alias + byte_index as u64) as *const u8);
    }
    let read = decode_cr8_read(&bytes);
    let write = decode_cr8_write(&bytes);
    if read.is_none() && write.is_none() {
        return Cr8FaultOutcome::Unrelated;
    }
    let Some((irql_address, current_irql)) = hosted_current_irql(inst) else {
        return Cr8FaultOutcome::Rejected;
    };
    let Ok(snapshot) = crate::thread_context::LegacyThreadContext::read(channel.tcb) else {
        return Cr8FaultOutcome::Rejected;
    };
    if snapshot.registers[0] != words[0]
        || snapshot.registers[1] != words[1]
        || snapshot.registers[2] != words[2]
    { return Cr8FaultOutcome::Rejected; }
    let mut registers = snapshot.registers;
    let (mask, next_irql) = if let Some(instruction) = read {
        let Some(mask) = project_cr8_read(&mut registers, instruction, current_irql) else {
            return Cr8FaultOutcome::Rejected;
        };
        (mask, None)
    } else {
        let Some((next, mask)) = project_cr8_write(&mut registers, write.unwrap()) else {
            return Cr8FaultOutcome::Rejected;
        };
        (mask, Some(next))
    };
    if crate::driver_launch::hosted_exception_stack::fault_source_identity(
        channel, active_reply_cap, badge,
    ) != source || hosted_current_irql(inst) != Some((irql_address, current_irql))
        || hosted_driver_process_notify::published_image_for_callback(index, inst, words[0])
            != Some(image)
    { return Cr8FaultOutcome::Rejected; }
    let restore = nt_thread_start::amd64_context::LegacyContextRestore {
        registers,
        register_mask: mask,
        floating_point: None,
        debug: None,
    };
    if crate::thread_context::write(channel.tcb, &restore, false).is_err() {
        // Uncertain context installation retains the original Reply in the pump.
        return Cr8FaultOutcome::Rejected;
    }
    if let Some(next) = next_irql {
        write_volatile(irql_address as *mut u8, next);
    }
    Cr8FaultOutcome::Applied
}
