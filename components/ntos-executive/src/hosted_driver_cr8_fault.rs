//! Authenticated inline CR8 access from a stopped hosted driver primary or provider-export lane.

use super::*;
use nt_kernel_exec::x86_cr8::{
    decode_cr8_read, decode_cr8_write, project_cr8_read, project_cr8_write,
};

pub(crate) enum Cr8FaultOutcome { Unrelated, Applied, Rejected }

static IRQ_CR8_DIAG: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Bounded native trace for the IRQ authentication boundary; remove after live validation.
pub(super) fn irq_cr8_diag(stage: u64, detail: u64) {
    if IRQ_CR8_DIAG.fetch_add(1, core::sync::atomic::Ordering::Relaxed) < 16 {
        print_str(b"[irq-cr8] stage=");
        print_u64(stage);
        print_str(b" detail=");
        print_hex64(detail);
        print_str(b"\n");
    }
}

/// The executive mirror of the component's IRQL byte is selected through the
/// admitted physical instance. A component-supplied address is never authority.
unsafe fn hosted_current_irql(shared: u64) -> Option<(u64, u8)> {
    let address = shared.checked_add(SH_HOSTED_CURRENT_IRQL)?;
    let value = read_volatile(address as *const u8);
    (value <= 15).then_some((address, value))
}

/// An IRQ callback executes on its own physical lane. Its IRQL lives in that lane's arena,
/// whereas the ordinary driver shared byte can belong to a parked primary dispatch.
unsafe fn service_irq_read(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    words: [u64; 5],
) -> Cr8FaultOutcome {
    let Some(lane) = hosted_irq_cr8_fault_lane(channel, reply_cap, badge) else {
        irq_cr8_diag(1, reply_cap);
        return Cr8FaultOutcome::Rejected;
    };
    let Some(inst) = instance(lane.instance) else { return Cr8FaultOutcome::Rejected; };
    let Some(image) = hosted_driver_process_notify::published_image_for_callback(
        lane.instance, inst, words[0],
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
    let Some(alias) = ExecVaWindow::try_for_instance(lane.instance)
        .and_then(|window| window.code_va.checked_add(offset))
    else { return Cr8FaultOutcome::Rejected; };
    let mut bytes = [0u8; 4];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = read_volatile((alias + index as u64) as *const u8);
    }
    if decode_cr8_write(&bytes).is_some() {
        // A write must pass the arena's active-transaction transition contract; do not
        // silently alter the primary's shared byte or resume this lane without that owner.
        return Cr8FaultOutcome::Rejected;
    }
    let Some(instruction) = decode_cr8_read(&bytes) else {
        irq_cr8_diag(2, u32::from_le_bytes(bytes) as u64);
        return Cr8FaultOutcome::Unrelated;
    };
    let arena = &*(lane.arena_va as *const nt_hosted_runtime::HostedIrqArena);
    let Ok(irql) = arena.control.current_irql(lane.identity) else {
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
    let Some(mask) = project_cr8_read(&mut registers, instruction, irql) else {
        return Cr8FaultOutcome::Rejected;
    };
    if hosted_irq_cr8_fault_lane(channel, reply_cap, badge) != Some(lane)
        || arena.control.current_irql(lane.identity) != Ok(irql)
        || hosted_driver_process_notify::published_image_for_callback(
            lane.instance, inst, words[0],
        ) != Some(image)
    { irq_cr8_diag(3, lane.transaction.transaction); return Cr8FaultOutcome::Rejected; }
    let restore = nt_thread_start::amd64_context::LegacyContextRestore {
        registers,
        register_mask: mask,
        floating_point: None,
        debug: None,
    };
    if crate::thread_context::write(channel.tcb, &restore, false).is_err() {
        irq_cr8_diag(4, channel.tcb);
        return Cr8FaultOutcome::Rejected;
    }
    irq_cr8_diag(5, irql as u64);
    Cr8FaultOutcome::Applied
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
    if channel.dispatch_label == FSD_IRQ_LANE_COMPLETION_LABEL {
        return service_irq_read(channel, active_reply_cap, badge, words);
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
    // A provider-export worker has its own IRQL byte in its exact retained bank. Other worker
    // and IRQ lanes cannot borrow either that byte or the primary's dispatch authority.
    let provider_worker = unsafe {
        hosted_provider_export_lane::matches_channel(index, inst, channel)
    };
    let primary = caller.runtime.is_none() && channel.tcb == inst.tcb
        && channel.shared_va == inst.exec_shared_va;
    let Some(shared) = nt_hosted_runtime::select_hosted_cr8_bank(
        inst.exec_shared_va, channel.shared_va, primary, provider_worker) else {
        return Cr8FaultOutcome::Rejected;
    };
    if channel.ingress_route != Some(caller.route)
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
    let Some((irql_address, current_irql)) = hosted_current_irql(shared) else {
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
    ) != source || hosted_current_irql(shared) != Some((irql_address, current_irql))
        || nt_hosted_runtime::select_hosted_cr8_bank(
            inst.exec_shared_va, channel.shared_va,
            caller.runtime.is_none() && channel.tcb == inst.tcb
                && channel.shared_va == inst.exec_shared_va,
            hosted_provider_export_lane::matches_channel(index, inst, channel),
        ) != Some(shared)
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
