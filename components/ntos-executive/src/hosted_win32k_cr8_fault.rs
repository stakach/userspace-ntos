//! Source-owned CR8 read faults from the authenticated, stopped win32k provider lane.

use crate::spawn_hosts::{PumpChannel, ReqKind};
use nt_kernel_exec::x86_cr8::{decode_cr8_read, project_cr8_read};

pub(crate) enum Cr8FaultOutcome {
    Unrelated,
    Applied,
    Rejected,
}

/// Install only RIP and the decoded destination GPR. The caller retains the original Reply until
/// this acknowledged write has completed, then consumes that Reply exactly once to resume.
pub(crate) unsafe fn service(
    channel: &PumpChannel,
    reply_cap: u64,
    badge: u64,
    words: [u64; 5],
) -> Cr8FaultOutcome {
    if channel.caps.kind != ReqKind::Syscall
        || channel.shared_va != crate::win32k_subsystem::WIN32K_SHARED_VADDR
        || channel.dispatch_label != crate::win32k_subsystem::W32_DISPATCH_LABEL
        || words[3] != 13
    {
        return Cr8FaultOutcome::Unrelated;
    }
    let image_len = match channel.image_frames.checked_mul(0x1000) {
        Some(len) if len != 0 => len,
        _ => return Cr8FaultOutcome::Unrelated,
    };
    let Some(offset) = words[0].checked_sub(channel.code_va) else {
        return Cr8FaultOutcome::Unrelated;
    };
    if offset.checked_add(4).is_none_or(|end| end > image_len) || channel.exec_code_va == 0 {
        return Cr8FaultOutcome::Unrelated;
    }
    let Some(alias) = channel.exec_code_va.checked_add(offset) else {
        return Cr8FaultOutcome::Rejected;
    };
    let mut bytes = [0u8; 4];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = core::ptr::read_volatile((alias + index as u64) as *const u8);
    }
    let Some(instruction) = decode_cr8_read(&bytes) else {
        return Cr8FaultOutcome::Unrelated;
    };
    if words[4] != 0 || channel.tcb == 0 || reply_cap == 0 {
        return Cr8FaultOutcome::Rejected;
    }
    let source = crate::driver_launch::hosted_exception_stack::fault_source_identity(
        channel, reply_cap, badge,
    );
    let Some(crate::driver_launch::hosted_exception_stack::FaultSourceIdentity::Win32k {
        route, dispatch, tcb,
    }) = source else { return Cr8FaultOutcome::Rejected; };
    if tcb != channel.tcb || channel.ingress_route != Some(route) || route.badge() != badge {
        return Cr8FaultOutcome::Rejected;
    }
    let Some((current_route, current_dispatch, stack_base, stack_bytes)) =
        crate::win32k_glue::win32k_physical_stack_route_for_channel(
            channel.tcb, channel.fault_ep, reply_cap,
        ) else { return Cr8FaultOutcome::Rejected; };
    if (current_route, current_dispatch) != (route, dispatch) {
        return Cr8FaultOutcome::Rejected;
    }
    let Some(lane_id) = crate::win32k_cr8_publication::lane_id_for_stack(stack_base, stack_bytes)
    else { return Cr8FaultOutcome::Rejected; };
    let expected_dispatch_id = if channel.kernel_caller.is_some() {
        crate::service_sec_image::kernel_provider_activation::fault_dispatch_id(channel, dispatch)
    } else {
        crate::win32k_glue::dispatch_observation_snapshot(dispatch.lane())
            .map(|observation| observation.dispatch_id)
    };
    let Some(expected_dispatch_id) = expected_dispatch_id
    else { return Cr8FaultOutcome::Rejected; };
    let Some(receipt) = crate::win32k_cr8_publication::read(lane_id)
    else { return Cr8FaultOutcome::Rejected; };
    if receipt.for_fault(lane_id, expected_dispatch_id).is_none() {
        return Cr8FaultOutcome::Rejected;
    }
    let Ok(snapshot) = crate::thread_context::LegacyThreadContext::read(tcb)
    else { return Cr8FaultOutcome::Rejected; };
    if snapshot.registers[0] != words[0]
        || snapshot.registers[1] != words[1]
        || snapshot.registers[2] != words[2]
    {
        return Cr8FaultOutcome::Rejected;
    }
    let mut registers = snapshot.registers;
    let Some(mask) = project_cr8_read(&mut registers, instruction, receipt.irql)
    else { return Cr8FaultOutcome::Rejected; };
    // Recheck both ownership and generation after the native read. A stale receipt may never
    // authorize an installation into a reused physical lane.
    if crate::driver_launch::hosted_exception_stack::fault_source_identity(
        channel, reply_cap, badge,
    ) != source
        || crate::win32k_cr8_publication::read(lane_id) != Some(receipt)
    {
        return Cr8FaultOutcome::Rejected;
    }
    let restore = nt_thread_start::amd64_context::LegacyContextRestore {
        registers,
        register_mask: mask,
        floating_point: None,
        debug: None,
    };
    if crate::thread_context::write(tcb, &restore, false).is_err() {
        // The effect is uncertain; the caller walls with the original Reply retained.
        return Cr8FaultOutcome::Rejected;
    }
    Cr8FaultOutcome::Applied
}
