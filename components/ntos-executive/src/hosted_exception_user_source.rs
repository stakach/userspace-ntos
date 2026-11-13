//! A paused win32k dispatch's exact logical caller and saved user stack context.
//!
//! This snapshot is only one input to `Flags=1`. Its caller must also retain the physical
//! `StackLease`, admit mapped user image metadata, and revalidate the process image views through
//! completion. A saved TCB alone does not authorize user image addresses or publication.

use super::StackLease;
use nt_unwind::user_frame_source::{UserFrameIdentity, UserFrameSnapshot, UserTrapRegisters};

/// Capture only under the same physical lane and logical user dispatch. No TCB, TEB, or numeric
/// user address is accepted without the current process/thread generation and VAD owner.
pub(crate) unsafe fn capture_attached_user_frame_snapshot(
    channel: &crate::spawn_hosts::PumpChannel,
    lease: &StackLease,
) -> Option<(UserFrameSnapshot, u64, u64)> {
    use nt_user_host::process_identity::ProcessGeneration;

    if !lease.still_live() || !crate::win32k_glue::registry_logical_caller_is_current(channel) {
        return None;
    }
    let caller = channel.logical_caller?;
    let ProcessGeneration::Hosted(generation) = caller.process().generation else {
        return None;
    };
    if caller.pi() as u64 != channel.client_pi
        || generation != channel.client_generation
        || caller.tcb() <= 1
    {
        return None;
    }
    let handler_ptr = crate::service_sec_image::registry_live_handler_pointer().ok()?;
    let handler = &*handler_ptr;
    if !handler.validate_provider_logical_caller(caller)
        || handler.hosted_thread_tcb_for_badge(caller.badge()) != Some(caller.tcb())
    {
        return None;
    }
    let teb = handler.hosted_thread_teb_for_badge(caller.badge())?;
    let (allocation_base, runtime_stack_top, _) =
        handler.hosted_thread_user_stack_for_badge(caller.badge(), caller.pi())?;
    if teb == 0 || allocation_base == 0 || allocation_base >= runtime_stack_top {
        return None;
    }

    // ReadRegisters returns the saved user trap state of the blocked logical caller. Its reply
    // envelope must be successful and contain all 20 words; the provider's own TCB is unrelated.
    let mut words = [0u64; 20];
    if !crate::win32k_glue::tcb_read_regs20_checked(caller.tcb(), &mut words) {
        return None;
    }
    let context = UserTrapRegisters::from_sel4_words(&words)?;

    // NtTib.StackBase and StackLimit occupy TEB+8 and TEB+16. The checked process copy may
    // resolve residency, so no borrow or identity assumption is carried across it.
    let mut tib = [0u8; 16];
    (&mut *handler_ptr)
        .process_memory_read_status(caller.pi(), teb.checked_add(8)?, &mut tib)
        .ok()?;
    let stack_high = u64::from_le_bytes(tib[..8].try_into().ok()?);
    let stack_low = u64::from_le_bytes(tib[8..].try_into().ok()?);
    if stack_low < allocation_base
        || stack_low >= stack_high
        || stack_high != runtime_stack_top
        || context.rsp() <= stack_low
        || context.rsp() >= stack_high
    {
        return None;
    }
    let map = crate::process_vm_region_map(caller.pi())?;
    let extent = map.extent_at(context.rsp())?;
    if extent.allocation_base != allocation_base
        || extent.type_ != nt_address_space::MEM_PRIVATE
        || extent.state != nt_address_space::VmExtentState::Committed
        || !lease.still_live()
        || !crate::win32k_glue::registry_logical_caller_is_current(channel)
        || !(&*handler_ptr).validate_provider_logical_caller(caller)
    {
        return None;
    }
    let snapshot = UserFrameSnapshot {
        identity: UserFrameIdentity {
            process_generation: generation,
            thread_activation: caller.thread().generation(),
            tcb: caller.tcb(),
            teb,
        },
        context,
        teb_stack_low: stack_low,
        teb_stack_high: stack_high,
    };
    Some((snapshot, allocation_base, runtime_stack_top))
}
