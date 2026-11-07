//! Exact paused-lane broker for native x64 kernel frame chains.
//!
//! This child of `hosted_exception_stack` can borrow the private physical stack lease. A caller
//! must retain the same PumpChannel, Reply, and badge until this function returns. If a result
//! write becomes uncertain, it must wall that lane and retain its Reply rather than retrying.

use super::{StackLease, StackReader};
use nt_unwind::{
    kernel_frame_ingress::{
        KernelFrameIngressPacket, FRAME_CHAIN_RESULT_CAPACITY, FRAME_PACKET_BYTES,
        FRAME_RESULT_OFFSET,
    },
    walk_captured_kernel_frame_chain_with_stop, CapturedKernelCallSite,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameChainBrokerError {
    /// No result word was touched; the request may be refused with a zero count.
    Refused,
    /// A requested attached-user continuation could not retain its exact source.
    UnsupportedUserSource,
    /// At least one output word may have changed. The physical lane and Reply must be walled.
    Uncertain,
}

/// Walk from a Win64 ingress packet copied through the exact paused physical lane.
///
/// The native shim reserves a fixed result suffix on its own component stack. The executive
/// writes only that suffix via the retained stack alias; the opaque caller output VA is never
/// translated or dereferenced here. The provider copies the successful prefix after it resumes.
fn capture_kernel_frame_chain(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    packet_va: u64,
    kind: crate::spawn_hosts::ReqKind,
) -> Result<u32, FrameChainBrokerError> {
    use FrameChainBrokerError::{Refused, Uncertain, UnsupportedUserSource};

    if channel.caps.kind != kind
        || channel.reply_cap != reply_cap
        || packet_va & 15 != 0
    {
        return Err(Refused);
    }
    let lease = StackLease::new(channel, reply_cap, badge).ok_or(Refused)?;
    let (low, high) = lease.bounds().ok_or(Refused)?;
    let packet_end = packet_va
        .checked_add(FRAME_PACKET_BYTES as u64)
        .ok_or(Refused)?;
    if packet_va < low || packet_end > high || !lease.still_live() {
        return Err(Refused);
    }
    let result_va = packet_va
        .checked_add(FRAME_RESULT_OFFSET as u64)
        .ok_or(Refused)?;
    let result_exec = lease
        .translate(result_va, (FRAME_CHAIN_RESULT_CAPACITY * 8) as u64)
        .ok_or(Refused)?;
    let request_word = lease.read_u64(packet_va + 24).ok_or(Refused)?;
    if ((request_word >> 32) as u32) & 0xfe != 0 {
        return Err(UnsupportedUserSource);
    }
    let packet = KernelFrameIngressPacket::capture_bounded(packet_va, low, high, &lease)
        .ok_or(Refused)?;
    // The packet must be the native shim's own fixed frame immediately below its entry return
    // slot. Matching shape alone is insufficient; `from_entry` validates the return PC through
    // the exact reader and admitted catalog below.
    let mut frames = [0u64; FRAME_CHAIN_RESULT_CAPACITY];
    let mut wrote = false;
    if kind == crate::spawn_hosts::ReqKind::Irp && packet.flags() & 1 != 0 {
        return Err(UnsupportedUserSource);
    }
    let walked = super::with_catalog(channel, reply_cap, |catalog| {
        if !lease.still_live() {
            return Err(Refused);
        }
        let return_pc = lease.read_u64(packet.entry_rsp()).ok_or(Refused)?;
        let captured = CapturedKernelCallSite::from_entry(
            packet.context_at_return(return_pc),
            packet.entry_rsp(),
            low,
            high,
            catalog,
            &lease,
        )
        .map_err(|_| Refused)?;
        let kernel_walk = walk_captured_kernel_frame_chain_with_stop(
            captured,
            &mut frames[..packet.count() as usize],
            packet.flags() & !1,
            catalog,
            &lease,
        )
        .map_err(|_| Refused)?;
        let kernel_reported = kernel_walk.count as u32;
        let mut reported = kernel_reported;
        if packet.flags() & 1 != 0 && kernel_reported < packet.walk_capacity() {
            // An unknown kernel image is not proof of a kernel-to-user transition. Require the
            // retained lane walk to reach its exact stack boundary before consulting the
            // separately authenticated logical caller and user TCB snapshot.
            if !kernel_walk.stop.authorizes_attached_user() {
                return Err(UnsupportedUserSource);
            }
            // The registered logical caller is the explicit transport boundary between this
            // provider stack and its paused user TCB. Never infer that boundary from PC bits.
            let skipped = packet.flags() >> 8;
            let kernel_published = kernel_reported.saturating_sub(skipped) as usize;
            let user_skip = skipped.saturating_sub(kernel_reported) as usize;
            let user_count = unsafe {
                super::user_walk::walk_attached_user_frames(
                    channel,
                    &lease,
                    &mut frames[kernel_published..packet.count() as usize],
                    user_skip,
                )
            }
            .map_err(|_| UnsupportedUserSource)?;
            reported = reported.checked_add(user_count as u32).ok_or(Refused)?;
        }
        let published = packet.published_result_count(reported).ok_or(Refused)?;
        for (index, frame) in frames[..published].iter().enumerate() {
            if !lease.still_live() {
                return Err(if wrote { Uncertain } else { Refused });
            }
            unsafe {
                core::ptr::write_volatile((result_exec + index as u64 * 8) as *mut u64, *frame)
            };
            wrote = true;
        }
        if !lease.still_live() {
            return Err(if wrote { Uncertain } else { Refused });
        }
        Ok(reported)
    });
    match walked {
        Some(Ok(count)) => Ok(count),
        Some(Err(_error)) if wrote => Err(Uncertain),
        Some(Err(error)) => Err(error),
        None if wrote => Err(Uncertain),
        None => Err(Refused),
    }
}

pub(crate) fn capture_win32k_frame_chain(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    packet_va: u64,
) -> Result<u32, FrameChainBrokerError> {
    capture_kernel_frame_chain(
        channel, reply_cap, badge, packet_va, crate::spawn_hosts::ReqKind::Syscall,
    )
}

pub(crate) fn capture_hosted_driver_frame_chain(
    channel: &crate::spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    packet_va: u64,
) -> Result<u32, FrameChainBrokerError> {
    capture_kernel_frame_chain(
        channel, reply_cap, badge, packet_va, crate::spawn_hosts::ReqKind::Irp,
    )
}
