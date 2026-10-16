//! Checked user stack and lazy image reader for one paused win32k logical caller.
//!
//! The physical provider lane and its exact logical caller must remain retained until the walk
//! and any result publication complete. This module does not infer a kernel-to-user transition;
//! the broker must first prove that transition at its dispatch boundary.

use super::StackLease;
use nt_unwind::{
    exception_walk::ExceptionImageError,
    user_frame_source::{AuthenticatedUserFrameSource, UserFrameIdentity, UserFrameSnapshot},
    user_image_catalog::OnDemandUserImageCatalog,
    FrameWalkError, StackReader,
};

struct AttachedUserStackReader<'a> {
    channel: &'a crate::spawn_hosts::PumpChannel,
    lease: &'a StackLease,
    caller: nt_user_host::provider_logical_caller::ProviderLogicalCaller,
    handler_ptr: *mut crate::ExecNtHandler,
    identity: UserFrameIdentity,
    allocation_base: u64,
    stack_low: u64,
    stack_high: u64,
}

impl AttachedUserStackReader<'_> {
    fn still_live(&self) -> bool {
        unsafe {
            self.lease.still_live()
                && crate::win32k_glue::registry_logical_caller_is_current(self.channel)
                && self.channel.logical_caller == Some(self.caller)
                && crate::service_sec_image::registry_live_handler_pointer().ok()
                    == Some(self.handler_ptr)
                && self.handler_ptr.as_ref().is_some_and(|handler| {
                    handler.validate_provider_logical_caller(self.caller)
                        && handler.capture_process_identity(self.caller.pi())
                            == Some(self.caller.process())
                        && handler.hosted_thread_tcb_for_badge(self.caller.badge())
                            == Some(self.identity.tcb)
                        && handler.hosted_thread_teb_for_badge(self.caller.badge())
                            == Some(self.identity.teb)
                        && handler.hosted_thread_user_stack_for_badge(
                            self.caller.badge(), self.caller.pi(),
                        ).is_some_and(|(base, top, _)| {
                            base == self.allocation_base && top == self.stack_high
                        })
                })
        }
    }
}

impl StackReader for AttachedUserStackReader<'_> {
    fn read_u64(&self, address: u64) -> Option<u64> {
        if address & 7 != 0
            || address <= self.stack_low
            || address.checked_add(8)? > self.stack_high
            || !self.still_live()
        {
            return None;
        }
        unsafe {
            let map = crate::process_vm_region_map(self.caller.pi())?;
            let extent = map.extent_at(address)?;
            if extent.allocation_base != self.allocation_base
                || extent.type_ != nt_address_space::MEM_PRIVATE
                || extent.state != nt_address_space::VmExtentState::Committed
                || map.protection_at(address)? & nt_address_space::PAGE_GUARD != 0
            {
                return None;
            }
            let mut bytes = [0u8; 8];
            // The native executive owns the single serialized handler for this paused dispatch.
            // The raw pointer avoids retaining a mutable handler borrow across checked page IO.
            (&mut *self.handler_ptr)
                .process_memory_read_status(self.caller.pi(), address, &mut bytes)
                .ok()?;
            self.still_live().then(|| u64::from_le_bytes(bytes))
        }
    }
}

/// Validate and walk the logical user's continuation under the exact running dispatch. The
/// caller applies one combined high-byte skip budget across kernel and user frames before staging.
pub(super) unsafe fn walk_attached_user_frames(
    channel: &crate::spawn_hosts::PumpChannel,
    lease: &StackLease,
    callers: &mut [u64],
    frames_to_skip: usize,
) -> Result<usize, FrameWalkError> {
    let caller = channel.logical_caller.ok_or(FrameWalkError::UnknownImage)?;
    let (snapshot, allocation_base, runtime_stack_top) =
        super::user_source::capture_attached_user_frame_snapshot(channel, lease)
            .ok_or(FrameWalkError::InvalidCallSite)?;
    let handler_ptr = crate::service_sec_image::registry_live_handler_pointer()
        .map_err(|_| FrameWalkError::UnknownImage)?;
    let reader = AttachedUserStackReader {
        channel,
        lease,
        caller,
        handler_ptr,
        identity: snapshot.identity,
        allocation_base,
        stack_low: snapshot.teb_stack_low,
        stack_high: snapshot.teb_stack_high,
    };
    if !reader.still_live() {
        return Err(FrameWalkError::InvalidCallSite);
    }
    let catalog = OnDemandUserImageCatalog::new(128, |pc| {
        if !reader.still_live() {
            return Err(ExceptionImageError::UnreadableImage);
        }
        let image = super::user_image::image_for_user_pc(handler_ptr, caller, pc)?;
        reader.still_live().then_some(image).ok_or(ExceptionImageError::UnreadableImage)
    }).ok_or(FrameWalkError::UnknownImage)?;
    let expected = UserFrameIdentity {
        process_generation: channel.client_generation,
        thread_activation: caller.thread().generation(),
        tcb: caller.tcb(),
        teb: snapshot.identity.teb,
    };
    let source = AuthenticatedUserFrameSource::admit(
        expected, snapshot, allocation_base, runtime_stack_top, &catalog,
    ).map_err(|_| FrameWalkError::UnknownImage)?;
    let count = source.walk_continuation(callers, frames_to_skip, &catalog, &reader)?;
    if !reader.still_live() {
        return Err(FrameWalkError::InvalidCallSite);
    }
    Ok(count)
}
