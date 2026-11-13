//! Checked mechanism effects for an exclusively owned parked Reply pool slot.

use crate::*;

pub(crate) unsafe fn validate_saved(cap: u64) -> Result<usize, u32> {
    if cap == 0 || cap == REPLY_MAIN_SLOT.load(Ordering::Relaxed) {
        return Err(nt_fs::STATUS_INVALID_HANDLE);
    }
    let identity = wait_reply_pool_ref().find_cap(cap)
        .ok_or(nt_fs::STATUS_INVALID_HANDLE)?;
    (wait_reply_pool_ref().state(identity)
        == Ok(nt_component_suspension::RootReplySlotState::Used))
        .then_some(identity.slot()).ok_or(nt_fs::STATUS_INVALID_HANDLE)
}

pub(crate) unsafe fn revoke(cap: u64) -> Result<(), u32> {
    validate_saved(cap)?;
    if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(cap) {
        return spawn_hosts::shared_ingress::owner::runtime::cancel_hosted(cap)
            .map_err(|_| nt_status::NtStatus::UNSUCCESSFUL.raw() as u32);
    }
    // Delete the final owned capability, not just descendants. Rejected deletion does not mutate
    // the binding; the caller retains this step separately from the subsequent empty-slot retype.
    if cnode_delete_r(cap) != 0 {
        return Err(nt_status::NtStatus::UNSUCCESSFUL.raw() as u32);
    }
    Ok(())
}

pub(crate) unsafe fn retype(cap: u64) -> Result<(), u32> {
    let slot = validate_saved(cap)?;
    if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(cap) {
        if !spawn_hosts::shared_ingress::owner::runtime::hosted_reply_cancelled(cap) {
            return Err(nt_fs::STATUS_INVALID_HANDLE);
        }
        return spawn_hosts::shared_ingress::owner::runtime::release_hosted_reply(cap)
            .map_err(|_| nt_fs::STATUS_INVALID_HANDLE);
    }
    if untyped_retype_r(CAP_INIT_UNTYPED, OBJ_REPLY, 0, 1, cap) != 0 {
        return Err(nt_fs::STATUS_INSUFFICIENT_RESOURCES);
    }
    // No callout separates accepted retype from pool publication and the caller's receipt.
    wait_reply_pool_mark_free(slot)
        .then_some(()).ok_or(nt_fs::STATUS_INVALID_HANDLE)
}

pub(crate) unsafe fn retire_sent(cap: u64) -> Result<(), u32> {
    let slot = validate_saved(cap)?;
    if spawn_hosts::shared_ingress::owner::runtime::owns_hosted_reply(cap) {
        return spawn_hosts::shared_ingress::owner::runtime::release_hosted_reply(cap)
            .map_err(|_| nt_fs::STATUS_INVALID_HANDLE);
    }
    // An acknowledged Reply already consumed the binding. Do not delete or retype it again.
    wait_reply_pool_mark_free(slot)
        .then_some(()).ok_or(nt_fs::STATUS_INVALID_HANDLE)
}
