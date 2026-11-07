//! Durable, move-only handoff of one selected root Call and its held nested parent.
//!
//! This row is dormant until lane admission and original root Reply parking can be completed
//! together. Its numeric root Reply is only a captured selector: the later admission must
//! revalidate REPLY_MAIN_SLOT, exact pool identity and physical binding before any effect.

use super::*;
use nt_user_host::root_ingress_handoff::{
    RootIngressHandoffKey, RootIngressHandoffReservation, RootIngressHandoffTable,
    RootIngressHandoffTicket,
};
use nt_component_suspension::{ReplyBindingObservation, RootReplyIdentity, RootReplySlotState};

/// An observed original root Reply, authenticated again immediately before any park effect.
#[allow(dead_code)]
pub(crate) struct RootReplyAuthority {
    reply: u64,
    identity: RootReplyIdentity,
    binding: nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
}

pub(crate) struct Bundle {
    pub(crate) taken: win32k_glue::TakenRootIngressDispatch,
    authority: RootReplyAuthority,
}

impl Bundle {
    #[allow(dead_code)]
    pub(crate) fn authority(&self) -> &RootReplyAuthority { &self.authority }
}

static mut OWNERS: RootIngressHandoffTable<Bundle> = RootIngressHandoffTable::new();

/// Capture before taking the selected pending slot. The child's Reply is separate from this
/// delivered parent's Reply; a numeric match without pool generation and TCB binding is refused.
#[allow(dead_code)]
pub(crate) unsafe fn capture_root_reply_authority(reply: u64) -> Option<RootReplyAuthority> {
    if reply == 0 || REPLY_MAIN_SLOT.load(Ordering::Relaxed) != reply { return None; }
    let identity = wait_reply_pool_ref().find_cap(reply)?;
    if wait_reply_pool_ref().state(identity).ok() != Some(RootReplySlotState::Used) {
        return None;
    }
    let binding = crate::spawn_hosts::shared_ingress::owner::runtime
        ::parkable_hosted_reply_binding(reply)?;
    if crate::spawn_hosts::query_component_reply_binding(binding.tcb, reply)
        != Ok(ReplyBindingObservation::BoundToTarget)
    {
        return None;
    }
    Some(RootReplyAuthority { reply, identity, binding })
}

/// A fresh observation must still identify the same pool incarnation and hosted caller.
#[allow(dead_code)]
pub(crate) unsafe fn root_reply_authority_is_live(authority: &RootReplyAuthority) -> bool {
    capture_root_reply_authority(authority.reply).is_some_and(|current| {
        current.identity == authority.identity && current.binding == authority.binding
    })
}

#[allow(dead_code)]
pub(crate) unsafe fn reserve_capacity() -> Option<RootIngressHandoffReservation> {
    let _durable = allocator::enter_durable();
    (&mut *core::ptr::addr_of_mut!(OWNERS)).reserve().ok()
}

#[allow(dead_code)]
pub(crate) unsafe fn cancel_reservation(reservation: RootIngressHandoffReservation) -> bool {
    (&mut *core::ptr::addr_of_mut!(OWNERS)).cancel_reservation(reservation)
}

/// Check the pending copy against its move-only physical parent before storing either. The
/// supplied root Reply is not authenticated here; this is durable storage, not lane admission.
/// Refusal returns the complete bundle, and the reservation remains available for cancellation.
#[allow(dead_code)]
pub(crate) unsafe fn retain(
    reservation: RootIngressHandoffReservation,
    taken: win32k_glue::TakenRootIngressDispatch,
    authority: RootReplyAuthority,
) -> Result<RootIngressHandoffTicket, (win32k_glue::TakenRootIngressDispatch, RootReplyAuthority)> {
    let win32k_glue::RootIngressYield::ParkedUnbound { ticket, child, owner, .. } = taken.pending.yielded
    else { return Err((taken, authority)) };
    let parent_identity = taken.parent.identity();
    let snapshot = taken.pending.snapshot;
    if ticket != taken.parent.ticket()
        || parent_identity.dispatch().lane() != snapshot.dispatch.lane
        || snapshot.callback_token.is_some()
        || snapshot.pump.reply_cap == 0
        || owner.dispatch_id != snapshot.dispatch.dispatch_id
        || !crate::spawn_hosts::shared_ingress::owner::runtime::nested
            ::undelivered_root_parent_candidate(&taken.parent, child)
        || !crate::spawn_hosts::shared_ingress::owner::runtime
            ::prepared_root_ingress_child_is_current(child)
        || child.reply() == authority.reply
        || !root_reply_authority_is_live(&authority)
    {
        return Err((taken, authority));
    }
    let Some(key) = RootIngressHandoffKey::new(parent_identity, child, authority.reply) else {
        return Err((taken, authority));
    };
    (&mut *core::ptr::addr_of_mut!(OWNERS))
        .retain(reservation, key, Bundle { taken, authority })
        .map_err(|(_, bundle)| (bundle.taken, bundle.authority))
}

/// The exact ticket may lend its bundle to a later lane transfer. A refused transfer must
/// return the same bundle to this row; neither operation changes a physical Reply.
#[allow(dead_code)]
pub(crate) unsafe fn take(ticket: RootIngressHandoffTicket) -> Option<Bundle> {
    (&mut *core::ptr::addr_of_mut!(OWNERS)).take(ticket)
}

#[allow(dead_code)]
pub(crate) unsafe fn restore(
    ticket: RootIngressHandoffTicket,
    taken: Bundle,
) -> Result<(), Bundle> {
    (&mut *core::ptr::addr_of_mut!(OWNERS)).restore(ticket, taken)
}
