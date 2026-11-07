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

type Bundle = win32k_glue::TakenRootIngressDispatch;

static mut OWNERS: RootIngressHandoffTable<Bundle> = RootIngressHandoffTable::new();

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
    taken: Bundle,
    root_reply: u64,
) -> Result<RootIngressHandoffTicket, Bundle> {
    let win32k_glue::RootIngressYield::ParkedUnbound { ticket, child, owner, .. } = taken.pending.yielded
    else { return Err(taken) };
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
    {
        return Err(taken);
    }
    let Some(key) = RootIngressHandoffKey::new(parent_identity, child, root_reply) else {
        return Err(taken);
    };
    (&mut *core::ptr::addr_of_mut!(OWNERS))
        .retain(reservation, key, taken)
        .map_err(|(_, taken)| taken)
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
