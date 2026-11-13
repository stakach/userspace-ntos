//! Native owner of the one physical win32k request and callback page.
//!
//! The lock protects only pure authority transitions. Client selection, page access, pumps,
//! and callbacks must run after it is dropped, while the authority remains Reserved, Active,
//! or Restoring. A busy or full authority refuses admission without consuming the caller's Reply.

use core::sync::atomic::{AtomicBool, Ordering};
use nt_user_callback::{
    SharedPageAuthority, SharedPageLeaseError, SharedPageLeaseIdentity,
    SharedPageProvisionalIdentity, SharedPageReservationEffect, SharedPageRestoreEffect,
    SharedPageSnapshot,
};

// An enforced storage limit, not a claim about all possible concurrent suspensions. A full
// table refuses capture while leaving the active owner and its Reply retained.
const MAX_PARKED: usize = 64;

static AUTHORITY_BUSY: AtomicBool = AtomicBool::new(false);
static mut AUTHORITY: SharedPageAuthority<MAX_PARKED> = SharedPageAuthority::new();

struct AuthorityGuard;

impl AuthorityGuard {
    fn acquire() -> Self {
        while AUTHORITY_BUSY
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }
}

impl Drop for AuthorityGuard {
    fn drop(&mut self) {
        AUTHORITY_BUSY.store(false, Ordering::Release);
    }
}

fn transition<R>(f: impl FnOnce(&mut SharedPageAuthority<MAX_PARKED>) -> R) -> R {
    let _guard = AuthorityGuard::acquire();
    // The guard is held only for this call. No reference to the static escapes the closure.
    f(unsafe { &mut *core::ptr::addr_of_mut!(AUTHORITY) })
}

pub(crate) fn reserve<R>(
    identity: SharedPageProvisionalIdentity,
    reply: R,
) -> Result<R, (SharedPageLeaseError, R)> {
    transition(|authority| authority.reserve(identity, reply))
}

pub(crate) fn cancel_reservation(
    identity: SharedPageProvisionalIdentity,
    effect: SharedPageReservationEffect,
) -> Result<(), SharedPageLeaseError> {
    transition(|authority| authority.cancel_reservation(identity, effect))
}

pub(crate) fn promote(
    identity: SharedPageProvisionalIdentity,
    admitted: SharedPageLeaseIdentity,
) -> Result<(), SharedPageLeaseError> {
    transition(|authority| authority.promote(identity, admitted))
}

pub(crate) fn capture_and_park(
    identity: SharedPageLeaseIdentity,
    snapshot: SharedPageSnapshot,
) -> Result<(), SharedPageLeaseError> {
    transition(|authority| authority.capture_and_park(identity, snapshot))
}

pub(crate) fn quarantine_active(
    identity: SharedPageLeaseIdentity,
) -> Result<(), SharedPageLeaseError> {
    transition(|authority| authority.quarantine_active(identity))
}

pub(crate) fn reacquire(
    identity: SharedPageLeaseIdentity,
) -> Result<SharedPageSnapshot, SharedPageLeaseError> {
    transition(|authority| authority.reacquire(identity))
}

pub(crate) fn acknowledge_restore(
    identity: SharedPageLeaseIdentity,
    effect: SharedPageRestoreEffect,
) -> Result<(), SharedPageLeaseError> {
    transition(|authority| authority.acknowledge_restore(identity, effect))
}

pub(crate) fn finish_active(identity: SharedPageLeaseIdentity) -> Result<(), SharedPageLeaseError> {
    transition(|authority| authority.finish_active(identity))
}
