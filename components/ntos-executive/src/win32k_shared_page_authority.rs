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

// ----------------------------------------------------------------------------------------------
// #419 stage 1: audit mode. Every write-to-dispatch transition goes through the authority, but a
// refusal is reported and repaired instead of refusing work, so a lifecycle site that is not yet
// wired shows up as a tagged violation in the boot log rather than wedging win32k.

/// False while the lifecycle wiring is audited; enforcing mode refuses instead of repairing.
pub(crate) const ENFORCING: bool = false;

static VIOLATIONS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Total audit violations so far.
pub(crate) fn violations() -> u64 {
    VIOLATIONS.load(Ordering::Relaxed)
}

/// Whether some dispatch holds the page (reserved, active, restoring or pinned).
pub(crate) fn is_held() -> bool {
    transition(|authority| authority.is_held())
}

fn error_name(error: SharedPageLeaseError) -> &'static [u8] {
    match error {
        SharedPageLeaseError::InvalidIdentity => b"invalid-identity",
        SharedPageLeaseError::Duplicate => b"duplicate",
        SharedPageLeaseError::Capacity => b"capacity",
        SharedPageLeaseError::Empty => b"empty",
        SharedPageLeaseError::NotTop => b"not-top",
        SharedPageLeaseError::WrongSnapshot => b"wrong-snapshot",
        SharedPageLeaseError::AlreadyDisplaced => b"already-displaced",
        SharedPageLeaseError::MissingSnapshot => b"missing-snapshot",
        SharedPageLeaseError::UnexpectedCurrent => b"unexpected-current",
        SharedPageLeaseError::NotDisplaced => b"not-displaced",
        SharedPageLeaseError::RestoreNotApplied => b"restore-not-applied",
        SharedPageLeaseError::Uncertain => b"uncertain",
    }
}

fn report(site: &[u8], op: &[u8], error: &[u8], dispatch_id: u64, client: nt_user_callback::SharedPageClientIdentity) {
    let holder = transition(|authority| authority.audit_holder());
    let total = VIOLATIONS.fetch_add(1, Ordering::Relaxed) + 1;
    if total > 64 && !total.is_power_of_two() {
        return;
    }
    crate::print_str(b"[w32k-page-authority] violation #");
    crate::print_u64(total);
    crate::print_str(b" site=");
    crate::print_str(site);
    crate::print_str(b" op=");
    crate::print_str(op);
    crate::print_str(b" error=");
    crate::print_str(error);
    crate::print_str(b" dispatch=");
    crate::print_u64(dispatch_id);
    crate::print_str(b" pi/tid=");
    crate::print_u64(u64::from(client.pi));
    crate::print_str(b"/");
    crate::print_u64(client.tid);
    crate::print_str(b" holder=");
    let (kind, id): (&[u8], u64) = match holder {
        nt_user_callback::SharedPageAuditHolder::None => (b"none", 0),
        nt_user_callback::SharedPageAuditHolder::Reserved(id) => (b"reserved", id),
        nt_user_callback::SharedPageAuditHolder::Active(id) => (b"active", id),
        nt_user_callback::SharedPageAuditHolder::Restoring(id) => (b"restoring", id),
        nt_user_callback::SharedPageAuditHolder::Uncertain(id) => (b"uncertain", id),
    };
    crate::print_str(kind);
    crate::print_str(b":");
    crate::print_u64(id);
    crate::print_str(b"\n");
}

/// Root ingress, before the first shared ARG write: no other dispatch may hold the page.
pub(crate) fn audit_root_free(dispatch_id: u64, client: nt_user_callback::SharedPageClientIdentity, site: &[u8]) {
    if is_held() {
        report(site, b"root-ingress", b"page-held", dispatch_id, client);
        // The holder never released the page: the next transition starts from a free page.
        transition(|authority| {
            let holder = match authority.audit_holder() {
                nt_user_callback::SharedPageAuditHolder::None => return,
                nt_user_callback::SharedPageAuditHolder::Reserved(id)
                | nt_user_callback::SharedPageAuditHolder::Active(id)
                | nt_user_callback::SharedPageAuditHolder::Restoring(id)
                | nt_user_callback::SharedPageAuditHolder::Uncertain(id) => id,
            };
            authority.audit_force_clear(holder);
        });
    }
}

/// Root ingress: reserve the page before the first shared ARG write.
pub(crate) fn audit_reserve(identity: SharedPageProvisionalIdentity, site: &[u8]) {
    if let Err((error, ())) = reserve(identity, ()) {
        report(site, b"reserve", error_name(error), identity.dispatch_id, identity.client);
        transition(|authority| {
            authority.audit_force_clear(identity.dispatch_id);
            let _ = authority.reserve(identity, ());
        });
    }
}

/// A root reservation whose call never reached a lane is released without effect.
pub(crate) fn audit_cancel(identity: SharedPageProvisionalIdentity, site: &[u8]) {
    if let Err(error) = cancel_reservation(identity, SharedPageReservationEffect::NoEffect) {
        report(site, b"cancel", error_name(error), identity.dispatch_id, identity.client);
        transition(|authority| authority.audit_force_clear(identity.dispatch_id));
    }
}

/// First write of a dispatch's request: adopt its root reservation, or enter directly.
pub(crate) fn audit_enter(identity: SharedPageLeaseIdentity, site: &[u8]) {
    let id = identity.dispatch.dispatch_id;
    let result = transition(|authority| {
        if authority.audit_holder() == nt_user_callback::SharedPageAuditHolder::Reserved(id) {
            authority.audit_force_active(identity);
            return Ok(());
        }
        authority.enter(identity, ()).map(|()| ()).map_err(|(error, ())| error)
    });
    if let Err(error) = result {
        report(site, b"enter", error_name(error), id, identity.client);
        transition(|authority| authority.audit_force_active(identity));
    }
}

/// A dispatch yields: its exact full publication moves into the parked table.
pub(crate) fn audit_park(identity: SharedPageLeaseIdentity, snapshot: Option<SharedPageSnapshot>, site: &[u8]) {
    let id = identity.dispatch.dispatch_id;
    let Some(snapshot) = snapshot else {
        report(site, b"park", b"no-exact-snapshot", id, identity.client);
        transition(|authority| authority.audit_force_clear(id));
        return;
    };
    if let Err(error) = capture_and_park(identity, snapshot) {
        report(site, b"park", error_name(error), id, identity.client);
        transition(|authority| authority.audit_force_park(identity, snapshot));
    }
}

/// A parked dispatch takes the page back before its publication is restored.
pub(crate) fn audit_reacquire(identity: SharedPageLeaseIdentity, site: &[u8]) {
    if let Err(error) = reacquire(identity) {
        report(site, b"reacquire", error_name(error), identity.dispatch.dispatch_id, identity.client);
        transition(|authority| authority.audit_force_active(identity));
    }
}

/// The restore's physical evidence: the exact page written, or nothing written.
pub(crate) fn audit_restored(identity: SharedPageLeaseIdentity, applied: Option<SharedPageSnapshot>, site: &[u8]) {
    let effect = match applied {
        Some(page) => SharedPageRestoreEffect::Applied(page),
        None => SharedPageRestoreEffect::NoEffect,
    };
    if let Err(error) = acknowledge_restore(identity, effect) {
        report(site, b"restore", error_name(error), identity.dispatch.dispatch_id, identity.client);
        transition(|authority| authority.audit_force_active(identity));
    }
}

/// A dispatch completed: the page has no writer.
pub(crate) fn audit_finish(identity: SharedPageLeaseIdentity, site: &[u8]) {
    if let Err(error) = finish_active(identity) {
        report(site, b"finish", error_name(error), identity.dispatch.dispatch_id, identity.client);
        transition(|authority| authority.audit_force_clear(identity.dispatch.dispatch_id));
    }
}
