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

pub(crate) fn promote(
    identity: SharedPageProvisionalIdentity,
    admitted: SharedPageLeaseIdentity,
) -> Result<(), SharedPageLeaseError> {
    transition(|authority| authority.promote(identity, admitted))
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

// ----------------------------------------------------------------------------------------------
// #419: every write-to-dispatch transition goes through the authority. Enforcing, a refused
// transition is reported and refused: the caller retains its pending owner or answers Busy
// with no effect. With ENFORCING false (audit mode, kept for diagnosis) the authority is
// repaired instead, so a missed site shows up in the boot log rather than wedging win32k.

/// Whether refused transitions are refused (true) or reported and repaired (audit mode).
pub(crate) const ENFORCING: bool = true;

static VIOLATIONS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Total violations so far.
pub(crate) fn violations() -> u64 {
    VIOLATIONS.load(Ordering::Relaxed)
}

/// Parked dispatches, for the census.
pub(crate) fn parked_count() -> usize {
    transition(|authority| authority.parked_count())
}

/// Whether some dispatch holds the page (reserved, active, restoring or pinned).
pub(crate) fn is_held() -> bool {
    transition(|authority| authority.is_held())
}

/// Audit mode only: put the authority back in a consistent state after a refused transition.
fn repair(f: impl FnOnce(&mut SharedPageAuthority<MAX_PARKED>)) {
    if !ENFORCING {
        transition(f);
    }
}

/// A pre-lane hold of the page by one exact provisional dispatch. Dropped while still only
/// reserved (a local refusal before the dispatch's first page write), it is cancelled with no
/// effect. Once promoted, dropping it does nothing: the dispatch's settlement owns the page.
pub(crate) struct PageReservation(SharedPageProvisionalIdentity);

impl Drop for PageReservation {
    fn drop(&mut self) {
        let identity = self.0;
        transition(|authority| {
            if authority.reservation() == Some(identity) {
                // Reserved means no request, header or context cell was written for it.
                let _ = authority.cancel_reservation(identity, SharedPageReservationEffect::NoEffect);
            }
        });
    }
}

/// Reserve the page before a dispatch's first shared write. Busy is ordinary contention,
/// not a violation: the caller retains its Call (root) or answers Busy (funnel).
pub(crate) fn reserve(
    identity: SharedPageProvisionalIdentity,
) -> Result<PageReservation, SharedPageLeaseError> {
    transition(|authority| authority.reserve(identity, ()))
        .map(|()| PageReservation(identity))
        .map_err(|(error, ())| error)
}

/// The root's reservation for this exact dispatch, if root ingress reserved it.
pub(crate) fn root_reservation(dispatch_id: u64) -> Option<SharedPageProvisionalIdentity> {
    transition(|authority| authority.reservation()).filter(|owner| owner.dispatch_id == dispatch_id)
}

/// Bind the reservation to its admitted lane before the first request write. False refuses.
pub(crate) fn promote_page(
    reserved: SharedPageProvisionalIdentity,
    admitted: SharedPageLeaseIdentity,
    site: &[u8],
) -> bool {
    match promote(reserved, admitted) {
        Ok(()) => true,
        Err(error) => {
            report(site, b"promote", error_name(error), admitted.dispatch.dispatch_id, admitted.client);
            repair(|authority| authority.audit_force_active(admitted));
            !ENFORCING
        }
    }
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
    print_holder(holder);
    crate::print_str(b"\n");
}

static ROOT_INGRESS_BUSY_TRACES: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// A root ingress found the page held and returned its Call to the ingress owner. Names the
/// holder (the dispatch that keeps the page), whether the prelude witness still matched, and
/// whether the return succeeded. Bounded: 16, then powers of two.
pub(crate) fn trace_root_ingress_busy(
    dispatch_id: u64,
    client: nt_user_callback::SharedPageClientIdentity,
    ssn: u64,
    error: SharedPageLeaseError,
    witnessed: bool,
    returned: bool,
) {
    let sample = ROOT_INGRESS_BUSY_TRACES.fetch_add(1, Ordering::Relaxed) + 1;
    if sample > 16 && !sample.is_power_of_two() { return; }
    let holder = transition(|authority| authority.audit_holder());
    crate::print_str(b"[w32k-page-authority] root ingress busy sample=");
    crate::print_u64(sample);
    crate::print_str(b" dispatch=");
    crate::print_u64(dispatch_id);
    crate::print_str(b" pi/tid=");
    crate::print_u64(u64::from(client.pi));
    crate::print_str(b"/");
    crate::print_u64(client.tid);
    crate::print_str(b" ssn=0x");
    crate::print_hex_u64(ssn);
    crate::print_str(b" error=");
    crate::print_str(error_name(error));
    crate::print_str(b" witnessed=");
    crate::print_u64(u64::from(witnessed));
    crate::print_str(b" returned=");
    crate::print_u64(u64::from(returned));
    crate::print_str(b" holder=");
    print_holder(holder);
    crate::print_str(b"\n");
}

fn print_holder(holder: nt_user_callback::SharedPageAuditHolder) {
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
}

/// One pump return (or a lend of the page) settles its dispatch's hold exactly once.
pub(crate) fn audit_settle(
    identity: SharedPageLeaseIdentity,
    settlement: nt_user_callback::SharedPagePumpSettlement,
    site: &[u8],
) {
    use nt_user_callback::SharedPagePumpSettlement as Settlement;
    let Err(error) = transition(|authority| authority.settle(identity, settlement)) else { return };
    let id = identity.dispatch.dispatch_id;
    let (op, error): (&[u8], &[u8]) = match settlement {
        Settlement::Yielded(None) => (b"park", b"no-exact-snapshot"),
        Settlement::Yielded(Some(_)) => (b"park", error_name(error)),
        Settlement::Completed => (b"finish", error_name(error)),
        Settlement::Retained => (b"retain", error_name(error)),
    };
    report(site, op, error, id, identity.client);
    repair(|authority| match settlement {
        Settlement::Yielded(Some(snapshot)) => authority.audit_force_park(identity, snapshot),
        Settlement::Yielded(None) | Settlement::Completed => authority.audit_force_clear(id),
        Settlement::Retained => authority.audit_force_active(identity),
    });
}

/// A dispatch lends the page with its exact full publication (a nested child or source terminal
/// is about to write it).
pub(crate) fn audit_park(identity: SharedPageLeaseIdentity, snapshot: Option<SharedPageSnapshot>, site: &[u8]) {
    audit_settle(identity, nt_user_callback::SharedPagePumpSettlement::Yielded(snapshot), site);
}

/// A parked dispatch takes the page back before its publication is restored. Returns the
/// exact page it parked. `Err` refuses the resume (in audit mode the caller may go on, and
/// `expected`, its retained copy, seeds the repair).
pub(crate) fn audit_reacquire(
    identity: SharedPageLeaseIdentity,
    expected: Option<SharedPageSnapshot>,
    site: &[u8],
) -> Result<SharedPageSnapshot, ()> {
    reacquire(identity).map_err(|error| {
        report(site, b"reacquire", error_name(error), identity.dispatch.dispatch_id, identity.client);
        repair(|authority| match expected {
            Some(saved) => authority.audit_force_restoring(identity, saved),
            None => authority.audit_force_active(identity),
        });
    })
}

/// A user callback was abandoned (its continuations discarded): its dispatch never takes the
/// page back, so its parked page is retired instead of filling the table.
pub(crate) fn retire_parked(dispatch_id: u64) -> bool {
    transition(|authority| authority.retire_parked(dispatch_id))
}

/// The restore's physical evidence: the exact page written, or nothing written.
pub(crate) fn audit_restored(identity: SharedPageLeaseIdentity, applied: Option<SharedPageSnapshot>, site: &[u8]) {
    let effect = match applied {
        Some(page) => SharedPageRestoreEffect::Applied(page),
        None => SharedPageRestoreEffect::NoEffect,
    };
    if let Err(error) = acknowledge_restore(identity, effect) {
        report(site, b"restore", error_name(error), identity.dispatch.dispatch_id, identity.client);
        repair(|authority| authority.audit_force_active(identity));
    }
}
