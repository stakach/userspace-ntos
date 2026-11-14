//! Named, bounded receipts for a hosted dispatch the pump could not own.
//!
//! An ownership refusal fails the one dispatch that asked for it. Before admission nothing has
//! been issued, so the request reports a refusal status and the retained Call stays where it
//! was. After admission the dispatch stays fenced on its lane: the pump result is never
//! reported as completed, and no Reply or request page is handed to another dispatch.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_component_suspension::AdmissionRefusal;

const STATUS_DEVICE_BUSY: i32 = nt_status::NtStatus::DEVICE_BUSY.raw();
const RECEIPT_CAP: u64 = 16;

static RECEIPTS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub(super) enum Invariant {
    /// The transport snapshot does not resolve to its retained physical source.
    PhysicalIngressIdentity,
    /// A dispatch was requested for a source that never enrolled a route.
    EnrolledSource,
    /// The running parent could not be parked for the nested dispatch.
    NestedParentPark,
    /// The shared ingress refused to admit the target's retained Call.
    DispatchAdmission(Option<AdmissionRefusal>),
    /// The admitted lane has no canonical Reply to answer on.
    AdmittedCanonicalReply,
    /// The root-issued registry caller does not match the executing job.
    RegistryCaller,
    /// The driver thread projection for this execution is not retained.
    ThreadProjection,
    /// A scheduler yield lost the canonical Reply of its own dispatch.
    YieldedCanonicalReply,
    /// A scheduler yield did not retain its exact receive continuation.
    YieldedReceiveContinuation,
    /// The final completion Call does not authenticate against the admitted dispatch.
    CompletionAuthentication,
}

impl Invariant {
    fn name(self) -> &'static str {
        match self {
            Self::PhysicalIngressIdentity => "physical-ingress-identity",
            Self::EnrolledSource => "enrolled-source",
            Self::NestedParentPark => "nested-parent-park",
            Self::DispatchAdmission(_) => "dispatch-admission",
            Self::AdmittedCanonicalReply => "admitted-canonical-reply",
            Self::RegistryCaller => "registry-caller",
            Self::ThreadProjection => "thread-projection",
            Self::YieldedCanonicalReply => "yielded-canonical-reply",
            Self::YieldedReceiveContinuation => "yielded-receive-continuation",
            Self::CompletionAuthentication => "completion-authentication",
        }
    }

    fn detail(self) -> &'static str {
        match self {
            Self::DispatchAdmission(Some(refusal)) => refusal.name(),
            Self::DispatchAdmission(None) => "unresolved-caller",
            _ => "-",
        }
    }

    /// Nothing has been issued to the target yet: its Call is still retained and unadmitted.
    fn precedes_admission(self) -> bool {
        matches!(
            self,
            Self::PhysicalIngressIdentity
                | Self::EnrolledSource
                | Self::NestedParentPark
                | Self::DispatchAdmission(_)
        )
    }

    /// A refusal before admission has no effects and may be retried by its caller. Everything
    /// later leaves an admitted or entered dispatch behind and is reported as a plain failure.
    fn status(self) -> i32 {
        match self {
            Self::PhysicalIngressIdentity | Self::EnrolledSource => STATUS_INVALID_HANDLE,
            Self::NestedParentPark | Self::DispatchAdmission(_) => STATUS_DEVICE_BUSY,
            _ => STATUS_UNSUCCESSFUL,
        }
    }
}

/// Read-only: names the refused invariant, the target route and lane, and the lane that held
/// the execution token. The first receipts and every power-of-two repeat are printed.
pub(super) unsafe fn receipt(
    invariant: Invariant,
    channel: &crate::spawn_hosts::PumpChannel,
    parent_parked: bool,
) {
    let count = RECEIPTS.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    if count > RECEIPT_CAP && !count.is_power_of_two() {
        return;
    }
    let identity = channel.ingress_route.map(|route| route.identity());
    let readiness = channel.ingress_route.and_then(|route| runtime::admission_readiness(route).ok());
    print_str(b"[hosted-pump-refusal] invariant=");
    print_str(invariant.name().as_bytes());
    print_str(b" detail=");
    print_str(invariant.detail().as_bytes());
    print_str(b" status=0x");
    print_hex(invariant.status() as u32);
    print_str(b" route=");
    print_u64(channel.ingress_route.map_or(0, |route| route.badge()));
    print_str(b" lane=");
    print_u64(identity.map_or(0, |identity| identity.lane.index as u64));
    print_str(b"/");
    print_u64(identity.map_or(0, |identity| identity.lane.generation));
    print_str(b" tcb=0x");
    print_hex64(channel.tcb);
    print_str(b" running-lane=");
    match runtime::running_lane() {
        Some(lane) => {
            print_u64(lane.index as u64);
            print_str(b"/");
            print_u64(lane.generation);
        }
        None => print_str(b"none"),
    }
    print_str(b" parent-parked=");
    print_u64(u64::from(parent_parked));
    print_str(b" receive-busy/held-call/pool=");
    match readiness {
        Some(readiness) => {
            print_u64(u64::from(readiness.receive_busy));
            print_str(b"/");
            print_u64(u64::from(readiness.held_call));
            print_str(b"/");
            print_u64(readiness.pool_len as u64);
            print_str(b":");
            print_u64(readiness.pool_capacity as u64);
        }
        None => print_str(b"unknown"),
    }
    print_str(b" count=");
    print_u64(count);
    print_str(b"\n");
}

/// Fail one dispatch that was refused before the component was entered.
pub(super) unsafe fn refuse(
    invariant: Invariant,
    channel: &crate::spawn_hosts::PumpChannel,
    parent: Option<runtime::nested::ParkedParentHandle>,
) -> HostedPumpRestore {
    receipt(invariant, channel, parent.is_some());
    let mut result = crate::spawn_hosts::PumpResult::refused(invariant.status(), channel.reply_cap);
    result.refused_before_entry = invariant.precedes_admission();
    restore_parent(result, parent)
}

/// The component was entered and its exact continuation was lost. Keep the result uncertain:
/// it is never reported completed, and its lane stays admitted so nothing reuses the Reply.
pub(super) unsafe fn retain_uncertain(
    invariant: Invariant,
    channel: &crate::spawn_hosts::PumpChannel,
    result: &mut crate::spawn_hosts::PumpResult,
    parent_parked: bool,
) {
    receipt(invariant, channel, parent_parked);
    result.completed = false;
    result.scheduler_yielded = false;
    result.status = invariant.status();
}

/// Return a refused result through the exact parked parent, as the pump does for an entered one.
/// A parent that cannot be restored keeps its retained row, and the result stays attributed to
/// it instead of being reported upward.
unsafe fn restore_parent(
    result: crate::spawn_hosts::PumpResult,
    mut parent: Option<runtime::nested::ParkedParentHandle>,
) -> HostedPumpRestore {
    let restore_key = parent.as_ref().and_then(|handle| runtime::nested::result_key(handle));
    let restore_ticket = parent.as_ref().map(|handle| handle.ticket());
    if runtime::nested::restore(&mut parent).is_err() {
        // An impossible missing key is still a retained refusal. The physical row remains
        // discoverable in `runtime::nested`; never return an entered result as completed.
        let (Some(key), Some(ticket)) = (restore_key, restore_ticket) else {
            return HostedPumpRestore::Unattributed(result);
        };
        return HostedPumpRestore::Retained {
            result,
            key,
            ticket,
            retryable: runtime::nested::pending_ticket(ticket),
        };
    }
    HostedPumpRestore::Restored(result)
}
