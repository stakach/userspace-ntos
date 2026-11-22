use crate::HostedProviderObjectOwner;

/// A dispatch-loop receipt only releases a worker for reuse when the guarded native call
/// itself completed successfully. A failed guarded call can have uncertain native effects.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderExportCompletion {
    Reusable,
    Retain(i32),
}

pub const fn classify_hosted_provider_export_completion(
    completed: bool,
    status: i32,
) -> HostedProviderExportCompletion {
    if !completed {
        HostedProviderExportCompletion::Retain(0xc000_0001u32 as i32)
    } else if status != 0 {
        HostedProviderExportCompletion::Retain(status)
    } else {
        HostedProviderExportCompletion::Reusable
    }
}

/// How one provider-export dispatch slice ended for the export's owner (#420).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderExportPumpEnd {
    /// The pump returned this receipt.
    Returned { completed: bool, status: i32 },
    /// The pump stopped unfinished and is kept by the calling service's continuation: the
    /// export has not returned yet, so nothing about its result is known.
    Kept,
}

/// The worker lane row after one dispatch slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedProviderExportWorkerPhase {
    /// Reusable for the next export.
    Ready,
    /// Still running this export; no other export may select it.
    Entered,
    /// The export may have had native effects that are not accounted for.
    Uncertain,
}

/// An unfinished, kept export is still running: its row stays `Entered` until the kept pump
/// finishes and its own completion classifies it. Only a returned receipt can release it.
pub const fn hosted_provider_export_worker_phase(
    end: HostedProviderExportPumpEnd,
) -> HostedProviderExportWorkerPhase {
    match end {
        HostedProviderExportPumpEnd::Kept => HostedProviderExportWorkerPhase::Entered,
        HostedProviderExportPumpEnd::Returned { completed, status } =>
            match classify_hosted_provider_export_completion(completed, status) {
                HostedProviderExportCompletion::Reusable => HostedProviderExportWorkerPhase::Ready,
                HostedProviderExportCompletion::Retain(_) =>
                    HostedProviderExportWorkerPhase::Uncertain,
            },
    }
}

/// Whether a provider export runs on a provider worker lane instead of the primary lane.
///
/// DXG interface callbacks always do. Any other export does when the provider's primary lane
/// cannot admit it because that lane is already running: the provider called out into this
/// dependent and the dependent re-entered the provider (NDIS calls a miniport's
/// MiniportInitialize, which calls NdisAllocateMemoryWithTag). In NT that is a nested call on
/// the same thread; here it needs a second lane, since the primary's Reply is in use.
pub const fn hosted_provider_export_needs_worker(dxg_callback: bool, primary_admits: bool) -> bool {
    dxg_callback || !primary_admits
}

/// Whether a provider may get a worker lane for a reentrant export.
///
/// A provider library such as ndis.sys never publishes a device stack, so its instance never
/// becomes dispatch-ready; readiness gates ordinary device dispatch, not exports. A worker lane
/// needs a live, unfaulted provider with a published export singleton and a primary lane.
pub const fn hosted_provider_worker_admissible(
    faulted: bool,
    singleton_published: bool,
    primary_route: bool,
) -> bool {
    !faulted && singleton_published && primary_route
}

/// Which authenticated lane of a hosted instance a service request came from. Every lane a
/// driver's code runs on is a full execution context of that instance: it has its own IRQL for
/// CR8 emulation, and may use the instance's services (e.g. synchronise with its interrupt).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HostedInstanceLane {
    /// The instance's primary lane and its shared bank.
    Primary,
    /// A dispatch worker (provider-export or ordinary/class) and its own bank.
    Worker,
}

/// Identify exactly one authenticated physical lane of the instance, or none: a lane of another
/// instance, or an unauthenticated one, matches none of these.
pub const fn hosted_instance_lane(primary: bool, provider_worker: bool, ordinary_worker: bool)
    -> Option<HostedInstanceLane> {
    match (primary, provider_worker, ordinary_worker) {
        (true, false, false) => Some(HostedInstanceLane::Primary),
        (false, true, false) | (false, false, true) => Some(HostedInstanceLane::Worker),
        _ => None,
    }
}

/// The bank holding the authenticated lane's own IRQL byte: the primary's shared bank, or a
/// worker's own bank.
pub const fn hosted_lane_irql_bank(lane: HostedInstanceLane, primary_shared: u64, channel_shared: u64) -> u64 {
    match lane {
        HostedInstanceLane::Primary => primary_shared,
        HostedInstanceLane::Worker => channel_shared,
    }
}

/// A thread may take an interrupt's lock only once it has raised to that interrupt's
/// SynchronizeIrql, which is at least DISPATCH_LEVEL.
pub const fn interrupt_lock_irql_matches(synchronize_irql: u8, lane_irql: u8) -> bool {
    synchronize_irql >= 2 && lane_irql == synchronize_irql
}

/// Pick the IRQL byte's containing bank only after native code has authenticated one exact
/// physical lane. Provider workers cannot borrow the parked primary's IRQL state.
pub const fn select_hosted_cr8_bank(primary_shared: u64, channel_shared: u64,
    primary_authority: bool, provider_worker_authority: bool) -> Option<u64> {
    if primary_shared == 0 || channel_shared == 0 || primary_authority == provider_worker_authority {
        return None;
    }
    if primary_authority && channel_shared == primary_shared {
        Some(primary_shared)
    } else if provider_worker_authority && channel_shared != primary_shared {
        Some(channel_shared)
    } else {
        None
    }
}

/// Checked page extent of an isolated worker request arena and its optional argument bank.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedWorkerBankLayout {
    bank_offset: u64,
    bank_bytes: u64,
    arg_end: Option<u64>,
}

impl HostedWorkerBankLayout {
    pub const fn new(bank_offset: u64, bank_frames: u64, arg_offset: Option<u64>,
        arg_frames: u64, stride: u64) -> Option<Self> {
        if bank_offset & 0xfff != 0 || bank_frames == 0 { return None; }
        let Some(bank_bytes) = bank_frames.checked_mul(0x1000) else { return None; };
        let Some(bank_end) = bank_offset.checked_add(bank_bytes) else { return None; };
        if bank_end > stride { return None; }
        let arg_end = if let Some(arg_offset) = arg_offset {
            if arg_offset & 0xfff != 0 || arg_offset < bank_end || arg_frames == 0 {
                return None;
            }
            let Some(arg_bytes) = arg_frames.checked_mul(0x1000) else { return None; };
            let Some(end) = arg_offset.checked_add(arg_bytes) else { return None; };
            if end > stride { return None; }
            Some(end)
        } else { None };
        Some(Self { bank_offset, bank_bytes, arg_end })
    }

    pub const fn bank_bytes(self) -> u64 { self.bank_bytes }
    pub const fn bank_end(self) -> u64 { self.bank_offset + self.bank_bytes }
    pub const fn arg_end(self) -> Option<u64> { self.arg_end }
}

/// Physical channel identity of a hosted provider worker. A Reply cap slot is local to its
/// CNode; all resources must belong to the same live worker publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostedProviderWorkerIdentity {
    pub tcb: u64,
    pub reply_cnode: u64,
    pub reply: u64,
    pub shared_bank: u64,
    pub route_endpoint: u64,
    pub route_badge: u64,
    pub route_generation: u64,
}

impl HostedProviderWorkerIdentity {
    pub const fn new(
        tcb: u64,
        reply_cnode: u64,
        reply: u64,
        shared_bank: u64,
        route_endpoint: u64,
        route_badge: u64,
        route_generation: u64,
    ) -> Option<Self> {
        if tcb == 0 || reply_cnode == 0 || reply == 0 || shared_bank == 0 || route_endpoint == 0
            || route_badge == 0 || route_generation == 0 {
            return None;
        }
        Some(Self { tcb, reply_cnode, reply, shared_bank, route_endpoint, route_badge, route_generation })
    }
}

/// Select a reentrant worker only for the exact retained provider/dependent publication and a
/// distinct admitted channel. Callers must obtain both identities from live owned resources.
pub const fn select_hosted_provider_export_worker(
    expected_owner: HostedProviderObjectOwner,
    expected_publication: u64,
    live_owner: HostedProviderObjectOwner,
    live_publication: u64,
    primary: HostedProviderWorkerIdentity,
    worker: HostedProviderWorkerIdentity,
    worker_ready: bool,
) -> Option<HostedProviderWorkerIdentity> {
    if !worker_ready
        || expected_publication == 0
        || !expected_owner.pair_matches(
            live_owner.provider_domain_id,
            live_owner.provider_domain_cookie,
            live_owner.dependent_domain_id,
            live_owner.dependent_domain_cookie,
        )
        || expected_publication != live_publication
        || primary.tcb == worker.tcb
        || (primary.reply_cnode == worker.reply_cnode && primary.reply == worker.reply)
        || primary.shared_bank == worker.shared_bank
        // A generation belongs to one lane and may equal another lane's generation. The
        // ingress registry issues unique badges for route publications on its endpoint.
        || primary.route_badge == worker.route_badge
    {
        return None;
    }
    Some(worker)
}

#[cfg(test)]
mod reentry_tests {
    use super::hosted_provider_export_needs_worker;

    #[test]
    fn a_provider_library_that_never_publishes_a_device_stack_gets_a_worker_lane() {
        use super::hosted_provider_worker_admissible;
        // Boot 44510687412 attempt 2: worker preparation for ndis.sys refused with
        // STATUS_DEVICE_NOT_CONNECTED because the library's instance is never device-ready.
        assert!(hosted_provider_worker_admissible(false, true, true));
        assert!(!hosted_provider_worker_admissible(true, true, true));
        assert!(!hosted_provider_worker_admissible(false, false, true));
        assert!(!hosted_provider_worker_admissible(false, true, false));
    }

    #[test]
    fn a_reentrant_export_into_a_running_provider_uses_a_worker_lane() {
        // Boot 44463332736: E1000's MiniportInitialize called ndis.sys while ndis's primary
        // lane was running NdisIPnPStartDevice; the primary refused with reply-aliased BUSY
        // and the adapter context allocation failed (STATUS_INSUFFICIENT_RESOURCES).
        assert!(hosted_provider_export_needs_worker(false, false));
        assert!(!hosted_provider_export_needs_worker(false, true));
        assert!(hosted_provider_export_needs_worker(true, true));
    }

    #[test]
    fn a_kept_export_keeps_its_worker_entered_until_its_true_result() {
        use super::{hosted_provider_export_worker_phase as phase,
            HostedProviderExportPumpEnd as End, HostedProviderExportWorkerPhase as Phase};
        // The legacy pump reported an unfinished export as an incomplete receipt, which
        // fenced the worker as uncertain while the export was still running (#420).
        assert_eq!(phase(End::Returned { completed: false, status: 0xc000_00aeu32 as i32 }),
            Phase::Uncertain);
        assert_eq!(phase(End::Kept), Phase::Entered,
            "a kept export is still running: it is neither reusable nor uncertain");
        assert_eq!(phase(End::Returned { completed: true, status: 0 }), Phase::Ready);
        assert_eq!(phase(End::Returned { completed: true, status: 0xc000_0001u32 as i32 }),
            Phase::Uncertain);
    }
}
