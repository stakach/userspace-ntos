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
