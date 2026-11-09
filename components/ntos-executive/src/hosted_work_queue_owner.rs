//! Retained ownership of a provider work queue entry after its shared ring slot advances.
//!
//! This identity names the queue entry only. A suspended callback must separately retain
//! and authenticate its physical route, dispatch, TCB, Reply, and epoch before root resumes it.

use super::*;
use nt_component_suspension::HostedWorkQueueClaim;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct QueueEntryKey {
    domain_id: u64,
    domain_cookie: u64,
    head: u64,
    work_item: u64,
}

impl QueueEntryKey {
    pub(super) fn new(inst: DriverInstance, head: u64, work_item: u64) -> Self {
        Self {
            domain_id: inst.hosted_domain_id,
            domain_cookie: inst.hosted_domain_cookie,
            head,
            work_item,
        }
    }
}

#[derive(Clone, Copy)]
pub(super) struct QueueEntry {
    pub(super) kind: u64,
    pub(super) work_item: u64,
    pub(super) routine: u64,
    pub(super) arg0: u64,
    pub(super) arg1: u64,
}

struct Row {
    claim: HostedWorkQueueClaim<QueueEntryKey, QueueEntry>,
    ndis: Option<HostedProviderNdisWorkItemDispatch>,
}

static mut CLAIMS: Vec<Option<Row>> = Vec::new();

/// Reserve the claim before clearing the shared slot or entering any native callback.
pub(super) unsafe fn claim(index: usize, key: QueueEntryKey, entry: QueueEntry) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(CLAIMS);
    if rows.len() <= index {
        let additional = index + 1 - rows.len();
        if rows.try_reserve(additional).is_err() { return false; }
        rows.resize_with(index + 1, || None);
    }
    if rows[index].is_some() { return false; }
    rows[index] = Some(Row { claim: HostedWorkQueueClaim::dequeue(key, entry), ndis: None });
    true
}

pub(super) unsafe fn pending(index: usize) -> bool {
    (&*core::ptr::addr_of!(CLAIMS)).get(index).is_some_and(Option::is_some)
}

/// Return only copied callback arguments; the row keeps the physical queue claim.
pub(super) unsafe fn enter(index: usize, key: QueueEntryKey) -> Option<QueueEntry> {
    (&mut *core::ptr::addr_of_mut!(CLAIMS)).get_mut(index)?
        .as_mut()?.claim.enter(key).ok()
}

pub(super) unsafe fn record_ndis(
    index: usize, key: QueueEntryKey, dispatch: Option<HostedProviderNdisWorkItemDispatch>,
) -> bool {
    let Some(row) = (&mut *core::ptr::addr_of_mut!(CLAIMS)).get_mut(index)
        .and_then(Option::as_mut) else { return false; };
    if row.claim.retained_entry(key).is_err() || row.ndis.is_some() { return false; }
    row.ndis = dispatch;
    true
}

pub(super) unsafe fn acknowledge_return(index: usize, key: QueueEntryKey) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(CLAIMS);
    let Some(row) = rows.get_mut(index).and_then(Option::as_mut) else { return false; };
    if row.claim.acknowledge_return(key).is_err() { return false; }
    rows[index] = None;
    true
}

/// The shared slot was consumed, but the callback did not enter. A missing or mismatched
/// row stays retained; neither path may acknowledge a provider return that never occurred.
pub(super) unsafe fn abort_before_enter(index: usize, key: QueueEntryKey) -> bool {
    let rows = &mut *core::ptr::addr_of_mut!(CLAIMS);
    let Some(row) = rows.get_mut(index).and_then(Option::as_mut) else { return false; };
    if row.ndis.is_some() || row.claim.abort_before_enter(key).is_err() { return false; }
    rows[index] = None;
    true
}
