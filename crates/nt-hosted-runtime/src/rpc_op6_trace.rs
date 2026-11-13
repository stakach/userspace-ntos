//! Bounded request/response identity for the PnP validation RPC diagnostic.
//!
//! NPFS file IDs distinguish the two endpoints with their low bit. This diagnostic pairs one
//! outstanding validation request per pipe with the next response written to its opposite endpoint.
//! The response header call ID is not an identity: LiberNT emits 1 for each response. Pairing
//! records timing evidence only; it does not cache results or change pipe ownership.

#[derive(Clone, Copy)]
struct Pending {
    call_id: u32,
    started_ticks: u64,
}

#[derive(Clone, Copy)]
struct PipeSlot {
    request_fid: u64,
    pending: Option<Pending>,
}

pub struct RpcOp6ExchangeTracker<const N: usize> {
    pipes: [Option<PipeSlot>; N],
    requests: u64,
    completed: u64,
    overflow: u64,
    overlapping_requests: u64,
    orphan_responses: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RpcOp6TraceCounts {
    pub requests: u64,
    pub completed: u64,
    pub overflow: u64,
    pub overlapping_requests: u64,
    pub orphan_responses: u64,
}

impl<const N: usize> RpcOp6ExchangeTracker<N> {
    pub const fn new() -> Self {
        Self { pipes: [None; N], requests: 0, completed: 0, overflow: 0, overlapping_requests: 0, orphan_responses: 0 }
    }

    /// An overlap or a full tracker cannot replace an outstanding request.
    pub fn record_request(&mut self, request_fid: u64, call_id: u32, now_ticks: u64) -> bool {
        if request_fid == 0 {
            self.overflow = self.overflow.saturating_add(1);
            return false;
        }
        if let Some(pipe) = self.pipes.iter_mut().flatten().find(|pipe| pipe.request_fid == request_fid) {
            if pipe.pending.is_some() {
                self.overlapping_requests = self.overlapping_requests.saturating_add(1);
                return false;
            }
            pipe.pending = Some(Pending { call_id, started_ticks: now_ticks });
            self.requests = self.requests.saturating_add(1);
            return true;
        }
        let Some(slot) = self.pipes.iter_mut().find(|slot| slot.is_none()) else {
            self.overflow = self.overflow.saturating_add(1);
            return false;
        };
        *slot = Some(PipeSlot { request_fid, pending: Some(Pending { call_id, started_ticks: now_ticks }) });
        self.requests = self.requests.saturating_add(1);
        true
    }

    /// Return the captured request call ID and elapsed ticks for the next response on this pipe.
    /// Unrelated pipes are ignored; a response on a known pipe with no request is an orphan.
    pub fn complete_response(&mut self, response_fid: u64, now_ticks: u64) -> Option<(u32, u64)> {
        let Some(pipe) = self.pipes.iter_mut().flatten().find(|pipe| pipe.request_fid ^ 1 == response_fid) else {
            return None;
        };
        let Some(entry) = pipe.pending.take() else {
            self.orphan_responses = self.orphan_responses.saturating_add(1);
            return None;
        };
        self.completed = self.completed.saturating_add(1);
        Some((entry.call_id, now_ticks.saturating_sub(entry.started_ticks)))
    }

    pub fn counts(&self) -> RpcOp6TraceCounts {
        RpcOp6TraceCounts {
            requests: self.requests,
            completed: self.completed,
            overflow: self.overflow,
            overlapping_requests: self.overlapping_requests,
            orphan_responses: self.orphan_responses,
        }
    }
}

impl<const N: usize> Default for RpcOp6ExchangeTracker<N> {
    fn default() -> Self { Self::new() }
}
