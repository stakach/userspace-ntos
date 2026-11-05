//! Address and backing ownership for private hosted DMA graph members.
//!
//! A pointer-only provider release must never address a later graph, even if that graph uses
//! the same physical frame. This ledger only plans addresses and validates exact owners;
//! its native caller owns mapping, unmapping, and frame effects.

use alloc::vec::Vec;
use crate::HostedDomainIdentity;

const PAGE_BYTES: u64 = 0x1000;
const SLOT_BYTES: u64 = 0x100;
const SLOTS_PER_PAGE: u8 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AliasBacking {
    pub frame: u64,
    pub generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AliasGraph {
    pub domain: HostedDomainIdentity,
    pub request: u64,
    pub page: u64,
    pub slot: u8,
    pub map: u64,
    pub context: u64,
    pub list: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AliasError {
    Invalid,
    Exhausted,
    MissingBacking,
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GraphState { Reserved, Published, Retired, Uncertain }

struct Entry { graph: AliasGraph, state: GraphState }
#[derive(Clone, Copy)]
struct SlotReceipt { request: u64, state: GraphState }
struct Page {
    id: u64,
    base: u64,
    next_slot: u8,
    backing: Option<AliasBacking>,
    reclaiming: bool,
    uncertain: bool,
    slots: [Option<SlotReceipt>; SLOTS_PER_PAGE as usize],
}

pub struct AliasArena {
    domain: HostedDomainIdentity,
    first: u64,
    limit: u64,
    pages: Vec<Page>,
    // Only active or uncertain graphs need full rows. Exact retired pointer receipts remain in
    // their page slot, while compact ranges reject a late replay of an old request nonce.
    graphs: Vec<Entry>,
    retired_requests: Vec<(u64, u64)>,
}

impl AliasArena {
    pub fn new(domain: HostedDomainIdentity, first: u64, limit: u64) -> Result<Self, AliasError> {
        if domain.cookie == 0 || first == 0 || first & (PAGE_BYTES - 1) != 0
            || limit <= first || limit & (PAGE_BYTES - 1) != 0 {
            return Err(AliasError::Invalid);
        }
        Ok(Self { domain, first, limit, pages: Vec::new(), graphs: Vec::new(),
            retired_requests: Vec::new() })
    }

    /// Reserves authority before any native mapping effect. A repeated request returns the
    /// original slot, including when the provider reply was lost.
    pub fn reserve(&mut self, request: u64) -> Result<AliasGraph, AliasError> {
        if request == 0 { return Err(AliasError::Invalid); }
        if let Some(entry) = self.graphs.iter().find(|entry| entry.graph.request == request) {
            return match entry.state {
                GraphState::Reserved | GraphState::Published => Ok(entry.graph),
                GraphState::Retired => Err(AliasError::Invalid),
                GraphState::Uncertain => Err(AliasError::Uncertain),
            };
        }
        if self.retired_requests.iter().any(|&(first, last)| first <= request && request <= last) {
            return Err(AliasError::Invalid);
        }
        if self.pages.last().is_none_or(|page| page.next_slot == SLOTS_PER_PAGE
            || page.uncertain || page.reclaiming) {
            // Physical pages may be recycled, but pointer-only release authority means that
            // component VAs cannot be reused within this driver's generation.
            let base = self.first.checked_add(
                (self.pages.len() as u64).checked_mul(PAGE_BYTES)
                    .ok_or(AliasError::Exhausted)?
            ).ok_or(AliasError::Exhausted)?;
            if base.checked_add(PAGE_BYTES).is_none_or(|end| end > self.limit) {
                return Err(AliasError::Exhausted);
            }
            self.pages.try_reserve(1).map_err(|_| AliasError::Exhausted)?;
            self.pages.push(Page { id: self.pages.len() as u64 + 1, base, next_slot: 0,
                backing: None, reclaiming: false, uncertain: false,
                slots: [None; SLOTS_PER_PAGE as usize] });
        }
        self.graphs.try_reserve(1).map_err(|_| AliasError::Exhausted)?;
        let page = self.pages.last_mut().ok_or(AliasError::Invalid)?;
        let slot = page.next_slot;
        page.next_slot += 1;
        let map = page.base + u64::from(slot) * SLOT_BYTES;
        let graph = AliasGraph { domain: self.domain, request, page: page.id, slot,
            map, context: map + 0x40, list: map + 0x80 };
        page.slots[usize::from(slot)] = Some(SlotReceipt {
            request, state: GraphState::Reserved,
        });
        self.graphs.push(Entry { graph, state: GraphState::Reserved });
        Ok(graph)
    }

    pub fn bind_page(&mut self, graph: AliasGraph, backing: AliasBacking)
        -> Result<(), AliasError>
    {
        if backing.frame == 0 || backing.generation == 0 || !self.exact_graph(graph) {
            return Err(AliasError::Invalid);
        }
        // One physical generation cannot back two simultaneously published component pages.
        // A later generation may reuse the frame after exact unmap and reclamation.
        if self.pages.iter().any(|page| page.id != graph.page
            && page.backing == Some(backing)) {
            return Err(AliasError::Invalid);
        }
        let page = self.pages.iter_mut().find(|page| page.id == graph.page)
            .ok_or(AliasError::Invalid)?;
        if page.uncertain || page.reclaiming { return Err(AliasError::Uncertain); }
        match page.backing {
            Some(saved) if saved == backing => Ok(()),
            Some(_) => Err(AliasError::Invalid),
            None => { page.backing = Some(backing); Ok(()) }
        }
    }

    pub fn publish(&mut self, graph: AliasGraph) -> Result<(), AliasError> {
        let page = self.pages.iter().find(|page| page.id == graph.page)
            .ok_or(AliasError::Invalid)?;
        if page.backing.is_none() { return Err(AliasError::MissingBacking); }
        if page.uncertain { return Err(AliasError::Uncertain); }
        let entry = self.graphs.iter_mut().find(|entry| entry.graph == graph)
            .ok_or(AliasError::Invalid)?;
        match entry.state {
            GraphState::Reserved | GraphState::Published => {
                entry.state = GraphState::Published;
                self.pages[graph.page as usize - 1].slots[usize::from(graph.slot)]
                    .as_mut().ok_or(AliasError::Invalid)?.state = GraphState::Published;
                Ok(())
            }
            GraphState::Retired => Err(AliasError::Invalid),
            GraphState::Uncertain => Err(AliasError::Uncertain),
        }
    }

    /// Cancel a slot for which the native caller proved no frame or cap effect occurred.
    /// The slot and request remain retired so an old nonce cannot later name a new graph.
    pub fn cancel_unpublished(&mut self, graph: AliasGraph) -> Result<(), AliasError> {
        if self.slot_receipt(graph).is_none() { return Err(AliasError::Invalid); }
        let index = self.graphs.iter().position(|entry| entry.graph == graph
            && entry.state == GraphState::Reserved).ok_or(AliasError::Invalid)?;
        let page = self.pages.get(graph.page as usize - 1).ok_or(AliasError::Invalid)?;
        if page.uncertain || page.reclaiming { return Err(AliasError::Uncertain); }
        self.retired_requests.try_reserve(1).map_err(|_| AliasError::Exhausted)?;
        self.pages[graph.page as usize - 1].slots[usize::from(graph.slot)]
            .as_mut().unwrap().state = GraphState::Retired;
        self.graphs.swap_remove(index);
        self.record_retired_request(graph.request);
        Ok(())
    }

    pub fn is_reserved(&self, graph: AliasGraph) -> bool {
        self.graphs.iter().any(|entry| entry.graph == graph
            && entry.state == GraphState::Reserved)
    }

    pub fn has_uncertain(&self) -> bool {
        self.pages.iter().any(|page| page.uncertain)
            || self.graphs.iter().any(|entry| entry.state == GraphState::Uncertain)
    }

    /// A native mapping effect with an unknown result retains the frame, cap, address, and
    /// request identity. No later graph may enter this page.
    pub fn quarantine(&mut self, graph: AliasGraph) -> Result<(), AliasError> {
        let page = self.pages.get_mut(graph.page.checked_sub(1).ok_or(AliasError::Invalid)? as usize)
            .ok_or(AliasError::Invalid)?;
        let entry = self.graphs.iter_mut().find(|entry| entry.graph == graph)
            .ok_or(AliasError::Invalid)?;
        if entry.state != GraphState::Reserved && entry.state != GraphState::Published {
            return Err(AliasError::Invalid);
        }
        entry.state = GraphState::Uncertain;
        page.uncertain = true;
        page.slots[usize::from(graph.slot)].as_mut()
            .ok_or(AliasError::Invalid)?.state = GraphState::Uncertain;
        Ok(())
    }

    pub fn backing(&self, graph: AliasGraph) -> Option<AliasBacking> {
        self.slot_receipt(graph)?;
        self.pages.get(graph.page.checked_sub(1)? as usize)?.backing
    }

    /// Resolve a pointer-only SG list through its unique page and slot. The returned request
    /// identity is captured in the slot receipt; provider-writable bytes are never consulted.
    pub fn graph_for_list(&self, list: u64) -> Option<AliasGraph> {
        let offset = list.checked_sub(self.first)?.checked_sub(0x80)?;
        let page_index = offset / PAGE_BYTES;
        let within_page = offset % PAGE_BYTES;
        if within_page % SLOT_BYTES != 0 { return None; }
        let slot = (within_page / SLOT_BYTES) as u8;
        if slot >= SLOTS_PER_PAGE { return None; }
        let page = self.pages.get(page_index as usize)?;
        let receipt = page.slots[usize::from(slot)]?;
        let map = page.base + u64::from(slot) * SLOT_BYTES;
        Some(AliasGraph { domain: self.domain, request: receipt.request,
            page: page.id, slot, map, context: map + 0x40, list: map + 0x80 })
    }

    /// Driver teardown may seal a partially filled page after all its published slots retire.
    pub fn seal_page(&mut self, page_id: u64) -> Result<Option<AliasBacking>, AliasError> {
        let page = self.pages.get_mut(page_id.checked_sub(1).ok_or(AliasError::Invalid)? as usize)
            .ok_or(AliasError::Invalid)?;
        if page.id != page_id || page.uncertain { return Err(AliasError::Uncertain); }
        if page.reclaiming { return Ok(page.backing); }
        if page.slots.iter().any(|slot| slot.is_some_and(|receipt|
            receipt.state != GraphState::Retired)) {
            return Err(AliasError::Invalid);
        }
        page.next_slot = SLOTS_PER_PAGE;
        if page.backing.is_some() { page.reclaiming = true; }
        Ok(page.backing)
    }

    pub fn retire(&mut self, graph: AliasGraph, exact_unmap: bool)
        -> Result<Option<AliasBacking>, AliasError>
    {
        let Some(index) = self.graphs.iter().position(|entry| entry.graph == graph) else {
            return match self.slot_receipt(graph) {
                Some(SlotReceipt { state: GraphState::Retired, .. }) => {
                    let page = self.pages.get(graph.page as usize - 1)
                        .ok_or(AliasError::Invalid)?;
                    if page.uncertain { return Err(AliasError::Uncertain); }
                    // A completed graph still owns a retryable page reclaim until the exact
                    // native frame transfer is confirmed. Any retired slot on that page can
                    // drive the same retained cleanup without reviving pointer authority.
                    Ok(if exact_unmap && page.reclaiming { page.backing } else { None })
                }
                Some(SlotReceipt { state: GraphState::Uncertain, .. }) => Err(AliasError::Uncertain),
                _ => Err(AliasError::Invalid),
            };
        };
        // Reserve the replay tombstone before any state change. Retired nonces coalesce into
        // ranges, so sustained ordered I/O does not retain one heap row per completed graph.
        if exact_unmap && self.graphs[index].state == GraphState::Published {
            self.retired_requests.try_reserve(1).map_err(|_| AliasError::Exhausted)?;
        }
        let entry = &mut self.graphs[index];
        match entry.state {
            GraphState::Published if exact_unmap => entry.state = GraphState::Retired,
            GraphState::Published => {
                entry.state = GraphState::Uncertain;
                let page = self.pages.iter_mut().find(|page| page.id == graph.page).unwrap();
                page.uncertain = true;
                page.slots[usize::from(graph.slot)].as_mut().unwrap().state = GraphState::Uncertain;
                return Err(AliasError::Uncertain);
            }
            GraphState::Retired => return Ok(None),
            GraphState::Reserved => return Err(AliasError::Invalid),
            GraphState::Uncertain => return Err(AliasError::Uncertain),
        }
        self.pages[graph.page as usize - 1].slots[usize::from(graph.slot)]
            .as_mut().unwrap().state = GraphState::Retired;
        self.graphs.swap_remove(index);
        self.record_retired_request(graph.request);
        let page = self.pages.iter_mut().find(|page| page.id == graph.page).unwrap();
        if page.uncertain || page.reclaiming || page.next_slot < SLOTS_PER_PAGE
            || page.slots.iter().any(|slot| slot.is_some_and(|receipt|
                receipt.state != GraphState::Retired)) {
            return Ok(None);
        }
        page.reclaiming = true;
        Ok(page.backing)
    }

    pub fn confirm_reclaim(&mut self, page_id: u64, backing: AliasBacking, exact: bool)
        -> Result<(), AliasError>
    {
        let page = self.pages.iter_mut().find(|page| page.id == page_id)
            .ok_or(AliasError::Invalid)?;
        if !page.reclaiming || page.backing != Some(backing) || page.uncertain {
            return Err(AliasError::Invalid);
        }
        if !exact { page.uncertain = true; return Err(AliasError::Uncertain); }
        page.backing = None;
        page.reclaiming = false;
        Ok(())
    }

    pub fn is_live(&self, graph: AliasGraph) -> bool {
        self.graphs.iter().any(|entry| entry.graph == graph
            && entry.state == GraphState::Published)
    }

    pub fn backed_pages(&self) -> usize {
        self.pages.iter().filter(|page| page.backing.is_some()).count()
    }

    fn exact_graph(&self, graph: AliasGraph) -> bool {
        graph.domain == self.domain && self.graphs.iter().any(|entry| entry.graph == graph
            && entry.state == GraphState::Reserved)
    }

    fn slot_receipt(&self, graph: AliasGraph) -> Option<SlotReceipt> {
        if graph.domain != self.domain || graph.slot >= SLOTS_PER_PAGE { return None; }
        let page = self.pages.get(graph.page.checked_sub(1)? as usize)?;
        if graph.map != page.base + u64::from(graph.slot) * SLOT_BYTES
            || graph.context != graph.map + 0x40 || graph.list != graph.map + 0x80 {
            return None;
        }
        page.slots[usize::from(graph.slot)]
            .filter(|receipt| receipt.request == graph.request)
    }

    fn record_retired_request(&mut self, request: u64) {
        let mut index = 0;
        while index < self.retired_requests.len()
            && self.retired_requests[index].1.saturating_add(1) < request {
            index += 1;
        }
        let mut first = request;
        let mut last = request;
        while index < self.retired_requests.len()
            && self.retired_requests[index].0 <= last.saturating_add(1) {
            let (other_first, other_last) = self.retired_requests.remove(index);
            first = first.min(other_first);
            last = last.max(other_last);
        }
        self.retired_requests.insert(index, (first, last));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HostedDomainId;

    fn arena() -> AliasArena {
        AliasArena::new(HostedDomainIdentity { domain_id: HostedDomainId(7), cookie: 11 },
            0x1_0000_0000, 0x1_0002_0000).unwrap()
    }

    #[test]
    fn hosted_dma_alias_recycled_frame_never_reuses_pointer_only_list_address() {
        let mut arena = arena();
        let first_backing = AliasBacking { frame: 9, generation: 1 };
        let mut old = None;
        for request in 1..=SLOTS_PER_PAGE as u64 {
            let graph = arena.reserve(request).unwrap();
            arena.bind_page(graph, first_backing).unwrap();
            arena.publish(graph).unwrap();
            old.get_or_insert(graph);
            let reclaim = arena.retire(graph, true).unwrap();
            if request == SLOTS_PER_PAGE as u64 { assert_eq!(reclaim, Some(first_backing)); }
        }
        let old = old.unwrap();
        arena.confirm_reclaim(old.page, first_backing, true).unwrap();
        let replacement = arena.reserve(17).unwrap();
        arena.bind_page(replacement, AliasBacking { frame: 9, generation: 2 }).unwrap();
        arena.publish(replacement).unwrap();
        assert_ne!(old.list, replacement.list);
        assert_eq!(arena.retire(old, true), Ok(None));
        assert!(arena.is_live(replacement));
        assert_eq!(arena.backed_pages(), 1);
    }

    #[test]
    fn hosted_dma_alias_uncertain_unmap_never_reclaims_backing() {
        let mut arena = arena();
        let graph = arena.reserve(1).unwrap();
        let backing = AliasBacking { frame: 10, generation: 1 };
        arena.bind_page(graph, backing).unwrap();
        arena.publish(graph).unwrap();
        assert_eq!(arena.retire(graph, false), Err(AliasError::Uncertain));
        assert_eq!(arena.retire(graph, true), Err(AliasError::Uncertain));
        assert_eq!(arena.backed_pages(), 1);
    }

    #[test]
    fn hosted_dma_alias_uncertain_page_never_accepts_another_graph() {
        let mut arena = arena();
        let old = arena.reserve(1).unwrap();
        arena.bind_page(old, AliasBacking { frame: 10, generation: 1 }).unwrap();
        arena.publish(old).unwrap();
        assert_eq!(arena.retire(old, false), Err(AliasError::Uncertain));
        let next = arena.reserve(2).unwrap();
        assert_ne!(old.page, next.page);
        assert_ne!(old.list, next.list);
    }

    #[test]
    fn hosted_dma_alias_one_backing_cannot_name_two_live_pages() {
        let mut arena = arena();
        let backing = AliasBacking { frame: 10, generation: 1 };
        for request in 1..=SLOTS_PER_PAGE as u64 {
            let graph = arena.reserve(request).unwrap();
            arena.bind_page(graph, backing).unwrap();
            arena.publish(graph).unwrap();
        }
        let next_page = arena.reserve(17).unwrap();
        assert_eq!(arena.bind_page(next_page, backing), Err(AliasError::Invalid));
    }

    #[test]
    fn hosted_dma_alias_retired_requests_do_not_grow_graph_rows() {
        let mut arena = arena();
        let backing = AliasBacking { frame: 10, generation: 1 };
        let mut first = None;
        for request in 1..=SLOTS_PER_PAGE as u64 {
            let graph = arena.reserve(request).unwrap();
            arena.bind_page(graph, backing).unwrap();
            arena.publish(graph).unwrap();
            first.get_or_insert(graph);
            arena.retire(graph, true).unwrap();
        }
        let first = first.unwrap();
        arena.confirm_reclaim(first.page, backing, true).unwrap();
        assert_eq!(arena.graphs.len(), 0);
        assert_eq!(arena.reserve(1), Err(AliasError::Invalid));
    }

    #[test]
    fn hosted_dma_alias_out_of_order_retirement_coalesces_replay_receipts() {
        let mut arena = arena();
        let backing = AliasBacking { frame: 10, generation: 1 };
        let mut graphs = Vec::new();
        for request in 1..=3 {
            let graph = arena.reserve(request).unwrap();
            arena.bind_page(graph, backing).unwrap();
            arena.publish(graph).unwrap();
            graphs.push(graph);
        }
        for index in [2, 0, 1] { arena.retire(graphs[index], true).unwrap(); }
        assert_eq!(arena.retired_requests, [(1, 3)]);
        assert_eq!(arena.reserve(2), Err(AliasError::Invalid));
        let next = arena.reserve(4).unwrap();
        assert_eq!(next.slot, 3);
    }

    #[test]
    fn hosted_dma_alias_forged_slot_cannot_retire_live_graph() {
        let mut arena = arena();
        let graph = arena.reserve(1).unwrap();
        arena.bind_page(graph, AliasBacking { frame: 10, generation: 1 }).unwrap();
        arena.publish(graph).unwrap();
        let forged = AliasGraph { list: graph.list + SLOT_BYTES, ..graph };
        assert_eq!(arena.retire(forged, true), Err(AliasError::Invalid));
        assert!(arena.is_live(graph));
    }

    #[test]
    fn hosted_dma_alias_exact_retirement_retries_pending_page_reclaim() {
        let mut arena = arena();
        let backing = AliasBacking { frame: 10, generation: 1 };
        let mut last = None;
        for request in 1..=SLOTS_PER_PAGE as u64 {
            let graph = arena.reserve(request).unwrap();
            arena.bind_page(graph, backing).unwrap();
            arena.publish(graph).unwrap();
            arena.retire(graph, true).unwrap();
            last = Some(graph);
        }
        let last = last.unwrap();
        assert_eq!(arena.retire(last, true), Ok(Some(backing)),
            "a confirmed Put retry must finish retained frame recycle");
        arena.confirm_reclaim(last.page, backing, true).unwrap();
        assert_eq!(arena.retire(last, true), Ok(None));
    }

    #[test]
    fn hosted_dma_alias_definite_acquisition_failure_can_retire_unpublished_slot() {
        {
            let mut arena = arena();
            let graph = arena.reserve(1).unwrap();
            assert_eq!(arena.seal_page(graph.page), Err(AliasError::Invalid));
            arena.cancel_unpublished(graph).unwrap();
            assert_eq!(arena.seal_page(graph.page), Ok(None));
            assert_eq!(arena.reserve(graph.request), Err(AliasError::Invalid));
        }

        // A later request may successfully back the same page before teardown. The earlier
        // no-effect slot still needs its own exact retirement receipt.
        let mut arena = arena();
        let failed = arena.reserve(1).unwrap();
        let later = arena.reserve(2).unwrap();
        let backing = AliasBacking { frame: 9, generation: 1 };
        arena.bind_page(later, backing).unwrap();
        arena.publish(later).unwrap();
        arena.retire(later, true).unwrap();
        assert_eq!(arena.seal_page(failed.page), Err(AliasError::Invalid));
        arena.cancel_unpublished(failed).unwrap();
        assert_eq!(arena.seal_page(failed.page), Ok(Some(backing)));
    }
}
