//! Owned SG graphs use nonreused component VAs and recyclable page backing. The allocation
//! catalog lock serializes request, mapping, and pointer-only retirement authority.
use super::*;
use nt_io_manager::hosted_dma_alias::{AliasArena, AliasBacking, AliasError, AliasGraph};

const BASE: u64 = 0x0000_0106_0000_0000;
const LIMIT: u64 = BASE + 0x1000_0000; // 256 MiB of virtual slots per isolated driver.
const PAGE: u64 = 0x1000;
const SLOT: u64 = 0x100;
const SG_BYTES: u64 = 0x28;

pub(crate) fn contains(address: u64) -> bool { (BASE..LIMIT).contains(&address) }

/// Native cap effects mutate this retained row before each fallible syscall.
pub(crate) struct NativePage {
    pub component_va: u64,
    pub pml4: u64,
    pub domain: HostedDomainIdentity,
    pub owner: u16,
    pub frame: u64,
    pub generation: u64,
    pub map_cap: u64,
    pub mapped: bool,
    pub recycled: bool,
    pub uncertain: bool,
    pub pt_pending: bool,
    pub leases: [u64; 16],
}

struct Mapping {
    id: DmaPrivateMappingId,
    logical: u64,
    backing: u64,
    length: u64,
    released: bool,
}

struct Graph {
    lease_id: u64,
    request_id: u64,
    identity: AliasGraph,
    mappings: Vec<Mapping>,
    map_released: bool,
}

struct Arena {
    instance: DriverInstance,
    domain: HostedDomainIdentity,
    addresses: AliasArena,
    pages: Vec<Option<NativePage>>,
    graphs: Vec<Graph>,
}

static mut ARENAS: Vec<Arena> = Vec::new();
fn arenas() -> &'static mut Vec<Arena> { unsafe { &mut *core::ptr::addr_of_mut!(ARENAS) } }

fn status(error: AliasError) -> nt_status::NtStatus {
    match error {
        AliasError::Invalid => nt_status::NtStatus::INVALID_HANDLE,
        AliasError::Exhausted | AliasError::MissingBacking =>
            nt_status::NtStatus::INSUFFICIENT_RESOURCES,
        AliasError::Uncertain => nt_status::NtStatus::DEVICE_BUSY,
    }
}

fn arena_index(inst: DriverInstance, domain: HostedDomainIdentity) -> Option<usize> {
    arenas().iter().position(|row| row.domain == domain && same_arena(row.instance, inst))
}

fn ensure_arena(inst: DriverInstance, domain: HostedDomainIdentity)
    -> Result<usize, nt_status::NtStatus>
{
    if let Some(index) = arena_index(inst, domain) { return Ok(index); }
    if arenas().iter().any(|row| row.domain == domain) {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    arenas().try_reserve(1).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let addresses = AliasArena::new(domain, BASE, LIMIT).map_err(status)?;
    arenas().push(Arena { instance: inst, domain, addresses,
        pages: Vec::new(), graphs: Vec::new() });
    Ok(arenas().len() - 1)
}

pub(super) fn has_arena(inst: DriverInstance) -> bool {
    arenas().iter().any(|row| same_arena(row.instance, inst))
}

/// Readiness admits exact retained cleanup but never an outstanding published graph or an
/// uncertain cap effect. Reserved slots from a definite acquisition refusal are cancelled by
/// drain under the same catalog lock; they never published a component pointer.
pub(super) fn has_pending_effects(inst: DriverInstance) -> bool {
    arenas().iter().any(|row| same_arena(row.instance, inst)
        && (!row.graphs.is_empty() || row.addresses.has_uncertain()
            || row.pages.iter().flatten().any(|page| page.uncertain)))
}

pub(super) unsafe fn provision(inst: DriverInstance, lease_id: u64, request_id: u64)
    -> Result<(u64, u64, u64), nt_status::NtStatus>
{
    if lease_id == 0 || request_id == 0 { return Err(nt_status::NtStatus::INVALID_PARAMETER); }
    let _durable = crate::allocator::enter_durable();
    let _catalog = lock();
    let domain = validate_arena(inst)?;
    let index = ensure_arena(inst, domain)?;
    let row = &mut arenas()[index];
    if let Some(saved) = row.graphs.iter().find(|saved| saved.request_id == request_id) {
        if saved.lease_id != lease_id || saved.map_released
            || !row.addresses.is_live(saved.identity) {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        let graph = saved.identity;
        return Ok((graph.map, graph.context, graph.list));
    }
    row.graphs.try_reserve(1).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    row.pages.try_reserve(1).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let graph = row.addresses.reserve(request_id).map_err(status)?;
    let page_index = graph.page as usize - 1;
    if page_index == row.pages.len() {
        row.pages.push(None);
    }
    if row.pages[page_index].is_none() {
        let base = graph.map & !(PAGE - 1);
        let page = match crate::driver_launch::acquire_dma_alias_page(inst, domain, base) {
            Ok(page) => page,
            // No frame was handed to this arena. FrameAcquisition retains any unfinished
            // internal acquisition itself; this unpublished slot can retry or be cancelled
            // during teardown without replaying a native map or reusing a visible pointer.
            Err(error) => return Err(error),
        };
        let backing = AliasBacking { frame: page.frame, generation: page.generation };
        row.pages[page_index] = Some(page);
        if let Err(error) = row.addresses.bind_page(graph, backing) {
            // Acquisition has already handed us a live root cap. Keep it with the exact
            // reserved slot even if the pure receipt unexpectedly rejects this backing.
            row.pages[page_index].as_mut().unwrap().uncertain = true;
            let _ = row.addresses.quarantine(graph);
            return Err(status(error));
        }
        let page = row.pages[page_index].as_mut().unwrap();
        if let Err(error) = crate::driver_launch::map_dma_alias_page(page) {
            let _ = row.addresses.quarantine(graph);
            page.uncertain = true;
            return Err(error);
        }
    }
    let page = row.pages[page_index].as_mut().ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if page.uncertain || !page.mapped || page.frame == 0
        || row.addresses.backing(graph) != Some(AliasBacking {
            frame: page.frame, generation: page.generation,
        }) {
        let _ = row.addresses.quarantine(graph);
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    page.leases[usize::from(graph.slot)] = lease_id;
    if let Err(error) = row.addresses.publish(graph) {
        page.uncertain = true;
        let _ = row.addresses.quarantine(graph);
        return Err(status(error));
    }
    row.graphs.push(Graph { lease_id, request_id, identity: graph,
        mappings: Vec::new(), map_released: false });
    Ok((graph.map, graph.context, graph.list))
}

pub(super) unsafe fn record_mapping(
    inst: DriverInstance, lease_id: u64, map: u64, logical: u64,
    backing: u64, length: u64, kind: DmaPrivateMappingKind,
    register: impl FnOnce() -> Result<DmaPrivateMappingId, nt_status::NtStatus>,
) -> Result<DmaPrivateMappingId, nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let _catalog = lock();
    let domain = validate_arena(inst)?;
    let index = arena_index(inst, domain).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let row = &mut arenas()[index];
    let graph_index = row.graphs.iter().position(|graph| graph.lease_id == lease_id
        && graph.identity.map == map && !graph.map_released)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if logical == 0 || backing == 0 || length == 0
        || !row.addresses.is_live(row.graphs[graph_index].identity) {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let exact = |mapping: &Mapping| !mapping.released && mapping.id.kind() == kind
        && mapping.logical == logical && mapping.backing == backing
        && mapping.length == length;
    if let Some(saved) = row.graphs[graph_index].mappings.iter().find(|saved| exact(saved)) {
        return Ok(saved.id);
    }
    if row.graphs.iter().enumerate().any(|(other_index, graph)|
        other_index != graph_index && graph.mappings.iter().any(|mapping| exact(mapping))) {
        return Err(nt_status::NtStatus::OBJECT_NAME_COLLISION);
    }
    let graph = &mut row.graphs[graph_index];
    graph.mappings.try_reserve(1).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let id = register()?;
    if id.kind() != kind || graph.mappings.iter().any(|mapping| mapping.id == id) {
        return Err(nt_status::NtStatus::OBJECT_NAME_COLLISION);
    }
    graph.mappings.push(Mapping { id, logical, backing, length, released: false });
    Ok(id)
}

pub(super) unsafe fn mapping_receipt(
    inst: DriverInstance, map: u64, logical: u64, backing: u64, length: u64,
    kind: DmaPrivateMappingKind,
) -> Option<(u64, DmaPrivateMappingId)> {
    let _catalog = lock();
    let domain = validate_arena(inst).ok()?;
    let row = &arenas()[arena_index(inst, domain)?];
    let graph = row.graphs.iter().find(|graph| graph.identity.map == map
        && !graph.map_released && row.addresses.is_live(graph.identity))?;
    let mapping = graph.mappings.iter().find(|mapping| !mapping.released
        && mapping.id.kind() == kind && mapping.logical == logical
        && mapping.backing == backing && mapping.length == length)?;
    Some((graph.lease_id, mapping.id))
}

fn release_mappings(graph: &mut Graph,
    release: &mut impl FnMut(DmaPrivateMappingId) -> Result<(), nt_status::NtStatus>)
    -> Result<(), nt_status::NtStatus>
{
    for mapping in &mut graph.mappings {
        if !mapping.released {
            release(mapping.id)?;
            mapping.released = true;
        }
    }
    graph.map_released = true;
    Ok(())
}

unsafe fn finish_page(row: &mut Arena, graph: AliasGraph, backing: AliasBacking)
    -> Result<(), nt_status::NtStatus>
{
    {
        let page = row.pages.get_mut(graph.page as usize - 1)
            .and_then(Option::as_mut).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
        if page.frame != backing.frame || page.generation != backing.generation {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        crate::driver_launch::release_dma_alias_page(page)?;
    }
    row.addresses.confirm_reclaim(graph.page, backing, true).map_err(status)?;
    let base = graph.map & !0x1f_ffff;
    let pt_end_page = ((graph.page - 1) / 512 + 1) * 512;
    if row.pages.len() as u64 >= pt_end_page
        && row.pages.iter().flatten().all(|page| page.component_va & !0x1f_ffff != base
        || page.frame == 0) {
        finish_pt(row, graph)?;
    }
    Ok(())
}

unsafe fn finish_pt(row: &mut Arena, graph: AliasGraph)
    -> Result<(), nt_status::NtStatus>
{
    let page = row.pages.get_mut(graph.page as usize - 1)
        .and_then(Option::as_mut).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    page.pt_pending = true;
    crate::driver_launch::retire_dma_alias_pt_if_empty(
        row.domain, row.instance.pml4, graph.map,
    )?;
    page.pt_pending = false;
    Ok(())
}

unsafe fn retire_index(row: &mut Arena, index: usize, whole_graph: bool,
    release: &mut impl FnMut(DmaPrivateMappingId) -> Result<(), nt_status::NtStatus>)
    -> Result<(), nt_status::NtStatus>
{
    release_mappings(&mut row.graphs[index], release)?;
    if !whole_graph { return Ok(()); }
    let identity = row.graphs[index].identity;
    let backing = row.addresses.retire(identity, true).map_err(status)?;
    row.graphs.swap_remove(index);
    if let Some(backing) = backing { finish_page(row, identity, backing)?; }
    Ok(())
}

pub(super) unsafe fn retire(inst: DriverInstance, lease_id: u64, address: u64,
    whole_graph: bool,
    mut release: impl FnMut(DmaPrivateMappingId) -> Result<(), nt_status::NtStatus>,
) -> Result<(), nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let _catalog = lock();
    let domain = validate_arena(inst)?;
    let index = arena_index(inst, domain).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let row = &mut arenas()[index];
    let position = row.graphs.iter().position(|graph| graph.lease_id == lease_id
        && if whole_graph { graph.identity.list == address }
           else { graph.identity.map == address });
    if let Some(position) = position {
        return retire_index(row, position, whole_graph, &mut release);
    }
    if !whole_graph { return Err(nt_status::NtStatus::INVALID_HANDLE); }
    let graph = row.addresses.graph_for_list(address)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let page = row.pages.get(graph.page as usize - 1)
        .and_then(Option::as_ref).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if page.leases[usize::from(graph.slot)] != lease_id {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let pt_pending = page.pt_pending;
    if let Some(backing) = row.addresses.retire(graph, true).map_err(status)? {
        finish_page(row, graph, backing)?;
    } else if pt_pending {
        finish_pt(row, graph)?;
    }
    Ok(())
}

pub(super) unsafe fn sg_members(inst: DriverInstance, lease_id: u64, list: u64)
    -> Result<(u64, u64), nt_status::NtStatus>
{
    let _catalog = lock();
    let domain = validate_arena(inst)?;
    let row = &arenas()[arena_index(inst, domain).ok_or(nt_status::NtStatus::INVALID_HANDLE)?];
    let graph = row.graphs.iter().find(|graph| graph.lease_id == lease_id
        && graph.identity.list == list && row.addresses.is_live(graph.identity))
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    Ok((graph.identity.map, graph.identity.context))
}

pub(super) unsafe fn copy_list(inst: DriverInstance, list: u64, destination: u64)
    -> Result<(), nt_status::NtStatus>
{
    let _catalog = lock();
    let domain = validate_arena(inst)?;
    let row = &arenas()[arena_index(inst, domain).ok_or(nt_status::NtStatus::INVALID_HANDLE)?];
    let graph = row.graphs.iter().find(|graph| graph.identity.list == list
        && row.addresses.is_live(graph.identity))
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let page = row.pages.get(graph.identity.page as usize - 1)
        .and_then(Option::as_ref).ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if page.uncertain || !page.mapped || page.frame == 0 {
        return Err(nt_status::NtStatus::DEVICE_BUSY);
    }
    crate::driver_launch::copy_dma_alias_list(page, u64::from(graph.identity.slot) * SLOT + 0x80,
        destination, SG_BYTES)
}

pub(super) unsafe fn retire_lease(inst: DriverInstance, lease_id: u64,
    mut release: impl FnMut(DmaPrivateMappingId) -> Result<(), nt_status::NtStatus>)
    -> Result<(), nt_status::NtStatus>
{
    let _durable = crate::allocator::enter_durable();
    let _catalog = lock();
    let domain = validate_arena(inst)?;
    let Some(index) = arena_index(inst, domain) else { return Ok(()); };
    let row = &mut arenas()[index];
    while let Some(position) = row.graphs.iter().position(|graph| graph.lease_id == lease_id) {
        retire_index(row, position, true, &mut release)?;
    }
    Ok(())
}

pub(super) unsafe fn drain(inst: DriverInstance) -> Result<(), nt_status::NtStatus> {
    let _catalog = lock();
    let domain = validate_arena(inst)?;
    let Some(index) = arena_index(inst, domain) else { return Ok(()); };
    let row = &mut arenas()[index];
    if !row.graphs.is_empty() { return Err(nt_status::NtStatus::DEVICE_BUSY); }
    for page_index in 0..row.pages.len() {
        let page_id = page_index as u64 + 1;
        if row.pages[page_index].as_ref().is_some_and(|page| page.uncertain) {
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
        for slot in 0..16u64 {
            let list = BASE + page_index as u64 * PAGE + slot * SLOT + 0x80;
            if let Some(graph) = row.addresses.graph_for_list(list) {
                if row.addresses.is_reserved(graph) {
                    row.addresses.cancel_unpublished(graph).map_err(status)?;
                }
            }
        }
        let backing = row.addresses.seal_page(page_id).map_err(status)?;
        if let Some(backing) = backing {
            let graph = row.addresses.graph_for_list(BASE + page_index as u64 * PAGE + 0x80)
                .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
            finish_page(row, graph, backing)?;
        }
    }
    for page_index in (0..row.pages.len()).step_by(512) {
        let end = row.pages.len().min(page_index + 512);
        if row.pages[page_index..end]
            .iter().flatten().any(|page| page.frame != 0) {
            return Err(nt_status::NtStatus::DEVICE_BUSY);
        }
        let Some(first_page) = row.pages[page_index..end].iter()
            .position(Option::is_some).map(|offset| page_index + offset) else {
            // Every acquisition in this group was definitively refused before a frame or
            // paging effect could enter a native row.
            continue;
        };
        let page = row.pages[first_page].as_mut().unwrap();
        page.pt_pending = true;
        crate::driver_launch::retire_dma_alias_pt_if_empty(
            row.domain, row.instance.pml4, BASE + page_index as u64 * PAGE,
        )?;
        page.pt_pending = false;
    }
    arenas().swap_remove(index);
    Ok(())
}
