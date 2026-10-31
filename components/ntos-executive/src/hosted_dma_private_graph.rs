//! Exact physical ownership of hosted map-register and scatter/gather private storage.
//! The enclosing allocation catalog lock serializes every row and tombstone transition.
use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Kind { Map, ScatterGatherOwned, ScatterGatherBorrowed }

struct Mapping { id: u64, logical: u64, backing: u64, length: u64, released: bool }
struct Graph {
    instance: DriverInstance,
    domain: HostedDomainIdentity,
    lease_id: u64,
    request_id: u64,
    kind: Kind,
    map: Option<SourcePoolAllocationIdentity>,
    context: Option<SourcePoolAllocationIdentity>,
    list: Option<SourcePoolAllocationIdentity>,
    borrowed_list: Option<SourcePoolAllocationIdentity>,
    borrowed_address: u64,
    mappings: Vec<Mapping>,
    map_released: bool,
    map_freed: bool,
    context_freed: bool,
    list_freed: bool,
    published: bool,
    abandoned: bool,
}
struct Tombstone {
    instance: DriverInstance,
    physical: Option<SourcePoolAllocationIdentity>,
    address: u64,
    retire_receipt: Option<(u64, bool)>,
}
static mut GRAPHS: Vec<Graph> = Vec::new();
static mut TOMBSTONES: Vec<Tombstone> = Vec::new();
fn graphs() -> &'static mut Vec<Graph> { unsafe { &mut *core::ptr::addr_of_mut!(GRAPHS) } }
fn tombstones() -> &'static mut Vec<Tombstone> { unsafe { &mut *core::ptr::addr_of_mut!(TOMBSTONES) } }

fn live_member(member: Option<SourcePoolAllocationIdentity>, freed: bool, address: u64) -> bool {
    !freed && member.is_some_and(|member| contains_allocation(member, address))
}
pub(super) fn protects(inst: DriverInstance, address: u64) -> bool {
    graphs().iter().any(|row| same_pool(row.instance, inst)
        && (live_member(row.map, row.map_freed, address)
            || live_member(row.context, row.context_freed, address)
            || live_member(row.list, row.list_freed, address)
            || live_member(row.borrowed_list, false, address)))
        || tombstones().iter().any(|row| same_pool(row.instance, inst)
            && row.physical.is_some_and(|member| contains_allocation(member, address)))
}
pub(super) fn owns_pool(inst: DriverInstance) -> bool {
    has_live_graph(inst) || tombstones().iter().any(|row|
        same_arena(row.instance, inst) || same_pool(row.instance, inst))
}
pub(super) fn has_live_graph(inst: DriverInstance) -> bool {
    graphs().iter().any(|row| same_arena(row.instance, inst) || same_pool(row.instance, inst))
}

unsafe fn allocate_member(inst: DriverInstance, size: u64)
    -> Result<SourcePoolAllocationIdentity, nt_status::NtStatus>
{
    let address = hosted_instance_pool_alloc_unlocked(inst, size)
        .ok_or(nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    allocation(inst, address)
}

/// A request nonce makes allocation idempotent when the physical effect succeeded but its reply
/// was lost. All members are captured before any address can be handed to the component.
pub(super) unsafe fn provision(
    inst: DriverInstance, lease_id: u64, request_id: u64, kind: Kind,
    borrowed_list: u64,
) -> Result<(u64, u64, u64), nt_status::NtStatus> {
    if lease_id == 0 || request_id == 0 || (kind == Kind::ScatterGatherBorrowed) != (borrowed_list != 0) {
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    }
    let _durable = crate::allocator::enter_durable();
    let _catalog = lock();
    let domain = validate_arena(inst)?;
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let index = if let Some(index) = graphs().iter().position(|row|
        row.domain == domain && row.lease_id == lease_id && row.request_id == request_id)
    {
        let row = &graphs()[index];
        if !same_arena(row.instance, inst) || row.kind != kind || row.abandoned
            || row.borrowed_address != borrowed_list
            || row.map_released {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
        index
    } else {
        if kind == Kind::ScatterGatherBorrowed {
            let pool_list = if (FSD_POOL_VADDR..FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000)
                .contains(&borrowed_list) { Some(allocation(inst, borrowed_list)?) } else { None };
            if pool_list.is_some_and(|list| list.capacity < HOSTED_SG_LIST_SIZE_ONE)
                || dma_adapter_pair::protects(inst, borrowed_list)
                || interrupt_projection::protects(inst, borrowed_list)
                || protects(inst, borrowed_list)
                || rows().iter().any(|row| same_pool(row.instance, inst)
                    && contains_allocation(row.allocation, borrowed_list))
                || file_rows().iter().any(|row| same_pool(row.instance, inst)
                    && protects_file_member(row, borrowed_list))
                || temporary_pins().iter().any(|row| same_pool(row.instance, inst)
                    && contains_allocation(row.allocation, borrowed_list))
                || tombstones().iter().any(|row| same_pool(row.instance, inst)
                    && row.address == borrowed_list)
            {
                return Err(nt_status::NtStatus::OBJECT_NAME_COLLISION);
            }
        }
        graphs().try_reserve(1).map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        let borrowed = if borrowed_list != 0
            && (FSD_POOL_VADDR..FSD_POOL_VADDR + FSD_POOL_FRAMES * 0x1000).contains(&borrowed_list)
        { Some(allocation(inst, borrowed_list)?) } else { None };
        graphs().push(Graph {
            instance: inst, domain, lease_id, request_id, kind,
            map: None, context: None, list: None, borrowed_list: borrowed,
            borrowed_address: borrowed_list,
            mappings: Vec::new(), map_released: false, map_freed: false,
            context_freed: false, list_freed: false, published: false, abandoned: false,
        });
        graphs().len() - 1
    };
    if graphs()[index].map.is_none() {
        match allocate_member(inst, 0x20) {
            Ok(member) => graphs()[index].map = Some(member),
            Err(status) => {
                graphs()[index].abandoned = true;
                let _ = retire_index(inst, index, true, &mut |_| Ok(()));
                return Err(status);
            }
        }
    }
    if kind != Kind::Map && graphs()[index].context.is_none() {
        match allocate_member(inst, HOSTED_SG_CONTEXT_SIZE) {
            Ok(member) => graphs()[index].context = Some(member),
            Err(status) => {
                graphs()[index].abandoned = true;
                let _ = retire_index(inst, index, true, &mut |_| Ok(()));
                return Err(status);
            }
        }
    }
    if kind == Kind::ScatterGatherOwned && graphs()[index].list.is_none() {
        match allocate_member(inst, HOSTED_SG_LIST_SIZE_ONE) {
            Ok(member) => graphs()[index].list = Some(member),
            Err(status) => {
                graphs()[index].abandoned = true;
                let _ = retire_index(inst, index, true, &mut |_| Ok(()));
                return Err(status);
            }
        }
    }
    let row = &graphs()[index];
    for member in [row.map, row.context, row.list, row.borrowed_list].into_iter().flatten() {
        if allocation(inst, member.component_address)? != member {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
    }
    graphs()[index].published = true;
    let row = &graphs()[index];
    Ok((row.map.unwrap().component_address,
        row.context.map_or(0, |member| member.component_address),
        row.list.map_or(row.borrowed_address, |member| member.component_address)))
}

/// Register the logical mapping before the component publishes a shared record. Exact replay
/// returns its saved mapping ID; a different mapping for one token is a new row member.
pub(super) unsafe fn record_mapping(
    inst: DriverInstance, lease_id: u64, map: u64,
    logical: u64, backing: u64, length: u64,
    register: impl FnOnce() -> Result<u64, nt_status::NtStatus>,
) -> Result<u64, nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let _catalog = lock();
    let domain = validate_arena(inst)?;
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let index = graphs().iter().position(|row| row.domain == domain
        && same_arena(row.instance, inst) && row.lease_id == lease_id
        && row.map.is_some_and(|member| member.component_address == map)
        && row.published && !row.map_released)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if allocation(inst, map)? != graphs()[index].map.unwrap()
        || logical == 0 || backing == 0 || length == 0 {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    let exact = |mapping: &Mapping| !mapping.released && mapping.logical == logical
        && mapping.backing == backing && mapping.length == length;
    if let Some(mapping) = graphs()[index].mappings.iter().find(|mapping| exact(mapping)) {
        return Ok(mapping.id);
    }
    if graphs().iter().enumerate().any(|(other_index, row)| other_index != index
        && same_arena(row.instance, inst)
        && row.mappings.iter().any(|mapping| exact(mapping))) {
        return Err(nt_status::NtStatus::OBJECT_NAME_COLLISION);
    }
    graphs()[index].mappings.try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let id = register()?;
    if !graphs()[index].mappings.iter().any(|mapping| mapping.id == id) {
        graphs()[index].mappings.push(Mapping { id, logical, backing, length, released: false });
    }
    Ok(id)
}

pub(super) unsafe fn mapping_receipt(
    inst: DriverInstance, map: u64, logical: u64, backing: u64, length: u64,
) -> Option<(u64, u64)> {
    let _catalog = lock();
    let domain = validate_arena(inst).ok()?;
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)?;
    let row = graphs().iter().find(|row| row.domain == domain
        && same_arena(row.instance, inst) && row.published && !row.map_released
        && row.map.is_some_and(|member| member.component_address == map))?;
    if allocation(inst, map).ok()? != row.map? {
        return None;
    }
    let mapping = row.mappings.iter().find(|mapping| !mapping.released
        && mapping.logical == logical && mapping.backing == backing
        && mapping.length == length)?;
    Some((row.lease_id, mapping.id))
}

unsafe fn release_mappings(
    row: &mut Graph,
    release: &mut impl FnMut(u64) -> Result<(), nt_status::NtStatus>,
) -> Result<(), nt_status::NtStatus> {
    for mapping in &mut row.mappings {
        if !mapping.released {
            release(mapping.id)?;
            mapping.released = true;
        }
    }
    row.map_released = true;
    Ok(())
}

unsafe fn retire_index(
    inst: DriverInstance, index: usize, whole_graph: bool,
    release: &mut impl FnMut(u64) -> Result<(), nt_status::NtStatus>,
) -> Result<(), nt_status::NtStatus> {
    let row = &graphs()[index];
    for member in [row.map.filter(|_| !row.map_freed),
        row.context.filter(|_| !row.context_freed),
        row.list.filter(|_| !row.list_freed), row.borrowed_list]
        .into_iter().flatten()
    {
        if allocation(inst, member.component_address)? != member {
            return Err(nt_status::NtStatus::INVALID_HANDLE);
        }
    }
    if !row.published {
        for member in [graphs()[index].list.filter(|_| !graphs()[index].list_freed),
            graphs()[index].context.filter(|_| !graphs()[index].context_freed),
            graphs()[index].map.filter(|_| !graphs()[index].map_freed)]
            .into_iter().flatten()
        {
            if !hosted_instance_pool_free_unlocked(inst, member.component_address) {
                return Err(nt_status::NtStatus::INVALID_HANDLE);
            }
            if graphs()[index].list == Some(member) { graphs()[index].list_freed = true; }
            else if graphs()[index].context == Some(member) { graphs()[index].context_freed = true; }
            else { graphs()[index].map_freed = true; }
        }
        graphs().swap_remove(index);
        return Ok(());
    }
    // A map token is externally visible even when its SG graph remains live. Quarantine it
    // only when the whole graph is removed; an SG list also becomes an address tombstone.
    if whole_graph {
        let needed = 1 + 2 * usize::from(row.kind != Kind::Map);
        tombstones().try_reserve(needed)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    }
    release_mappings(&mut graphs()[index], release)?;
    if !whole_graph { return Ok(()); }
    let row = graphs().swap_remove(index);
    if let Some(map) = row.map {
        tombstones().push(Tombstone { instance: inst, physical: Some(map),
            address: map.component_address,
            retire_receipt: (row.kind == Kind::Map).then_some((row.lease_id, false)) });
    }
    if let Some(context) = row.context.filter(|_| !row.context_freed) {
        tombstones().push(Tombstone { instance: inst, physical: Some(context),
            address: context.component_address, retire_receipt: None });
    }
    if let Some(list) = row.list {
        tombstones().push(Tombstone { instance: inst, physical: row.list,
            address: list.component_address,
            retire_receipt: Some((row.lease_id, true)) });
    } else if row.borrowed_address != 0 {
        tombstones().push(Tombstone { instance: inst, physical: None,
            address: row.borrowed_address,
            retire_receipt: Some((row.lease_id, true)) });
    }
    Ok(())
}

pub(super) unsafe fn retire(
    inst: DriverInstance, lease_id: u64, address: u64, whole_graph: bool,
    mut release: impl FnMut(u64) -> Result<(), nt_status::NtStatus>,
) -> Result<(), nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let _catalog = lock();
    let domain = validate_arena(inst)?;
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let index = graphs().iter().position(|row| row.domain == domain
        && same_arena(row.instance, inst) && row.lease_id == lease_id
        && if whole_graph { row.kind != Kind::Map
            && row.list.map_or(row.borrowed_address, |member| member.component_address) == address }
           else { row.map.is_some_and(|member| member.component_address == address) });
    let Some(index) = index else {
        return if tombstones().iter().any(|row| same_arena(row.instance, inst)
            && row.address == address && row.retire_receipt == Some((lease_id, whole_graph))) {
            Ok(())
        } else {
            Err(nt_status::NtStatus::INVALID_HANDLE)
        };
    };
    let finish = whole_graph || graphs()[index].kind == Kind::Map;
    retire_index(inst, index, finish, &mut release)
}

pub(super) unsafe fn sg_members(
    inst: DriverInstance, lease_id: u64, list: u64,
) -> Result<(u64, u64), nt_status::NtStatus> {
    let _catalog = lock();
    let domain = validate_arena(inst)?;
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let row = graphs().iter().find(|row| row.domain == domain
        && same_arena(row.instance, inst) && row.lease_id == lease_id
        && row.kind != Kind::Map && row.published
        && row.list.map_or(row.borrowed_address, |member| member.component_address) == list)
        .ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let map = row.map.ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    let context = row.context.ok_or(nt_status::NtStatus::INVALID_HANDLE)?;
    if row.context_freed || allocation(inst, map.component_address)? != map
        || allocation(inst, context.component_address)? != context {
        return Err(nt_status::NtStatus::INVALID_HANDLE);
    }
    Ok((map.component_address, context.component_address))
}

pub(super) unsafe fn retire_lease(
    inst: DriverInstance, lease_id: u64,
    mut release: impl FnMut(u64) -> Result<(), nt_status::NtStatus>,
) -> Result<(), nt_status::NtStatus> {
    let _durable = crate::allocator::enter_durable();
    let _catalog = lock();
    let domain = validate_arena(inst)?;
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    while let Some(index) = graphs().iter().position(|row| row.domain == domain
        && same_arena(row.instance, inst) && row.lease_id == lease_id)
    {
        retire_index(inst, index, true, &mut release)?;
    }
    Ok(())
}

pub(super) unsafe fn drain_tombstones(inst: DriverInstance)
    -> Result<(), nt_status::NtStatus>
{
    let _catalog = lock();
    validate_arena(inst)?;
    let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
        .ok_or(nt_status::NtStatus::DEVICE_BUSY)?;
    let mut index = 0;
    while index < tombstones().len() {
        let row = &tombstones()[index];
        if !same_arena(row.instance, inst) { index += 1; continue; }
        if let Some(member) = row.physical {
            if allocation(inst, member.component_address)? != member
                || !hosted_instance_pool_free_unlocked(inst, member.component_address) {
                return Err(nt_status::NtStatus::INVALID_HANDLE);
            }
        }
        tombstones().swap_remove(index);
    }
    Ok(())
}
