//! Executive-owned contiguous RAM for isolated kernel drivers.
//!
//! The component's 8 MiB pool is unrelated to physical DMA RAM. This broker carves the smallest
//! power-of-two child Untyped and maps a verified 4 KiB frame run into a separate component VA
//! aperture.
//! Every cap, map and domain generation remains owned until a confirmed free or retirement.

use super::*;
use nt_hosted_runtime::{ContiguousRamLayout, ContiguousRamOwner, ContiguousRamPrepareTable,
    ContiguousRamReceipt, ContiguousRamRequest, ContiguousRamLeaseBank,
    ContiguousRamLeaseSource};

const PAGE: u64 = 4096;
const MAX_CHILD_BYTES: u64 = 64 << 20;
const APERTURE_BASE: u64 = 0x0000_0103_0000_0000;
const APERTURE_STRIDE: u64 = MAX_CHILD_BYTES;
const APERTURE_SLOTS: u64 = 8;
const STATUS_INVALID_PARAMETER: i32 = 0xc000_000du32 as i32;
const STATUS_ACCESS_DENIED: i32 = 0xc000_0022u32 as i32;
const STATUS_INSUFFICIENT_RESOURCES: i32 = 0xc000_009au32 as i32;
const STATUS_NOT_FOUND: i32 = 0xc000_0034u32 as i32;
const STATUS_SUCCESS: i32 = 0;

const _: () = assert!(APERTURE_BASE >= FSD_WORKER_EXEC_ALIAS_BASE + 0x8000_0000);
const _: () = assert!(APERTURE_BASE >= FSD_EXEC_LIMIT);
const _: () = assert!(APERTURE_BASE + APERTURE_SLOTS * APERTURE_STRIDE < 0x0000_0200_0000_0000);

struct Allocation {
    slot: usize,
    owner: ContiguousRamOwner,
    address: u64,
    length: u64,
    cache: u32,
    child: u64,
    cap_base: u64,
    capacity_frames: u64,
    child_ready: bool,
    frames: u64,
    retyped: u64,
    mapped: u64,
    quarantined: bool,
    published: bool,
    available: bool,
}

static BROKER_LOCK: AtomicU64 = AtomicU64::new(0);
static mut PREPARED: ContiguousRamPrepareTable = ContiguousRamPrepareTable::new();
static mut LEASES: ContiguousRamLeaseBank = ContiguousRamLeaseBank::new();
static mut ALLOCATIONS: Vec<Allocation> = Vec::new();

struct BrokerGuard;
impl Drop for BrokerGuard {
    fn drop(&mut self) { BROKER_LOCK.store(0, Ordering::Release); }
}
fn lock() -> BrokerGuard {
    while BROKER_LOCK.compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed).is_err() {
        crate::yield_now();
    }
    BrokerGuard
}

fn owner(instance: usize, inst: DriverInstance) -> Option<ContiguousRamOwner> {
    (inst.hosted_domain_id != 0 && inst.hosted_domain_cookie != 0).then_some(
        ContiguousRamOwner { instance, generation: inst.hosted_domain_cookie,
            domain: inst.hosted_domain_id })
}

fn next_aperture(owner: ContiguousRamOwner, ledger: &[Allocation], length: u64)
    -> Option<ContiguousRamLayout> {
    let child_bytes = ContiguousRamLayout::minimum_child_bytes(length)?;
    for slot in 0..APERTURE_SLOTS {
        let base = APERTURE_BASE.checked_add(slot.checked_mul(APERTURE_STRIDE)?)?;
        let plan = ContiguousRamLayout::for_request(length, base, child_bytes)?;
        if !ledger.iter().any(|row| !row.available && row.owner == owner && row.address == base) {
            return Some(plan);
        }
    }
    None
}

/// Called only from the authenticated hosted device service pump. The reply capability is held
/// throughout both operations; PREPARE has no native side effects and COMMIT consumes its ticket
/// before any retype/map can happen.
pub(super) fn service(ch: &crate::spawn_hosts::PumpChannel, op: u64, a1: u64, a2: u64, a3: u64,
    reply: u64, caller_badge: u64) -> (i32, u64, u64, u64) {
    let Some((instance, inst)) = instance_for_pump_channel(ch, reply) else {
        return (STATUS_ACCESS_DENIED, 0, 0, 0);
    };
    let Some(owner) = owner(instance, inst) else { return (STATUS_ACCESS_DENIED, 0, 0, 0); };
    if caller_badge == 0 { return (STATUS_ACCESS_DENIED, 0, 0, 0); }
    let _guard = lock();
    unsafe {
        match op {
            HOSTED_DEVICE_OP_CONTIGUOUS_PREPARE => match (&mut *core::ptr::addr_of_mut!(PREPARED))
                .prepare(owner, caller_badge, a1, a2, a3) {
                Ok(ticket) => (STATUS_SUCCESS, ticket, 0, 0),
                Err(_) => (STATUS_INVALID_PARAMETER, 0, 0, 0),
            },
            HOSTED_DEVICE_OP_CONTIGUOUS_EXPIRE => match (&mut *core::ptr::addr_of_mut!(PREPARED))
                .expire(owner, caller_badge, a1) {
                Ok(()) => (STATUS_SUCCESS, 0, 0, 0),
                Err(_) => (STATUS_NOT_FOUND, 0, 0, 0),
            },
            HOSTED_DEVICE_OP_CONTIGUOUS_COMMIT => {
                let request = match (&mut *core::ptr::addr_of_mut!(PREPARED))
                    .commit(owner, caller_badge, a1, a2, a3 as u32) {
                    Ok(request) if a3 == a3 as u32 as u64 => request,
                    _ => return (STATUS_INVALID_PARAMETER, 0, 0, 0),
                };
                print_str(b"[contiguous-broker] commit inst="); print_u64(instance as u64);
                print_str(b" len="); print_u64(request.length);
                print_str(b" cache="); print_u64(request.cache as u64);
                print_str(b"\n");
                match allocate(owner, inst, request) {
                    Some(address) => (STATUS_SUCCESS, address, 0, 0),
                    None => (STATUS_INSUFFICIENT_RESOURCES, 0, 0, 0),
                }
            }
            HOSTED_DEVICE_OP_CONTIGUOUS_FREE => {
                (free(owner, a1, a2, a3), 0, 0, 0)
            }
            _ => (STATUS_INVALID_PARAMETER, 0, 0, 0),
        }
    }
}

unsafe fn allocate(owner: ContiguousRamOwner, inst: DriverInstance,
    request: ContiguousRamRequest) -> Option<u64> {
    if request.cache != nt_hal_abi::MM_CACHED { return None; }
    let ledger = &mut *core::ptr::addr_of_mut!(ALLOCATIONS);
    let plan = next_aperture(owner, ledger, request.length)?;
    if request.low > request.high { return None; }
    let lease = (&mut *core::ptr::addr_of_mut!(LEASES))
        .reserve(owner, plan.child_bytes() / PAGE).ok()?;
    if lease.slot >= ledger.len() && ledger.try_reserve(1).is_err() {
        let _ = (&mut *core::ptr::addr_of_mut!(LEASES)).confirm_clean(owner, lease.slot);
        return None;
    }
    if lease.slot == ledger.len() {
        ledger.push(Allocation { slot: lease.slot, owner, address: plan.base(),
            length: request.length, cache: request.cache, child: 0, cap_base: 0,
            capacity_frames: 0, child_ready: false, frames: plan.frames(), retyped: 0,
            mapped: 0, quarantined: false, published: false, available: false });
    }
    let row = &mut ledger[lease.slot];
    row.owner = owner;
    row.address = plan.base();
    row.length = request.length;
    row.cache = request.cache;
    row.frames = plan.frames();
    row.retyped = 0;
    row.mapped = 0;
    row.quarantined = false;
    row.published = false;
    row.available = false;
    let result = allocate_into(row, inst, plan, request, lease.source);
    if result.is_none() {
        if row.quarantined || !cleanup_known_effects(row) {
            row.quarantined = true;
            let _ = (&mut *core::ptr::addr_of_mut!(LEASES)).quarantine(owner, lease.slot);
        } else {
            let _ = (&mut *core::ptr::addr_of_mut!(LEASES)).confirm_clean(owner, lease.slot);
        }
    }
    result
}

unsafe fn allocate_into(row: &mut Allocation, inst: DriverInstance, plan: ContiguousRamLayout,
    request: ContiguousRamRequest, source: ContiguousRamLeaseSource) -> Option<u64> {
    let owner = row.owner;
    print_str(b"[contiguous-broker] reserved aperture=0x");
    print_hex64(plan.base()); print_str(b" frames="); print_u64(plan.frames());
    print_str(b" child_bytes="); print_u64(plan.child_bytes());
    print_str(b"\n");
    match source {
        ContiguousRamLeaseSource::Fresh => {
            let child = try_alloc_slot()?;
            row.child = child;
            let caps = try_alloc_slot_run(plan.child_bytes() / PAGE)?;
            row.cap_base = caps;
            row.capacity_frames = plan.child_bytes() / PAGE;
            if (&mut *core::ptr::addr_of_mut!(LEASES)).attach_frame_slots(owner, row.slot,
                caps, row.capacity_frames).is_err() {
                panic!("contiguous RAM slot run lost its pre-effect owner");
            }
            if crate::untyped_retype_from_r(CAP_INIT_UNTYPED, OBJ_UNTYPED,
                plan.child_bytes().trailing_zeros(), 1, child) != 0 {
                print_str(b"[contiguous-broker] child retype failed\n");
                return None;
            }
            row.child_ready = true;
            if (&mut *core::ptr::addr_of_mut!(LEASES)).attach_resources(owner, row.slot,
                child, caps, row.capacity_frames).is_err() {
                panic!("contiguous RAM lease lost its pre-effect owner");
            }
            print_str(b"[contiguous-broker] child retyped cap="); print_u64(child);
            print_str(b" slots="); print_u64(caps); print_str(b"\n");
        }
        ContiguousRamLeaseSource::SlotsOnly { cap_base, capacity_frames } => {
            if row.child_ready || row.child != 0 || row.cap_base != cap_base
                || row.capacity_frames != capacity_frames
                || capacity_frames != plan.child_bytes() / PAGE {
                row.quarantined = true;
                return None;
            }
            let child = try_alloc_slot()?;
            row.child = child;
            if crate::untyped_retype_from_r(CAP_INIT_UNTYPED, OBJ_UNTYPED,
                plan.child_bytes().trailing_zeros(), 1, child) != 0 {
                print_str(b"[contiguous-broker] child retype failed with retained slots\n");
                return None;
            }
            row.child_ready = true;
            if (&mut *core::ptr::addr_of_mut!(LEASES)).attach_resources(owner, row.slot,
                child, cap_base, capacity_frames).is_err() {
                panic!("contiguous RAM child lost its slot-only owner");
            }
            print_str(b"[contiguous-broker] child retyped with retained slots cap=");
            print_u64(child); print_str(b" slots="); print_u64(cap_base); print_str(b"\n");
        }
        ContiguousRamLeaseSource::Reuse { child, cap_base, capacity_frames } => {
            if !row.child_ready || row.child != child || row.cap_base != cap_base
                || row.capacity_frames != capacity_frames
                || capacity_frames != plan.child_bytes() / PAGE {
                row.quarantined = true;
                return None;
            }
            print_str(b"[contiguous-broker] reusing child cap="); print_u64(child);
            print_str(b" slots="); print_u64(cap_base); print_str(b"\n");
        }
    }
    let child = row.child;
    let caps = row.cap_base;
    let mut receipt = ContiguousRamReceipt::new(owner, plan, child)?;
    for batch in 0..plan.batch_count() {
        let (start, count) = plan.batch(batch)?;
        if crate::untyped_retype_from_r(child, OBJ_X86_4K_PAGE, PAGING_BITS,
            count, caps + start) != 0 {
            print_str(b"[contiguous-broker] frame retype failed batch=");
            print_u64(batch); print_str(b"\n");
            return None;
        }
        row.retyped += count as u64;
        for index in start..start + count as u64 {
            let physical = match crate::get_frame_paddr_checked(caps + index) {
                Ok(physical) => physical,
                Err(_) => {
                    print_str(b"[contiguous-broker] GetAddress failed frame=");
                    print_u64(index); print_str(b"\n");
                    return None;
                }
            };
            if receipt.record_frame(owner, index, caps + index, physical).is_err() {
                print_str(b"[contiguous-broker] physical run rejected frame=");
                print_u64(index); print_str(b" pa=0x"); print_hex64(physical);
                print_str(b"\n");
                return None;
            }
        }
    }
    print_str(b"[contiguous-broker] physical run verified frames=");
    print_u64(plan.frames()); print_str(b"\n");
    // Physical NT admission is completed before any frame is mapped into the provider.
    // The receipt checks every GetAddress-derived page and exact low/high/boundary bounds.
    // It requires map proof for publication, so perform a range precheck using first/last caps.
    let first = crate::get_frame_paddr_checked(caps).ok()?;
    let last_start = crate::get_frame_paddr_checked(caps + plan.frames() - 1).ok()?;
    let last = last_start.checked_add(PAGE - 1)?;
    if first < request.low || last > request.high
        || request.boundary != 0 && first / request.boundary != last / request.boundary {
        print_str(b"[contiguous-broker] NT physical range rejected first=0x");
        print_hex64(first); print_str(b" last=0x"); print_hex64(last);
        print_str(b"\n");
        return None;
    }
    let domain = HostedDomainIdentity {
        domain_id: nt_io_manager::HostedDomainId(inst.hosted_domain_id),
        cookie: inst.hosted_domain_cookie,
    };
    for index in 0..plan.frames() {
        let va = plan.base() + index * PAGE;
        if index % 512 == 0 && !ensure_paging(va, inst.pml4, domain) {
            print_str(b"[contiguous-broker] paging failed frame=");
            print_u64(index); print_str(b"\n");
            return None;
        }
        if receipt.begin_map(owner, index).is_err() { return None; }
        let result = page_map_r(caps + index, va, RW_NX, inst.pml4);
        if receipt.record_map_result(owner, index, (result == 0).then_some(()).ok_or(())).is_err() {
            row.quarantined = true;
            print_str(b"[contiguous-broker] map uncertain frame=");
            print_u64(index); print_str(b" label="); print_u64(result);
            print_str(b"\n");
            return None;
        }
        row.mapped += 1;
    }
    let address = receipt.publish(owner, request.low, request.high, request.boundary).ok()?;
    row.published = true;
    print_str(b"[contiguous-broker] published address=0x");
    print_hex64(address); print_str(b" bytes="); print_u64(request.length);
    print_str(b"\n");
    Some(address)
}

/// Only definite native effects are rolled back. Failed retypes are confirmed no-effect;
/// uncertain mappings and cleanup errors keep the child and cap run quarantined.
unsafe fn cleanup_known_effects(row: &mut Allocation) -> bool {
    if row.quarantined { return false; }
    while row.mapped != 0 {
        let cap = row.cap_base + row.mapped - 1;
        if page_unmap_r(cap) != 0 { row.quarantined = true; return false; }
        row.mapped -= 1;
    }
    while row.retyped != 0 {
        let cap = row.cap_base + row.retyped - 1;
        if cnode_delete_r(cap) != 0 { row.quarantined = true; return false; }
        row.retyped -= 1;
    }
    if row.child_ready {
        if cnode_revoke_r(row.child) != 0 { row.quarantined = true; return false; }
    } else {
        if row.child != 0 { recycle_deleted_root_slot(row.child); }
        row.child = 0;
    }
    row.published = false;
    row.available = true;
    true
}

unsafe fn free(owner: ContiguousRamOwner, address: u64, length: u64, cache: u64) -> i32 {
    let ledger = &mut *core::ptr::addr_of_mut!(ALLOCATIONS);
    let Some(index) = ledger.iter().position(|row| !row.available
        && row.owner == owner && row.address == address)
    else { return STATUS_NOT_FOUND; };
    let row = &mut ledger[index];
    if row.quarantined || !row.published || length != 0 && length != row.length
        || cache != u64::MAX && cache != row.cache as u64 {
        return STATUS_INVALID_PARAMETER;
    }
    row.published = false;
    if !cleanup_known_effects(row) {
        let _ = (&mut *core::ptr::addr_of_mut!(LEASES)).quarantine(owner, row.slot);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    if (&mut *core::ptr::addr_of_mut!(LEASES)).confirm_clean(owner, row.slot).is_err() {
        row.quarantined = true;
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    STATUS_SUCCESS
}

/// Called before the domain's PML4 and paging hierarchy retire. Any uncertain frame/map
/// transition blocks retirement so its physical child cannot be reused under a new generation.
pub(super) unsafe fn retire_instance(instance: usize, inst: DriverInstance) -> bool {
    let Some(owner) = owner(instance, inst) else { return false; };
    let _guard = lock();
    (&mut *core::ptr::addr_of_mut!(PREPARED)).retire_owner(owner);
    let ledger = &mut *core::ptr::addr_of_mut!(ALLOCATIONS);
    for row in ledger.iter_mut().filter(|row| row.owner == owner && !row.available) {
        if row.quarantined || !cleanup_known_effects(row) { return false; }
        if (&mut *core::ptr::addr_of_mut!(LEASES)).confirm_clean(owner, row.slot).is_err() {
            row.quarantined = true;
            return false;
        }
    }
    true
}
