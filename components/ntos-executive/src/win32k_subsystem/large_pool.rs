//! Provider-only large pool: exact allocation lifetimes and demand-mapped leaf pages.
//!
//! The pure ledger lives in `nt-memory-manager`. This adapter publishes each allocation to the
//! provider catalog before returning its VA, authenticates the physical win32k lane on faults,
//! and keeps every uncertain seL4 effect and cap quarantined against address reuse.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use nt_memory_manager::provider_large_arena::{
    LargeAllocation, LargeArena, LargePublication, PageMapDecision, PAGE_SIZE,
};

use super::*;

pub(super) const BASE: u64 = 0x0000_0100_4000_0000;
pub(super) const BYTES: u64 = 64 * 1024 * 1024;
const _: () = assert!(BASE >= crate::PRIVATE_VM_LIMIT);
const _: () = assert!(BASE + BYTES <= WIN32K_BULK_ARENA_VADDR);

// Inline bytes reside in the shared executive image; no provider-private Vec or Box pointer
// crosses into the root fault pump. Const construction avoids a large provider stack temporary.
static mut LARGE_ARENA: LargeArena = match LargeArena::new(BASE, BYTES) {
    Ok(arena) => arena,
    Err(_) => panic!("invalid large provider arena"),
};
static LARGE_ARENA_READY: AtomicBool = AtomicBool::new(false);
static FAULT_DENIAL_TRACES: AtomicU64 = AtomicU64::new(0);
const FAULT_DENIAL_TRACE_LIMIT: u64 = 8;
static RETIRE_DENIAL_TRACES: AtomicU64 = AtomicU64::new(0);

fn deny_fault(stage: u64, address: u64, fault_status: u64,
    ch: &crate::spawn_hosts::PumpChannel) -> Option<bool>
{
    if FAULT_DENIAL_TRACES.fetch_add(1, Ordering::Relaxed) < FAULT_DENIAL_TRACE_LIMIT {
        print_str(b"[win32k-large-pool] denied stage="); print_u64(stage);
        print_str(b" addr="); crate::print_hex_u64(address);
        print_str(b" fsr="); print_u64(fault_status);
        print_str(b" tcb="); crate::print_hex_u64(ch.tcb);
        print_str(b" fault-ep="); crate::print_hex_u64(ch.fault_ep);
        print_str(b" reply="); crate::print_hex_u64(ch.reply_cap);
        print_str(b" pml4="); crate::print_hex_u64(ch.pml4);
        print_str(b"\n");
    }
    Some(false)
}

pub(super) unsafe fn initialize_unlocked(_guard: &mut ProviderMetadataGuard) -> bool {
    LARGE_ARENA_READY.compare_exchange(false, true, Ordering::Release, Ordering::Relaxed).is_ok()
}

pub(super) fn contains(pointer: u64) -> bool {
    (BASE..BASE + BYTES).contains(&pointer)
}

/// Caller holds `ProviderMetadataGuard` through its entire use of this reference.
unsafe fn ledger_mut() -> Option<&'static mut LargeArena> {
    if !LARGE_ARENA_READY.load(Ordering::Acquire) { return None; }
    Some(&mut *core::ptr::addr_of_mut!(LARGE_ARENA))
}

unsafe fn rollback_unpublished(ledger: &mut LargeArena, allocation: LargeAllocation) {
    if ledger.begin_retirement(allocation).is_err()
        || ledger.complete_retirement(allocation).is_err()
    {
        print_str(b"[win32k-large-pool] fatal allocation rollback failure\n");
        park();
    }
}

/// `shared_pool::OutOfMemory` is the only caller-side reason to enter this backend. A successful
/// reserve and catalog registration precede any provider touch; zeroing occurs after lock release.
pub(super) unsafe fn allocate(bytes: u64, zero: bool) -> u64 {
    let Some(arena) = fixed_provider_arena_identity(PROVIDER_ARENA_LARGE_POOL_ID) else { return 0; };
    let result = {
        let mut guard = ProviderMetadataGuard::acquire();
        let Some(ledger) = ledger_mut() else { return 0; };
        let Ok(allocation) = ledger.reserve(bytes) else { return 0; };
        let snapshot = provider_allocations_unlocked(&mut guard).and_then(|catalog| {
            if !register_provider_allocation_observed(
                catalog, arena, allocation.base, allocation.capacity,
            ) { return None; }
            Some(catalog.active_exact_capacity(arena, allocation.base, allocation.capacity)
                .unwrap_or_else(|_| {
                    print_str(b"[win32k-large-pool] fatal catalog registration witness failure\n");
                    park();
                }))
        });
        if let Some(snapshot) = snapshot {
            let witness = LargePublication {
                arena_id: snapshot.identity.arena.id,
                arena_generation: snapshot.identity.arena.generation,
                allocation_id: snapshot.identity.allocation_id,
                allocation_generation: snapshot.identity.generation,
            };
            if ledger.publish(allocation, witness, snapshot.base, snapshot.capacity).is_err() {
                print_str(b"[win32k-large-pool] fatal catalog publication failure\n");
                park();
            }
            print_str(b"[win32k-large-pool] published base=");
            crate::print_hex_u64(allocation.base);
            print_str(b" capacity="); print_u64(allocation.capacity);
            print_str(b" generation="); print_u64(allocation.generation);
            print_str(b" records="); print_u64(ledger.allocation_count() as u64);
            print_str(b" ledger="); crate::print_hex_u64(ledger as *const LargeArena as u64);
            print_str(b"\n");
            Some(allocation)
        } else {
            rollback_unpublished(ledger, allocation);
            None
        }
    };
    let Some(allocation) = result else { return 0; };
    if zero {
        // Fresh retyped pages are zeroed. Explicitly touch the requested bytes here to preserve
        // the zeroing API even after VA reuse, without holding the metadata guard over faults.
        core::ptr::write_bytes(allocation.base as *mut u8, 0, bytes as usize);
    }
    allocation.base
}

fn channel_is_current_win32k(ch: &crate::spawn_hosts::PumpChannel) -> Result<(), u64> {
    unsafe {
        if ch.pml4 == 0 || ch.pml4 != crate::WIN32K_HOST_PML4.load(Ordering::Acquire) {
            return Err(1);
        }
        if ch.root_image_map_owner == 0 || u64::from(ch.root_image_map_owner)
            != crate::WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire)
        { return Err(2); }
        if ch.shared_va != WIN32K_SHARED_VADDR { return Err(3); }
        let Some(route) = ch.ingress_route else { return Err(4); };
        let Some(lane) = crate::win32k_glue::win32k_physical_lane_for_channel(
            ch.tcb, ch.fault_ep, ch.reply_cap,
        ) else { return Err(5); };
        if route.identity().lane != lane { return Err(6); }
        let Ok(source) = crate::spawn_hosts::shared_ingress::owner::runtime::physical_source(route)
            else { return Err(7); };
        if source.tcb != ch.tcb || source.pml4 != ch.pml4 { return Err(8); }
        if !crate::win32k_glue::verify_win32k_worker_source(source) { return Err(9); }
        Ok(())
    }
}

fn publication_is_current(ledger: &LargeArena, allocation: LargeAllocation) -> bool {
    let Some(arena) = fixed_provider_arena_identity(PROVIDER_ARENA_LARGE_POOL_ID) else {
        return false;
    };
    ledger.publication(allocation).is_ok_and(|witness|
        witness.is_valid()
            && witness.arena_id == arena.id
            && witness.arena_generation == arena.generation)
}

/// `Some(false)` is a hard wall for every unauthorized address in this entire band. Never let
/// an unreserved large-pool address fall into win32k's generic private-page zero filler.
pub(crate) unsafe fn service_fault(
    ch: &crate::spawn_hosts::PumpChannel,
    address: u64,
    fault_status: u64,
) -> Option<bool> {
    if !contains(address) { return None; }
    if let Err(stage) = channel_is_current_win32k(ch) {
        return deny_fault(stage, address, fault_status, ch);
    }
    let page = address & !(PAGE_SIZE - 1);
    // First check the allocation under the short metadata lock. Cap slot acquisition and every
    // subsequent native mapping effect occur after this guard is dropped.
    {
        let _guard = ProviderMetadataGuard::acquire();
        let Some(ledger) = ledger_mut() else { return deny_fault(10, address, fault_status, ch); };
        let allocation = match ledger.authorize_fault(address, fault_status) {
            Ok(allocation) => allocation,
            Err(error) => {
                if FAULT_DENIAL_TRACES.load(Ordering::Relaxed) < FAULT_DENIAL_TRACE_LIMIT {
                    print_str(b"[win32k-large-pool] ledger-fault error=");
                    print_u64(error as u64);
                    print_str(b" records="); print_u64(ledger.allocation_count() as u64);
                    print_str(b" ledger="); crate::print_hex_u64(ledger as *const LargeArena as u64);
                    print_str(b"\n");
                }
                return deny_fault(11, address, fault_status, ch);
            }
        };
        if !publication_is_current(ledger, allocation) {
            return deny_fault(13, address, fault_status, ch);
        }
        if ledger.page_cap(allocation, page).ok().flatten().is_some() {
            return if ledger.begin_page_map(allocation, page, 0)
                == Ok(PageMapDecision::AlreadyMapped) { Some(true) }
                else { deny_fault(14, address, fault_status, ch) };
        }
    }
    let Some(cap) = crate::try_alloc_slot() else {
        return deny_fault(15, address, fault_status, ch);
    };
    let (allocation, cap, decision) = {
        let _guard = ProviderMetadataGuard::acquire();
        let Some(ledger) = ledger_mut() else {
            crate::recycle_deleted_root_slot(cap);
            return deny_fault(16, address, fault_status, ch);
        };
        let Ok(allocation) = ledger.authorize_fault(address, fault_status) else {
            crate::recycle_deleted_root_slot(cap);
            return deny_fault(17, address, fault_status, ch);
        };
        if !publication_is_current(ledger, allocation) {
            crate::recycle_deleted_root_slot(cap);
            return deny_fault(19, address, fault_status, ch);
        }
        let decision = match ledger.begin_page_map(allocation, page, cap) {
            Ok(decision) => decision,
            Err(_) => {
                crate::recycle_deleted_root_slot(cap);
                return deny_fault(20, address, fault_status, ch);
            }
        };
        (allocation, cap, decision)
    };
    if decision == PageMapDecision::AlreadyMapped {
        crate::recycle_deleted_root_slot(cap);
        return Some(true);
    }
    let owner = ch.root_image_map_owner;
    if !crate::spawn_hosts::component_map_cap_bank_tag(owner, cap)
        || !crate::win32k_glue::ensure_w32_client_paging(page, ch.pml4)
        || crate::untyped_retype_r(crate::CAP_INIT_UNTYPED, crate::OBJ_X86_4K_PAGE,
            crate::PAGING_BITS, 1, cap) != 0
        || crate::page_map_r(cap, page, crate::RW_NX, ch.pml4) != 0
    {
        let mut guard = ProviderMetadataGuard::acquire();
        if !ledger_mut().is_some_and(|ledger|
            ledger.quarantine_page_map(allocation, page).is_ok())
        {
            print_str(b"[win32k-large-pool] fatal map quarantine failure\n");
        }
        print_str(b"[win32k-large-pool] map failed or uncertain page=0x");
        crate::print_hex_u64(page);
        print_str(b"\n");
        park();
    }
    let mut guard = ProviderMetadataGuard::acquire();
    if !ledger_mut().is_some_and(|ledger|
        ledger.complete_page_map(allocation, page).is_ok())
    {
        print_str(b"[win32k-large-pool] fatal map commit failure\n");
        park();
    }
    Some(true)
}

fn deny_retirement(stage: u64, base: u64, generation: u64) -> [u64; 4] {
    if RETIRE_DENIAL_TRACES.fetch_add(1, Ordering::Relaxed) < 8 {
        print_str(b"[win32k-large-pool] retirement denied stage="); print_u64(stage);
        print_str(b" base="); crate::print_hex_u64(base);
        print_str(b" generation="); print_u64(generation);
        print_str(b"\n");
    }
    [0; 4]
}

/// The pump invokes this in the executive's CSpace. Its only authority comes from the exact
/// physical win32k lane and the inline Retiring record, whose publication was recorded before
/// the provider received the VA. The provider catalog remains private to the provider heap.
pub(crate) unsafe fn service_retirement(
    ch: &crate::spawn_hosts::PumpChannel,
    base: u64,
    generation: u64,
    publication_id: u64,
    publication_generation: u64,
) -> [u64; 4] {
    if channel_is_current_win32k(ch).is_err() { return deny_retirement(1, base, generation); }
    let Some(arena) = fixed_provider_arena_identity(PROVIDER_ARENA_LARGE_POOL_ID) else {
        return deny_retirement(2, base, generation);
    };
    let allocation = {
        let _guard = ProviderMetadataGuard::acquire();
        let Some(ledger) = ledger_mut() else { return deny_retirement(3, base, generation); };
        let Ok((allocation, witness)) = ledger.retiring_snapshot(base, generation) else {
            return deny_retirement(4, base, generation);
        };
        if witness.arena_id != arena.id || witness.arena_generation != arena.generation
            || witness.allocation_id != publication_id
            || witness.allocation_generation != publication_generation
        {
            return deny_retirement(5, base, generation);
        }
        allocation
    };
    let owner = ch.root_image_map_owner;
    let mut page = allocation.base;
    let end = allocation.base + allocation.capacity;
    while page < end {
        let cap = {
            let _guard = ProviderMetadataGuard::acquire();
            let Some(ledger) = ledger_mut() else { park(); };
            let Ok((current, witness)) = ledger.retiring_snapshot(base, generation) else {
                print_str(b"[win32k-large-pool] fatal retirement identity changed\n");
                park();
            };
            if current != allocation || witness.arena_id != arena.id
                || witness.arena_generation != arena.generation
                || witness.allocation_id != publication_id
                || witness.allocation_generation != publication_generation
            {
                print_str(b"[win32k-large-pool] fatal retirement witness changed\n");
                park();
            }
            let cap = ledger.page_cap(allocation, page).unwrap_or_else(|_| park());
            if cap.is_some() && ledger.begin_page_unmap(allocation, page).is_err() {
                print_str(b"[win32k-large-pool] fatal root page retirement reservation\n");
                park();
            }
            cap
        };
        if let Some(cap) = cap {
            if !crate::spawn_hosts::component_map_cap_bank_release_page(owner, cap) {
                let _guard = ProviderMetadataGuard::acquire();
                let _ = ledger_mut().and_then(|ledger|
                    ledger.quarantine_page_unmap(allocation, page).ok());
                print_str(b"[win32k-large-pool] failed or uncertain root page release\n");
                park();
            }
            let _guard = ProviderMetadataGuard::acquire();
            if !ledger_mut().is_some_and(|ledger|
                ledger.complete_page_unmap(allocation, page).is_ok())
            {
                print_str(b"[win32k-large-pool] fatal root page release commit\n");
                park();
            }
        }
        page += PAGE_SIZE;
    }
    [base, generation, publication_id, publication_generation]
}

pub(super) unsafe fn free(pointer: u64) -> bool {
    if !contains(pointer) { return false; }
    let Some(arena) = fixed_provider_arena_identity(PROVIDER_ARENA_LARGE_POOL_ID) else { return false; };
    let (allocation, catalog_allocation) = {
        let mut guard = ProviderMetadataGuard::acquire();
        let Some(ledger) = ledger_mut() else { return false; };
        let Ok(allocation) = ledger.authorize_fault(pointer, 0) else { return false; };
        if allocation.base != pointer { return false; }
        let Some(catalog) = provider_allocations_unlocked(&mut guard) else { return false; };
        let Ok(snapshot) = catalog.active_exact_capacity(arena, pointer, allocation.capacity)
            else { return false; };
        let witness = LargePublication {
            arena_id: snapshot.identity.arena.id,
            arena_generation: snapshot.identity.arena.generation,
            allocation_id: snapshot.identity.allocation_id,
            allocation_generation: snapshot.identity.generation,
        };
        if ledger.publication(allocation) != Ok(witness) { return false; }
        if catalog.validate_retirement(snapshot.identity) != Ok(snapshot)
            || !validate_provider_allocation_event_retirement(snapshot)
            || !validate_provider_allocation_timer_retirement(snapshot)
            || !local_sync::validate_backing_retirement(provider_allocation_event_backing(snapshot))
        {
            return false;
        }
        if ledger.begin_retirement(allocation).is_err() { return false; }
        if catalog.begin_retirement(snapshot.identity) != Ok(snapshot) {
            print_str(b"[win32k-large-pool] fatal catalog retirement reservation failure\n");
            park();
        }
        (allocation, snapshot)
    };
    if !retire_provider_allocation_events(catalog_allocation)
        || !retire_provider_allocation_timers(catalog_allocation)
        || !local_sync::retire_backing(provider_allocation_event_backing(catalog_allocation))
    {
        print_str(b"[win32k-large-pool] fatal dependent retirement failure\n");
        park();
    }
    // Root owns every leaf cap. A synchronous broker call supplies an exact four-word
    // acknowledgement only after root has confirmed all unmap/delete effects. No metadata
    // guard crosses this call, since the root pump must inspect and advance the inline ledger.
    let (words, ack_base, ack_generation, ack_id, ack_publication_generation) =
        crate::driver_launch::call_on4_raw(
            (W32_LARGE_POOL_RETIRE_LABEL << 12) | 4,
            allocation.base,
            allocation.generation,
            catalog_allocation.identity.allocation_id,
            catalog_allocation.identity.generation,
        );
    if words != 4 || ack_base != allocation.base
        || ack_generation != allocation.generation
        || ack_id != catalog_allocation.identity.allocation_id
        || ack_publication_generation != catalog_allocation.identity.generation
    {
        print_str(b"[win32k-large-pool] missing exact root retirement acknowledgement\n");
        park();
    }
    let mut guard = ProviderMetadataGuard::acquire();
    let Some(catalog) = provider_allocations_unlocked(&mut guard) else { park(); };
    if catalog.retire(catalog_allocation.identity) != Ok(catalog_allocation)
        || !ledger_mut().is_some_and(|ledger|
            ledger.complete_retirement(allocation).is_ok())
    {
        print_str(b"[win32k-large-pool] fatal final retirement commit failure\n");
        park();
    }
    true
}
