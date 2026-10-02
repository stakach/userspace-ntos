//! Authenticated private component heap reservations and owned demand mappings.

use crate::*;
use alloc::{boxed::Box, vec::Vec};
use crate::spawn_hosts::shared_ingress::owner::runtime::{PhysicalDomain, PhysicalSource, PhysicalSourceKind};
use nt_memory_manager::component_heap::{HeapOwnerLedger, HeapPageState, HeapReservation};

struct Page { state: HeapPageState, cap: u64 }
struct Worker { source: PhysicalSource, verify: unsafe fn(PhysicalSource) -> bool }
struct Heap {
    primary: u64,
    pml4: u64,
    bank: u16,
    retiring: bool,
    committed_frames: u64,
    reservation: HeapReservation,
    ledger: Option<HeapOwnerLedger<PhysicalDomain, PhysicalSource>>,
    workers: Vec<Worker>,
    pages: Vec<Page>,
}
static mut HEAPS: Vec<Box<Heap>> = Vec::new();

pub(crate) unsafe fn stage(primary: u64, pml4: u64, bank: u16, region: &spawn_hosts::Region) {
    let spawn_hosts::FrameSource::DemandZeroed { initial_frames } = region.source else { return; };
    let _durable = allocator::enter_durable();
    assert_eq!(region.base_va, allocator::HEAP_BASE as u64);
    assert!(region.count <= allocator::HEAP_FRAMES);
    assert!(matches!(region.rights, spawn_hosts::Rights::Uniform(rights) if rights == RW_NX));
    let reservation = HeapReservation::new(region.base_va, initial_frames, region.count, true)
        .expect("valid component heap reservation");
    let mut pages = Vec::new();
    pages.try_reserve_exact(region.count as usize).expect("heap mapping ownership capacity");
    for index in 0..region.count {
        pages.push(Page { state: if index < initial_frames { HeapPageState::Mapped }
            else { HeapPageState::Uncommitted }, cap: 0 });
    }
    let heaps = &mut *core::ptr::addr_of_mut!(HEAPS);
    assert!(!heaps.iter().any(|heap| heap.pml4 == pml4 || heap.bank == bank));
    heaps.push(Box::new(Heap { primary, pml4, bank, retiring: false,
        committed_frames: initial_frames, reservation, ledger: None,
        workers: Vec::new(), pages }));
    print_str(b"[component-heap] initial-frames="); print_u64(initial_frames);
    print_str(b" reserved-frames="); print_u64(region.count); print_str(b"\n");
}

pub(crate) unsafe fn bind_source(source: PhysicalSource, verify: unsafe fn(PhysicalSource) -> bool) -> Result<(), ()> {
    let _durable = allocator::enter_durable();
    let Some(heap) = (&mut *core::ptr::addr_of_mut!(HEAPS)).iter_mut()
        .find(|heap| heap.pml4 == source.pml4) else { return Ok(()); };
    if heap.retiring || !(verify)(source) { return Err(()); }
    if heap.ledger.is_none() {
        if source.tcb != heap.primary || !matches!(source.kind, PhysicalSourceKind::Primary) {
            return Err(());
        }
        heap.ledger = Some(HeapOwnerLedger::new(source.domain, source.pml4));
    }
    heap.workers.try_reserve(1).map_err(|_| ())?;
    heap.ledger.as_mut().unwrap().bind_worker(source.domain, source, source.pml4).map_err(|_| ())?;
    if !heap.workers.iter().any(|worker| worker.source == source) {
        heap.workers.push(Worker { source, verify });
    }
    Ok(())
}

pub(crate) unsafe fn retire_source(source: PhysicalSource) -> Result<(), ()> {
    for heap in (&mut *core::ptr::addr_of_mut!(HEAPS)).iter_mut() {
        if !heap.workers.iter().any(|worker| worker.source == source) { continue; }
        if !heap.ledger.as_mut().is_some_and(|ledger| ledger.retire_worker(source.domain, source)) {
            return Err(());
        }
        heap.workers.retain(|worker| worker.source != source);
    }
    Ok(())
}

pub(crate) unsafe fn release_bank(bank: u16) -> bool {
    let heaps = &mut *core::ptr::addr_of_mut!(HEAPS);
    let Some(index) = heaps.iter().position(|heap| heap.bank == bank) else { return true; };
    let heap = &mut heaps[index];
    if heap.ledger.as_ref().is_some_and(|ledger| ledger.has_workers())
        || heap.pages.iter().any(|page| matches!(page.state, HeapPageState::Entered | HeapPageState::Indeterminate)) {
        return false;
    }
    heap.retiring = true;
    if let Some(ledger) = heap.ledger.as_mut() { ledger.retire_owner(); }
    // Keep the reservation until native bank teardown has positively completed.
    true
}

pub(crate) unsafe fn bank_released(bank: u16) {
    let heaps = &mut *core::ptr::addr_of_mut!(HEAPS);
    if let Some(index) = heaps.iter().position(|heap| heap.bank == bank) { heaps.swap_remove(index); }
}

/// Some(false) refuses every unauthorized heap-band fault rather than generic zero-filling it.
pub(crate) unsafe fn service_fault(channel: &spawn_hosts::PumpChannel, address: u64, fsr: u64) -> Option<bool> {
    let base = allocator::HEAP_BASE as u64;
    if address < base || address >= base + allocator::HEAP_FRAMES * 0x1000 { return None; }
    let Some(heap) = (&mut *core::ptr::addr_of_mut!(HEAPS)).iter_mut()
        .find(|heap| heap.pml4 == channel.pml4 && heap.bank == channel.root_image_map_owner)
        else { return Some(false); };
    if heap.retiring { return Some(false); }
    let Some(worker) = heap.workers.iter().find(|worker| worker.source.tcb == channel.tcb) else { return Some(false); };
    if !(worker.verify)(worker.source) || !heap.ledger.as_ref().is_some_and(|ledger|
        ledger.authorize(worker.source.domain, worker.source, channel.pml4)) { return Some(false); }
    let Ok(index) = heap.reservation.fault_page(address, fsr) else { return Some(false); };
    let page = &mut heap.pages[index as usize];
    if page.state.acknowledge_queued_fault() && page.cap != 0 {
        return Some(true);
    }
    if page.state != HeapPageState::Uncommitted { return Some(false); }
    let Some(cap) = try_alloc_slot() else { return Some(false); };
    page.cap = cap;
    assert!(page.state.begin());
    if !spawn_hosts::component_map_cap_bank_tag(heap.bank, cap) {
        page.state.complete(false);
        return Some(false);
    }
    let retyped = untyped_retype_r(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, cap);
    let mapped = retyped == 0 && page_map_r(cap, base + index * 0x1000, RW_NX, heap.pml4) == 0;
    page.state.complete(mapped);
    if mapped {
        heap.committed_frames += 1;
        let added = heap.committed_frames - heap.reservation.initial_frames();
        if added <= 4 || added % 128 == 0 {
            print_str(b"[component-heap-commit] bank="); print_u64(heap.bank as u64);
            print_str(b" owner-tcb="); print_u64(heap.primary);
            print_str(b" page="); print_u64(index);
            print_str(b" frame="); print_u64(cap);
            print_str(b" initial="); print_u64(heap.reservation.initial_frames());
            print_str(b" reserved="); print_u64(heap.reservation.reserved_frames());
            print_str(b" committed="); print_u64(heap.committed_frames); print_str(b"\n");
        }
    }
    Some(mapped)
}
