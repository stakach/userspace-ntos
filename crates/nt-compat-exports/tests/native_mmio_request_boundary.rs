//! Exercise the native MmMapIoSpace/MmUnmapIoSpace bodies with a fake root transport.
//! The pregranted VA is deliberately the same for both calls: it is not a request receipt.

use std::cell::{Cell, RefCell};
use std::ptr::write_volatile;
use std::sync::atomic::{AtomicU64, Ordering};

const PHYS: u64 = 0xe000_1000;
const LEN: u64 = 0x1000;
const VA: u64 = 0x7000_1000;
const CONTIG_PHYS: u64 = 0x2000_0000;
const CONTIG_VA: u64 = 0x6000_0000;
const SH_RESOURCE_ADDRESS_KIND_MEMORY: u8 = 1;
const SH_RESOURCE_MMIO_MAPPED_PHYS: u64 = 0x3c8;
const SH_RESOURCE_MMIO_MAPPED_LEN: u64 = 0x3d0;
const FSD_SERVICE_GOP_QUERY_LABEL: u64 = 42;
const FSD_SHARED_VADDR: u64 = 0;
const MM_NON_CACHED: u32 = 0;
const MM_CACHED: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PhysicalOwner {
    domain: u64,
    generation: u64,
    device: u64,
}

const OWNER_A: PhysicalOwner = PhysicalOwner {
    domain: 7,
    generation: 11,
    device: 23,
};

#[derive(Clone, Copy)]
struct SharedAddressResource {
    va: u64,
    map_len: u64,
    len: u64,
    translated_start: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootCall {
    Map {
        physical: u64,
        length: u64,
        cache: u32,
    },
    Unmap {
        base: u64,
        length: u64,
    },
}

#[derive(Default)]
struct FakeRoot {
    calls: Vec<RootCall>,
    live: Vec<(PhysicalOwner, u64)>, // (authenticated owner, per-call receipt)
    next_receipt: u64,
}

thread_local! {
    static SHARED: RefCell<Box<[u64; 128]>> = RefCell::new(Box::new([0; 128]));
    static ROOT: RefCell<FakeRoot> = RefCell::new(FakeRoot::default());
    static OWNER: Cell<PhysicalOwner> = const { Cell::new(OWNER_A) };
    static ASSIGNED_GRANT: Cell<bool> = const { Cell::new(true) };
}

fn reset() {
    SHARED.with(|bank| bank.borrow_mut().fill(0));
    ROOT.with(|root| *root.borrow_mut() = FakeRoot::default());
    OWNER.with(|owner| owner.set(OWNER_A));
    ASSIGNED_GRANT.with(|grant| grant.set(true));
}

fn shared_va() -> u64 {
    SHARED.with(|bank| bank.borrow().as_ptr() as u64)
}

fn root_calls() -> Vec<RootCall> {
    ROOT.with(|root| root.borrow().calls.clone())
}

fn live_receipts() -> Vec<(PhysicalOwner, u64)> {
    ROOT.with(|root| root.borrow().live.clone())
}

fn print_str(_: &[u8]) {}
fn print_hex64(_: u64) {}
fn print_u64(_: u64) {}

unsafe fn hosted_component_resource_shared_va() -> u64 {
    shared_va()
}

unsafe fn hosted_component_virtual_address(physical: u64, length: u64) -> Option<u64> {
    (physical == PHYS && length == LEN).then_some(VA)
}

unsafe fn find_shared_address_resource_by_range(
    _: u64,
    _: u8,
    physical: u64,
    length: u64,
    _: bool,
) -> Option<SharedAddressResource> {
    (ASSIGNED_GRANT.with(Cell::get) && physical == PHYS && length == LEN)
        .then_some(SharedAddressResource {
        va: VA,
        map_len: LEN,
        len: LEN,
        translated_start: PHYS,
    })
}

unsafe fn find_shared_address_resource_by_va(
    _: u64,
    base: u64,
    length: u64,
) -> Option<SharedAddressResource> {
    (base == VA && length <= LEN).then_some(SharedAddressResource {
        va: VA,
        map_len: LEN,
        len: LEN,
        translated_start: PHYS,
    })
}

// The production boundary may choose a primary physical Call or an IRQ-lane arena service.
// This fake supplies the common request effect without prescribing either IPC encoding.
fn submit_mmio_map_request(physical: u64, length: u64, cache: u32) -> Option<u64> {
    ROOT.with(|root| {
        let mut root = root.borrow_mut();
        root.calls.push(RootCall::Map {
            physical,
            length,
            cache,
        });
        let owner = OWNER.with(Cell::get);
        if physical == PHYS && length == LEN && cache == MM_NON_CACHED {
            root.next_receipt += 1;
            let receipt = root.next_receipt;
            root.live.push((owner, receipt));
            return Some(VA);
        }
        None
    })
}

fn submit_mmio_unmap_request(base: u64, length: u64) -> bool {
    ROOT.with(|root| {
        let mut root = root.borrow_mut();
        root.calls.push(RootCall::Unmap { base, length });
        let owner = OWNER.with(Cell::get);
        if base == VA && length == LEN {
            if let Some(index) = root
                .live
                .iter()
                .rposition(|(mapped_owner, _)| *mapped_owner == owner)
            {
                root.live.remove(index);
                return true;
            }
        }
        false
    })
}

fn call_on4_raw(_: u64, _: u64, _: u64, _: u64, _: u64) -> (u64, u64, u64, u64, u64) {
    (0, 0, 0, 0, 0)
}

mod hosted_driver_contiguous_memory {
    pub fn map_physical(physical: u64, length: u64, cache: u32) -> Option<u64> {
        (physical == super::CONTIG_PHYS
            && length == super::LEN
            && cache == super::MM_CACHED)
            .then_some(super::CONTIG_VA)
    }
    pub fn unmap_physical(base: u64, length: u64) -> bool {
        base == super::CONTIG_VA && length == super::LEN
    }
}

#[test]
fn cached_contiguous_ram_keeps_its_distinct_cache_policy() {
    reset();
    assert_eq!(hosted_mmio_request::map_io_space(CONTIG_PHYS, LEN, MM_CACHED), CONTIG_VA);
    assert!(root_calls().is_empty());
    hosted_mmio_request::unmap_io_space(CONTIG_VA, LEN);
    assert!(root_calls().is_empty());
}

#[test]
fn unassigned_gop_fallback_uses_the_same_per_call_root_request_path() {
    reset();
    ASSIGNED_GRANT.with(|grant| grant.set(false));
    assert_eq!(hosted_mmio_request::map_io_space(PHYS, LEN, MM_NON_CACHED), VA);
    assert_eq!(hosted_mmio_request::map_io_space(PHYS, LEN, MM_NON_CACHED), VA);
    assert_eq!(live_receipts().len(), 2);
    hosted_mmio_request::unmap_io_space(VA, LEN);
    assert_eq!(live_receipts().len(), 1);
    hosted_mmio_request::unmap_io_space(VA, LEN);
    assert!(live_receipts().is_empty());
}

mod hosted_provider_export_lane {
    pub fn current_component_bank() -> Option<u64> {
        Some(super::shared_va())
    }
}

mod hosted_class_irp_lane {
    pub fn current_component_bank() -> Option<u64> {
        Some(super::shared_va())
    }
}

#[path = "../../../components/ntos-executive/src/hosted_mmio_request.rs"]
mod hosted_mmio_request;

#[test]
fn identical_grant_maps_are_independent_root_requests_with_the_requested_cache() {
    reset();
    assert_eq!(
        hosted_mmio_request::map_io_space(PHYS, LEN, MM_NON_CACHED),
        VA
    );
    assert_eq!(
        hosted_mmio_request::map_io_space(PHYS, LEN, MM_NON_CACHED),
        VA
    );

    let calls = root_calls();
    assert_eq!(
        calls.len(),
        2,
        "two returned VAs require two retained root requests"
    );
    assert_eq!(
        calls,
        vec![
            RootCall::Map {
                physical: PHYS,
                length: LEN,
                cache: MM_NON_CACHED
            },
            RootCall::Map {
                physical: PHYS,
                length: LEN,
                cache: MM_NON_CACHED
            },
        ]
    );
    let live = live_receipts();
    assert_eq!(live.len(), 2);
    assert_ne!(
        live[0].1, live[1].1,
        "an identical VA is not an identical request receipt"
    );
}

#[test]
fn wrong_owner_length_and_duplicate_unmap_do_not_retire_another_request() {
    reset();
    assert_eq!(
        hosted_mmio_request::map_io_space(PHYS, LEN, MM_NON_CACHED),
        VA
    );
    assert_eq!(
        hosted_mmio_request::map_io_space(PHYS, LEN, MM_NON_CACHED),
        VA
    );
    assert_eq!(live_receipts().len(), 2);

    hosted_mmio_request::unmap_io_space(VA, LEN - 1);
    assert_eq!(
        live_receipts().len(),
        2,
        "wrong length cannot release either map"
    );
    for wrong_owner in [
        PhysicalOwner {
            generation: 12,
            ..OWNER_A
        },
        PhysicalOwner {
            domain: 8,
            ..OWNER_A
        },
        PhysicalOwner {
            device: 24,
            ..OWNER_A
        },
    ] {
        OWNER.with(|owner| owner.set(wrong_owner));
        hosted_mmio_request::unmap_io_space(VA, LEN);
        assert_eq!(
            live_receipts().len(),
            2,
            "another physical domain, generation, or device cannot release either map"
        );
    }
    OWNER.with(|owner| owner.set(OWNER_A));
    hosted_mmio_request::unmap_io_space(VA, LEN);
    assert_eq!(
        live_receipts().len(),
        1,
        "one exact unmap releases only one request"
    );
    hosted_mmio_request::unmap_io_space(VA, LEN);
    assert!(live_receipts().is_empty());
    hosted_mmio_request::unmap_io_space(VA, LEN);
    assert!(
        live_receipts().is_empty(),
        "stale third unmap cannot replay an effect"
    );
}

#[test]
fn unsupported_cache_does_not_return_a_pregranted_va_or_create_a_request() {
    reset();
    assert_eq!(hosted_mmio_request::map_io_space(PHYS, LEN, 77), 0);
    assert!(live_receipts().is_empty());
    assert!(root_calls().is_empty());
}
