use nt_hosted_runtime::{
    MmioRequest, MmioRequestAuthority, MmioRequestBacking, MmioRequestError, MmioRequestLedger, MmioRequestOwner,
    PoolOwnedRamSource,
};
use nt_pnp_context::ContextRegistry;

const PHYSICAL_PAGE: u64 = 0x1_11bf_5000;
const POOL_VA: u64 = 0x7000_0000;
const ALLOCATION: u64 = POOL_VA + 0xff0;
const RSDP_PHYSICAL: u64 = PHYSICAL_PAGE + 0xff0;
const RSDP_LENGTH: u64 = 36;
const CAP_BASE: u64 = 500;
const WB: u32 = 1;
const UC: u32 = 0;

fn source() -> PoolOwnedRamSource {
    PoolOwnedRamSource {
        instance: 6,
        domain_id: 23,
        domain_cookie: 29,
        pool_va_base: POOL_VA,
        pool_cap_base: CAP_BASE,
        pool_frames: 4,
        allocation_base: ALLOCATION,
        allocation_capacity: 0x40,
        allocation_generation: 19,
    }
}

fn cap_paddr(cap: u64) -> Option<u64> {
    (CAP_BASE..CAP_BASE + 4)
        .contains(&cap)
        .then_some(PHYSICAL_PAGE + (cap - CAP_BASE) * 0x1000)
}

fn request() -> (MmioRequest, u64) {
    MmioRequest::from_pool_owned(
        source(), source().owner(), RSDP_PHYSICAL, RSDP_LENGTH, UC, WB, cap_paddr,
    )
    .expect("live root cap and allocation must project the existing WB pool VA")
}

fn backing() -> MmioRequestBacking {
    MmioRequestBacking::PoolOwned {
        allocation_base: ALLOCATION,
        allocation_generation: 19,
        effective_cache: WB,
    }
}

fn protected(ledger: &MmioRequestLedger, source: PoolOwnedRamSource) -> bool {
    ledger.has_pool_source_rows(source.pool_cap_base, source.allocation_base,
        source.allocation_capacity)
}

#[test]
fn source_pool_projection_checks_every_cap_page_allocation_extent_and_identity() {
    let (mapped, va) = request();
    assert_eq!(va, ALLOCATION);
    assert_eq!(mapped.cache, UC, "retain the guest's requested cache type");
    assert_eq!(mapped.owner, source().owner());

    let forged_first_cap = |cap| cap_paddr(cap).map(|paddr| {
        if cap == CAP_BASE { paddr + 0x4000 } else { paddr }
    });
    let forged_second_cap = |cap| cap_paddr(cap).map(|paddr| {
        if cap == CAP_BASE + 1 { paddr + 0x4000 } else { paddr }
    });
    assert!(source().project(RSDP_PHYSICAL, RSDP_LENGTH, forged_first_cap).is_none());
    assert!(source().project(RSDP_PHYSICAL, RSDP_LENGTH, forged_second_cap).is_none());
    assert!(source().project(RSDP_PHYSICAL, RSDP_LENGTH, |cap| {
        if cap == CAP_BASE + 1 { None } else { cap_paddr(cap) }
    }).is_none());
    assert!(source().project(RSDP_PHYSICAL, 0x41, cap_paddr).is_none());
    assert!(source().project(RSDP_PHYSICAL, 0, cap_paddr).is_none());
    assert!(source().project(u64::MAX - 1, 4, cap_paddr).is_none());

    for foreign in [
        MmioRequestOwner { domain_cookie: 30, ..source().owner() },
        MmioRequestOwner { domain_id: 24, ..source().owner() },
        PoolOwnedRamSource { instance: 7, ..source() }.owner(),
        PoolOwnedRamSource { pool_cap_base: CAP_BASE + 4, ..source() }.owner(),
        PoolOwnedRamSource { allocation_generation: 20, ..source() }.owner(),
    ] {
        assert!(MmioRequest::from_pool_owned(
            source(), foreign, RSDP_PHYSICAL, RSDP_LENGTH, UC, WB, cap_paddr,
        ).is_none(), "foreign or stale owner cannot borrow this pool source");
    }
    assert!(MmioRequest::from_pool_owned(
        source(), source().owner(), RSDP_PHYSICAL, RSDP_LENGTH, 2, WB, cap_paddr,
    ).is_none(), "unproved WC request cannot borrow a WB pool mapping");
    assert!(MmioRequest::from_pool_owned(
        source(), source().owner(), RSDP_PHYSICAL, RSDP_LENGTH, UC, UC, cap_paddr,
    ).is_none(), "a requested UC cache cannot change the effective WB mapping");
}

#[test]
fn duplicate_maps_share_existing_wb_va_but_own_independent_receipts() {
    let mut ledger = MmioRequestLedger::new();
    let (request, va) = request();
    let first = ledger.prepare(request).unwrap();
    ledger.complete(first, va, backing()).unwrap();
    let second = ledger.prepare(request).unwrap();
    ledger.complete(second, va, backing()).unwrap();
    assert_ne!(first, second);
    assert!(protected(&ledger, source()));
    assert!(ledger.has_pool_cap_rows(CAP_BASE));
    assert_eq!(ledger.live_count(), 2);
    let rows: Vec<_> = ledger.owner_rows(source().owner()).collect();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|(request, _, row_backing, _)|
        request.cache == UC && *row_backing == Some(backing())));

    assert_eq!(ledger.begin_unmap(
        MmioRequestOwner { domain_cookie: 30, ..source().owner() }, va, RSDP_LENGTH,
    ), Err(MmioRequestError::NotFound));
    assert_eq!(ledger.begin_unmap(source().owner(), va, RSDP_LENGTH - 1),
        Err(MmioRequestError::NotFound));
    let (receipt, returned) = ledger.begin_unmap(source().owner(), va, RSDP_LENGTH).unwrap();
    assert_eq!((receipt, returned), (second, backing()));
    ledger.acknowledge_unmap(receipt).unwrap();
    assert_eq!(ledger.live_count(), 1);
    assert!(protected(&ledger, source()));
    let (receipt, _) = ledger.begin_unmap(source().owner(), va, RSDP_LENGTH).unwrap();
    assert_eq!(receipt, first);
    ledger.acknowledge_unmap(receipt).unwrap();
    assert!(!protected(&ledger, source()));
    assert!(!ledger.has_pool_cap_rows(CAP_BASE));
    assert_eq!(ledger.begin_unmap(source().owner(), va, RSDP_LENGTH),
        Err(MmioRequestError::NotFound));
}

#[test]
fn unresolved_map_or_unmap_fences_free_and_reuse_even_after_generation_changes() {
    let mut ledger = MmioRequestLedger::new();
    let (request, va) = request();
    let pending = ledger.prepare(request).unwrap();
    assert!(protected(&ledger, source()));
    ledger.mark_map_uncertain(pending).unwrap();
    assert!(ledger.has_pool_cap_rows(CAP_BASE));
    assert!(protected(&ledger, PoolOwnedRamSource {
        allocation_generation: 20, ..source()
    }));
    assert_eq!(ledger.prepare(request), Err(MmioRequestError::Unavailable));

    let mut ledger = MmioRequestLedger::new();
    let ready = ledger.prepare(request).unwrap();
    ledger.complete(ready, va, backing()).unwrap();
    let (receipt, _) = ledger.begin_unmap(source().owner(), va, RSDP_LENGTH).unwrap();
    ledger.mark_unmap_uncertain(receipt).unwrap();
    assert!(ledger.has_pool_cap_rows(CAP_BASE));
    assert!(protected(&ledger, source()));
    assert_eq!(ledger.begin_unmap(source().owner(), va, RSDP_LENGTH),
        Err(MmioRequestError::Unavailable));
}

#[test]
fn pool_and_assigned_pnp_maps_keep_distinct_authority_in_one_ledger() {
    let mut registry = ContextRegistry::new();
    registry.publish((), ()).unwrap();
    let lease = registry.acquire_active().unwrap().identity();
    let pnp_owner = MmioRequestOwner {
        domain_id: source().domain_id,
        domain_cookie: source().domain_cookie,
        authority: MmioRequestAuthority::Pnp { device_id: 93, context_lease: lease },
    };
    let mut ledger = MmioRequestLedger::new();
    let (pool_request, pool_va) = request();
    let pool_receipt = ledger.prepare(pool_request).unwrap();
    ledger.complete(pool_receipt, pool_va, backing()).unwrap();
    let pnp_request = MmioRequest {
        owner: pnp_owner, physical_start: 0xe000_0000, length: 0x1000, cache: UC,
    };
    let pnp_receipt = ledger.prepare(pnp_request).unwrap();
    ledger.complete(pnp_receipt, 0x8000_0000,
        MmioRequestBacking::Assigned { resource_id: 70, mapping_id: 71 }).unwrap();

    assert_eq!(ledger.begin_unmap(pnp_owner, pool_va, RSDP_LENGTH),
        Err(MmioRequestError::NotFound));
    let (pnp, assigned) = ledger.begin_unmap(pnp_owner, 0x8000_0000, 0x1000).unwrap();
    assert_eq!(pnp, pnp_receipt);
    assert_eq!(assigned, MmioRequestBacking::Assigned { resource_id: 70, mapping_id: 71 });
    ledger.acknowledge_unmap(pnp).unwrap();
    assert!(protected(&ledger, source()));

    let (pool, owned) = ledger.begin_unmap(source().owner(), pool_va, RSDP_LENGTH).unwrap();
    assert_eq!((pool, owned), (pool_receipt, backing()));
    ledger.acknowledge_unmap(pool).unwrap();
    assert!(!protected(&ledger, source()));
}
