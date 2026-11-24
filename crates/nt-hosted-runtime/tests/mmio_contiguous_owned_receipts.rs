use nt_hosted_runtime::{
    ContiguousRamOwner, ContiguousRamPublishedMapping, MmioRequest, MmioRequestBacking,
    MmioRequestError, MmioRequestLedger, MmioRequestOwner, MmioRequestPhase,
};

const PHYSICAL: u64 = 0x4000_0000;
const VIRTUAL: u64 = 0x7000_0000;
const LENGTH: u64 = 0x2000;
const CHILD: u64 = 81;
const CACHE: u32 = 1;

fn owner() -> ContiguousRamOwner {
    ContiguousRamOwner {
        instance: 6,
        generation: 19,
        domain: 23,
    }
}

fn published() -> ContiguousRamPublishedMapping {
    ContiguousRamPublishedMapping::new(owner(), VIRTUAL, PHYSICAL, LENGTH, CACHE).unwrap()
}

fn map(ledger: &mut MmioRequestLedger) -> nt_hosted_runtime::MmioRequestReceipt {
    let (request, address) = MmioRequest::from_contiguous_published(
        owner(),
        CHILD,
        published(),
        PHYSICAL,
        LENGTH,
        CACHE,
    )
    .unwrap();
    assert_eq!(address, VIRTUAL);
    let receipt = ledger.prepare(request).unwrap();
    ledger
        .complete(
            receipt,
            address,
            MmioRequestBacking::ContiguousOwned { child: CHILD },
        )
        .unwrap();
    receipt
}

#[test]
fn repeated_source_owned_maps_share_va_but_have_distinct_receipts() {
    let mut ledger = MmioRequestLedger::new();
    let first = map(&mut ledger);
    let second = map(&mut ledger);
    assert_ne!(first, second);
    assert_eq!(ledger.live_count(), 2);
    assert!(ledger.has_contiguous_source_rows(owner(), CHILD));

    let authority = MmioRequestOwner::contiguous_owned(owner(), CHILD);
    let (selected, backing) = ledger.begin_unmap(authority, VIRTUAL, LENGTH).unwrap();
    assert_eq!(selected, second);
    assert_eq!(
        backing,
        MmioRequestBacking::ContiguousOwned { child: CHILD }
    );
    ledger.acknowledge_unmap(selected).unwrap();
    assert!(ledger.has_contiguous_source_rows(owner(), CHILD));
    let (selected, _) = ledger.begin_unmap(authority, VIRTUAL, LENGTH).unwrap();
    assert_eq!(selected, first);
    ledger.acknowledge_unmap(selected).unwrap();
    assert!(!ledger.has_contiguous_source_rows(owner(), CHILD));
    assert_eq!(
        ledger.begin_unmap(authority, VIRTUAL, LENGTH),
        Err(MmioRequestError::NotFound)
    );
    assert_eq!(
        published().virtual_address(owner(), PHYSICAL, LENGTH, CACHE),
        Some(VIRTUAL),
        "per-call unmap does not free the source allocation"
    );
}

#[test]
fn source_owned_map_checks_published_owner_cache_range_and_exact_unmap() {
    for (caller, physical, length, cache) in [
        (
            ContiguousRamOwner {
                generation: 20,
                ..owner()
            },
            PHYSICAL,
            LENGTH,
            CACHE,
        ),
        (
            ContiguousRamOwner {
                instance: 7,
                ..owner()
            },
            PHYSICAL,
            LENGTH,
            CACHE,
        ),
        (owner(), PHYSICAL, LENGTH, 0),
        (owner(), PHYSICAL + LENGTH, 1, CACHE),
    ] {
        assert!(MmioRequest::from_contiguous_published(
            caller,
            CHILD,
            published(),
            physical,
            length,
            cache,
        )
        .is_none());
    }
    assert!(MmioRequest::from_contiguous_published(
        owner(),
        0,
        published(),
        PHYSICAL,
        LENGTH,
        CACHE,
    )
    .is_none());

    let mut ledger = MmioRequestLedger::new();
    let receipt = map(&mut ledger);
    for (caller, address, length) in [
        (
            MmioRequestOwner::contiguous_owned(
                ContiguousRamOwner {
                    generation: 20,
                    ..owner()
                },
                CHILD,
            ),
            VIRTUAL,
            LENGTH,
        ),
        (
            MmioRequestOwner::contiguous_owned(owner(), CHILD + 1),
            VIRTUAL,
            LENGTH,
        ),
        (
            MmioRequestOwner::contiguous_owned(owner(), CHILD),
            VIRTUAL + 1,
            LENGTH,
        ),
        (
            MmioRequestOwner::contiguous_owned(owner(), CHILD),
            VIRTUAL,
            LENGTH - 1,
        ),
    ] {
        assert_eq!(
            ledger.begin_unmap(caller, address, length),
            Err(MmioRequestError::NotFound)
        );
        assert_eq!(ledger.phase(receipt), Some(MmioRequestPhase::Ready));
    }
    assert!(ledger
        .complete(
            receipt,
            VIRTUAL,
            MmioRequestBacking::ContiguousOwned { child: CHILD + 1 }
        )
        .is_err());
    let (selected, _) = ledger
        .begin_unmap(
            MmioRequestOwner::contiguous_owned(owner(), CHILD),
            VIRTUAL,
            LENGTH,
        )
        .unwrap();
    ledger.mark_unmap_uncertain(selected).unwrap();
    assert!(ledger.has_contiguous_source_rows(owner(), CHILD));
    assert_eq!(
        ledger.begin_unmap(
            MmioRequestOwner::contiguous_owned(owner(), CHILD),
            VIRTUAL,
            LENGTH
        ),
        Err(MmioRequestError::Unavailable),
    );
}
