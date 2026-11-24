//! Exercises the production source-owned native receipt adapter. A published contiguous source
//! returns one VA for repeated maps, while each call retains an independent unmap obligation.

#[path = "../../../components/ntos-executive/src/hosted_contiguous_owned_requests.rs"]
mod hosted_contiguous_owned_requests;

use hosted_contiguous_owned_requests::HostedContiguousOwnedRequests;
use nt_hosted_runtime::{ContiguousRamOwner, ContiguousRamPublishedMapping, MmioRequestError};

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

#[test]
fn duplicate_source_owned_maps_retire_one_receipt_per_exact_unmap() {
    let mut requests = HostedContiguousOwnedRequests::new();
    assert_eq!(
        requests.map(owner(), CHILD, published(), PHYSICAL, LENGTH, CACHE),
        Ok(VIRTUAL)
    );
    assert_eq!(
        requests.map(owner(), CHILD, published(), PHYSICAL, LENGTH, CACHE),
        Ok(VIRTUAL)
    );
    assert!(requests.has_source_rows(owner(), CHILD));

    assert_eq!(
        requests.unmap(owner(), CHILD, VIRTUAL, LENGTH - 1),
        Err(MmioRequestError::NotFound)
    );
    assert_eq!(
        requests.unmap(
            ContiguousRamOwner {
                generation: 20,
                ..owner()
            },
            CHILD,
            VIRTUAL,
            LENGTH
        ),
        Err(MmioRequestError::NotFound)
    );
    assert_eq!(
        requests.unmap(owner(), CHILD + 1, VIRTUAL, LENGTH),
        Err(MmioRequestError::NotFound)
    );
    assert!(requests.has_source_rows(owner(), CHILD));

    assert_eq!(requests.unmap(owner(), CHILD, VIRTUAL, LENGTH), Ok(()));
    assert!(requests.has_source_rows(owner(), CHILD));
    assert_eq!(requests.unmap(owner(), CHILD, VIRTUAL, LENGTH), Ok(()));
    assert!(!requests.has_source_rows(owner(), CHILD));
    assert_eq!(
        requests.unmap(owner(), CHILD, VIRTUAL, LENGTH),
        Err(MmioRequestError::NotFound)
    );
    assert_eq!(
        published().virtual_address(owner(), PHYSICAL, LENGTH, CACHE),
        Some(VIRTUAL),
        "retiring a request must leave the source allocation published"
    );
}

#[test]
fn source_owned_map_requires_exact_published_grant() {
    let mut requests = HostedContiguousOwnedRequests::new();
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
        (owner(), PHYSICAL, LENGTH, 0),
        (owner(), PHYSICAL + LENGTH, 1, CACHE),
    ] {
        assert_eq!(
            requests.map(caller, CHILD, published(), physical, length, cache),
            Err(MmioRequestError::InvalidRequest)
        );
    }
    assert!(!requests.has_source_rows(owner(), CHILD));
}
