//! A process VAD authority must admit image addresses independently of the bounded policy used
//! for private allocations. NT5 mm/creasect.c preserves the PE base in Segment.BasedAddress;
//! mm/mapview.c tries that address before choosing an alternative for a genuine conflict.

use nt_address_space::image_view_placement::{
    plan_image_view_placement, ImageViewPlacement, ImageViewPlacementRequest,
};
use nt_address_space::{
    VmRegionMap, MEM_COMMIT, MEM_RESERVE, PAGE_READONLY, PAGE_READWRITE,
    STATUS_CONFLICTING_ADDRESSES, STATUS_INVALID_PARAMETER_4,
};

const USER_LIMIT: u64 = 0x0000_07ff_ffff_0000;
const PRIVATE_LIMIT: u64 = 0x0000_0100_4000_0000;
const AUTO_FLOOR: u64 = 0x0000_0100_3000_0000;
const PREFERRED: u64 = 0x0000_07ff_b600_0000;
const IMAGE_SIZE: u64 = 0x2b_1000;
const ALLOCATION: u32 = MEM_RESERVE | MEM_COMMIT;

fn occupied_process(upper: u64, low_size: u64) -> VmRegionMap<8> {
    let mut map = VmRegionMap::new(0, upper);
    map.allocate_between(
        Some(AUTO_FLOOR),
        low_size,
        ALLOCATION,
        PAGE_READWRITE,
        0,
        PRIVATE_LIMIT,
    )
    .unwrap();
    map
}

fn request() -> ImageViewPlacementRequest {
    ImageViewPlacementRequest {
        preferred_base: PREFERRED,
        requested_base: None,
        alternate_base: None,
        image_size: IMAGE_SIZE,
        highest_admitted_address: USER_LIMIT - 1,
        zero_bits: 0,
    }
}

fn place(map: &mut VmRegionMap<8>) -> ImageViewPlacement {
    let allocation = match map.allocate_mapped_between(
        Some(PREFERRED),
        IMAGE_SIZE,
        ALLOCATION,
        PAGE_READONLY,
        0,
        USER_LIMIT,
    ) {
        Ok(allocation) => allocation,
        Err(STATUS_CONFLICTING_ADDRESSES) => map
            .allocate_mapped_between(
                None,
                IMAGE_SIZE,
                ALLOCATION,
                PAGE_READONLY,
                AUTO_FLOOR,
                USER_LIMIT,
            )
            .unwrap(),
        Err(status) => panic!("unexpected placement error {status:#x}"),
    };
    plan_image_view_placement(
        ImageViewPlacementRequest {
            alternate_base: Some(allocation.base),
            ..request()
        },
        |base, size| base == allocation.base && size == allocation.size,
    )
    .unwrap()
}

#[test]
fn common_high_preferred_image_is_independent_of_low_allocation_order() {
    let mut parent = occupied_process(USER_LIMIT, 0x22_0000);
    let mut child = occupied_process(USER_LIMIT, 0x18_0000);
    let first = place(&mut parent);
    let second = place(&mut child);
    assert_eq!(first.base, PREFERRED);
    assert_eq!(second, first);
    assert_eq!(first.status, 0);
}

#[test]
fn private_bounded_authority_reproduces_load_order_dependent_image_relocation() {
    let mut parent = occupied_process(PRIVATE_LIMIT, 0x22_0000);
    let mut child = occupied_process(PRIVATE_LIMIT, 0x18_0000);
    let first = place(&mut parent);
    let second = place(&mut child);
    assert_ne!(first.base, PREFERRED);
    assert_ne!(second.base, PREFERRED);
    assert_ne!(first.base, second.base);
    assert_eq!(first.status, 0x4000_0003);
    assert_eq!(second.status, 0x4000_0003);
}

#[test]
fn real_conflict_still_relocates_but_explicit_conflicting_view_does_not() {
    let mut map = occupied_process(USER_LIMIT, 0x18_0000);
    map.allocate_mapped_between(
        Some(PREFERRED),
        IMAGE_SIZE,
        ALLOCATION,
        PAGE_READONLY,
        0,
        USER_LIMIT,
    )
    .unwrap();
    let before = map;
    assert_eq!(
        map.allocate_mapped_between(
            Some(PREFERRED),
            IMAGE_SIZE,
            ALLOCATION,
            PAGE_READONLY,
            0,
            USER_LIMIT
        ),
        Err(STATUS_CONFLICTING_ADDRESSES)
    );
    assert!(
        map == before,
        "rejected explicit conflict must preserve the VAD authority"
    );
    let plan = place(&mut map);
    assert_ne!(plan.base, PREFERRED);
    assert_eq!(plan.status, 0x4000_0003);
}

#[test]
fn wider_vad_authority_does_not_expand_private_policy_or_ignore_zero_bits() {
    let mut map = occupied_process(USER_LIMIT, 0x18_0000);
    let before = map;
    assert_eq!(
        map.allocate_between(
            Some(PREFERRED),
            0x1000,
            ALLOCATION,
            PAGE_READWRITE,
            0,
            PRIVATE_LIMIT
        ),
        Err(STATUS_CONFLICTING_ADDRESSES)
    );
    assert!(
        map == before,
        "private policy rejection must preserve the VAD authority"
    );
    assert_eq!(
        plan_image_view_placement(
            ImageViewPlacementRequest {
                requested_base: Some(PREFERRED),
                zero_bits: 1,
                ..request()
            },
            |_, _| panic!("explicit ZeroBits failure precedes VAD admission")
        ),
        Err(STATUS_INVALID_PARAMETER_4)
    );
    let alternative = map
        .allocate_mapped_between(
            None,
            IMAGE_SIZE,
            ALLOCATION,
            PAGE_READONLY,
            0x1_0000,
            0x8000_0000,
        )
        .unwrap();
    let plan = plan_image_view_placement(
        ImageViewPlacementRequest {
            alternate_base: Some(alternative.base),
            zero_bits: 1,
            ..request()
        },
        |base, size| base == alternative.base && size == alternative.size,
    )
    .unwrap();
    assert_eq!(plan.base, alternative.base);
    assert_eq!(plan.status, 0x4000_0003);
}
