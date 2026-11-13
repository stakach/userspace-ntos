use nt_address_space::image_view_placement::{
    plan_image_view_placement, x64_map_view_zero_bits_count, ImageViewPlacementRequest,
};
use nt_address_space::{STATUS_CONFLICTING_ADDRESSES, STATUS_INVALID_PARAMETER_4};

#[test]
fn csrss_shared_section_mask_yields_below_2g_top_down_generic_view() {
    use nt_address_space::{
        VmRegionMap, MEM_COMMIT, MEM_RESERVE, MEM_TOP_DOWN, PAGE_EXECUTE_READWRITE,
    };

    // Pinned LiberNT AMD64 CSRSRV passes 0x7fffffff to NtMapViewOfSection for its
    // anonymous SEC_RESERVE shared Section. It is a bit mask, not 2,147,483,647 bits.
    let count = x64_map_view_zero_bits_count(0x7fff_ffff).unwrap();
    assert_eq!(count, 33);
    let exclusive_limit = (u64::MAX >> count) + 1;
    assert_eq!(exclusive_limit, 0x8000_0000);
    let mut map = VmRegionMap::<4>::new(0x1_0000, 0x0000_0100_4000_0000);
    let view = map
        .allocate_below(
            None,
            0x10_0000,
            MEM_RESERVE | MEM_COMMIT | MEM_TOP_DOWN,
            PAGE_EXECUTE_READWRITE,
            exclusive_limit,
        )
        .unwrap();
    assert!(view.base >= 0x1_0000);
    assert!(view.base + view.size <= exclusive_limit);
    assert_eq!(x64_map_view_zero_bits_count(0), Ok(0));
    assert_eq!(x64_map_view_zero_bits_count(22), Err(STATUS_INVALID_PARAMETER_4));
}

fn request() -> ImageViewPlacementRequest {
    ImageViewPlacementRequest {
        preferred_base: 0x8000_0000,
        requested_base: None,
        alternate_base: Some(0x4000_0000),
        image_size: 0x12345,
        highest_admitted_address: 0x0000_07ff_fffd_ffff,
        zero_bits: 0,
    }
}

#[test]
fn natural_base_is_preferred_and_page_rounded_without_relocation() {
    let plan = plan_image_view_placement(request(), |_, _| true).unwrap();
    assert_eq!(plan.base, 0x8000_0000);
    assert_eq!(plan.size, 0x13000);
    assert_eq!(plan.status, 0);
}

#[test]
fn preferred_conflict_uses_checked_alternative_with_image_not_at_base() {
    let plan = plan_image_view_placement(request(), |base, _| base != 0x8000_0000).unwrap();
    assert_eq!(plan.base, 0x4000_0000);
    assert_eq!(plan.status, 0x4000_0003); // STATUS_IMAGE_NOT_AT_BASE, not synthetic success.
    assert_eq!(plan_image_view_placement(request(), |_, _| false), Err(STATUS_CONFLICTING_ADDRESSES));
}

#[test]
fn requested_base_is_64k_aligned_and_never_silently_replaced() {
    let mut input = request();
    input.requested_base = Some(0x5000_1234);
    let plan = plan_image_view_placement(input, |_, _| true).unwrap();
    assert_eq!(plan.base, 0x5000_0000);
    assert_eq!(plan.status, 0x4000_0003);
    assert_eq!(plan_image_view_placement(input, |_, _| false), Err(STATUS_CONFLICTING_ADDRESSES));
}

#[test]
fn invalid_extent_and_zero_bits_fail_before_conflict_queries() {
    for input in [
        ImageViewPlacementRequest { image_size: 0, ..request() },
        ImageViewPlacementRequest { image_size: u64::MAX, ..request() },
        ImageViewPlacementRequest { requested_base: Some(u64::MAX), ..request() },
    ] {
        assert!(plan_image_view_placement(input, |_, _| panic!("invalid range must not reach placement")).is_err());
    }
    // NT5 amd64 adds 32 to nonzero count arguments below 32, then caps the count at 53.
    let input = ImageViewPlacementRequest { zero_bits: 22, ..request() };
    assert_eq!(plan_image_view_placement(input, |_, _| panic!("invalid ZeroBits must not query ranges")),
        Err(STATUS_INVALID_PARAMETER_4));
    let input = ImageViewPlacementRequest { zero_bits: 21, ..request() };
    assert!(plan_image_view_placement(input, |_, _| true).is_err(),
        "placement must reject both candidates above the ZeroBits ceiling");
}

#[test]
fn x64_zero_bits_mask_constrains_placement_without_becoming_a_count() {
    let input = ImageViewPlacementRequest { zero_bits: 0x7fff_ffff, ..request() };
    let plan = plan_image_view_placement(input, |_, _| true).unwrap();
    assert_eq!(plan.base, 0x4000_0000);
    assert_eq!(plan.status, 0x4000_0003);
}

#[test]
fn explicit_base_above_zero_bits_limit_rejects_before_conflict_query() {
    let input = ImageViewPlacementRequest {
        requested_base: Some(0x8000_0000),
        zero_bits: 0x7fff_ffff,
        ..request()
    };
    assert_eq!(plan_image_view_placement(input, |_, _| panic!("ZeroBits rejection precedes VAD conflict lookup")),
        Err(STATUS_INVALID_PARAMETER_4));
}
