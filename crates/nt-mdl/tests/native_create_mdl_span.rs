use nt_mdl::create_mdl::mdl_size_for_range;

#[test]
fn x64_mdl_header_reserves_every_spanned_pfn() {
    assert_eq!(mdl_size_for_range(0x1000, 4096), Some(56));
    assert_eq!(mdl_size_for_range(0x1fff, 2), Some(64));
    assert_eq!(mdl_size_for_range(0, 0), Some(48));
    assert_eq!(mdl_size_for_range(u64::MAX, 2), None);
    assert_eq!(mdl_size_for_range(0, u64::from(u32::MAX) + 1), None);
    assert_eq!(mdl_size_for_range(0, 4096 * 4090), None);
}
