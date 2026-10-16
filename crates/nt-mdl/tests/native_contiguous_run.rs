use nt_mdl::contiguous::validate_page_run;

#[test]
fn admits_only_exact_physical_adjacency_and_constraints() {
    assert_eq!(validate_page_run(&[0x2000, 0x3000], 0x1000, 0x4fff, 0), Some((0x2000, 0x3fff)));
    assert_eq!(validate_page_run(&[0x2000, 0x4000], 0, u64::MAX, 0), None);
    assert_eq!(validate_page_run(&[0x2000, 0x3000], 0x3000, u64::MAX, 0), None);
    assert_eq!(validate_page_run(&[0x2000, 0x3000], 0, 0x3ffe, 0), None);
    assert_eq!(validate_page_run(&[0x2000, 0x3000], 0, u64::MAX, 0x3000), None);
    assert_eq!(validate_page_run(&[0x2000, 0x3000], 0, u64::MAX, 0x1800), None);
    assert_eq!(validate_page_run(&[0x2000, 0x3000], 0, u64::MAX, 0x4000), Some((0x2000, 0x3fff)));
    assert_eq!(validate_page_run(&[], 0, u64::MAX, 0), None);
}
