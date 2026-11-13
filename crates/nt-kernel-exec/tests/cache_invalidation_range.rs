use nt_kernel_exec::cache_invalidation::cache_lines;

#[test]
fn line_walk_covers_each_touched_line_once_and_rejects_overflow() {
    assert_eq!(cache_lines(0x103f, 2, 64).unwrap().collect::<Vec<_>>(), vec![0x1000, 0x1040]);
    assert_eq!(cache_lines(0x1040, 64, 64).unwrap().collect::<Vec<_>>(), vec![0x1040]);
    assert_eq!(cache_lines(0x1040, 0, 64).unwrap().collect::<Vec<_>>(), vec![]);
    assert!(cache_lines(u64::MAX - 1, 4, 64).is_none());
    assert!(cache_lines(0x1000, 1, 0).is_none());
    assert!(cache_lines(0x1000, 1, 48).is_none());
}
