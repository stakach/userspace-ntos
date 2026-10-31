use nt_kernel_exec::luid::LocalLuidAllocator;

#[test]
fn allocated_luids_share_one_monotonic_namespace() {
    let allocator = LocalLuidAllocator::new(0x3e9);
    assert_eq!(allocator.allocate(), Some(0x3e9));
    assert_eq!(allocator.allocate(), Some(0x3ea));
}

#[test]
fn exhausted_namespace_does_not_wrap_or_reissue() {
    let allocator = LocalLuidAllocator::new(u64::MAX - 1);
    assert_eq!(allocator.allocate(), Some(u64::MAX - 1));
    assert_eq!(allocator.allocate(), None);
    assert_eq!(allocator.allocate(), None);
}
