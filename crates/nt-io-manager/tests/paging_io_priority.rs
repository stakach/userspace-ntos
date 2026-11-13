//! Paging priority is derived from the exact IRP flags used by classpnp.sys.

use nt_io_manager::io_paging_priority::{paging_io_priority, IoPagingPriority};

#[test]
fn class_cache_operation_takes_priority_over_ordinary_paging() {
    assert_eq!(paging_io_priority(0x0000_8000), IoPagingPriority::High);
    assert_eq!(paging_io_priority(0x0000_8002), IoPagingPriority::High);
    assert_eq!(paging_io_priority(0x0000_0002), IoPagingPriority::Normal);
    assert_eq!(paging_io_priority(0), IoPagingPriority::Invalid);
    assert_eq!(paging_io_priority(0x0000_0100), IoPagingPriority::Invalid);
}

#[test]
fn priority_values_match_the_native_enum() {
    assert_eq!(IoPagingPriority::Invalid as u32, 0);
    assert_eq!(IoPagingPriority::Normal as u32, 1);
    assert_eq!(IoPagingPriority::High as u32, 2);
}
