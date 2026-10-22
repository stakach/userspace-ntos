//! Processor count and mask must describe the same boot topology to PCI.

use nt_kernel_exec::processor_topology::{active_processor_count_for_group, active_processor_mask};

#[test]
fn group_zero_and_all_groups_project_exact_active_count() {
    for count in [1u32, 4, 64] {
        assert_eq!(active_processor_count_for_group(u64::from(count), 0), count);
        assert_eq!(active_processor_count_for_group(u64::from(count), u16::MAX), count);
        assert_eq!(active_processor_count_for_group(u64::from(count), 1), 0);
        assert_eq!(active_processor_mask(u64::from(count)).count_ones(), count);
    }
}

#[test]
fn unavailable_boot_count_is_one_processor_not_zero() {
    assert_eq!(active_processor_count_for_group(0, 0), 1);
    assert_eq!(active_processor_mask(0), 1);
}
