//! Processor count and mask must describe the same boot topology to PCI.

use nt_kernel_exec::processor_topology::{active_processor_count_for_group, active_processor_mask, processor_number_for_index};

#[test]
fn local_processor_requires_exact_boot_apic_identity() {
    use nt_kernel_exec::processor_topology::local_processor_index;
    assert_eq!(local_processor_index(4, 0, 7, 7), Some(0));
    assert_eq!(local_processor_index(4, 2, 21, 21), Some(2));
    assert_eq!(local_processor_index(4, 0, 7, 8), None);
    assert_eq!(local_processor_index(4, 4, 7, 7), None);
    assert_eq!(local_processor_index(65, 64, 7, 7), None);
    assert_eq!(local_processor_index(u64::MAX, u32::MAX as u64 + 1, 7, 7), None);
}

#[test]
fn processor_index_projects_only_installed_group_zero_cpus() {
    assert_eq!(processor_number_for_index(1, 0), Some(0));
    assert_eq!(processor_number_for_index(2, 1), Some(1 << 16));
    assert_eq!(processor_number_for_index(2, 2), None);
    assert_eq!(processor_number_for_index(0, 0), None);
}

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
