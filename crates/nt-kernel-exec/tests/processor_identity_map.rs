use nt_kernel_exec::processor_topology::{ProcessorIdentityError, ProcessorIdentityMap};

#[test]
fn every_explicit_apic_identity_maps_to_its_logical_core() {
    let map = ProcessorIdentityMap::new(&[7, 42, u32::MAX]).unwrap();
    assert_eq!(map.count(), 3);
    assert_eq!(map.logical_index(7), Some(0));
    assert_eq!(map.logical_index(42), Some(1));
    assert_eq!(map.logical_index(u32::MAX), Some(2));
    assert_eq!(map.logical_index(8), None);
    for (index, id) in [7, 42, u32::MAX].into_iter().enumerate() {
        assert_eq!(map.apic_id(index as u32), Some(id));
    }
    assert_eq!(map.apic_id(3), None);
}

#[test]
fn empty_oversized_and_duplicate_topologies_are_rejected() {
    assert_eq!(ProcessorIdentityMap::new(&[]), Err(ProcessorIdentityError::InvalidCount));
    assert_eq!(ProcessorIdentityMap::new(&[0; 65]), Err(ProcessorIdentityError::InvalidCount));
    assert_eq!(ProcessorIdentityMap::new(&[7, 7]), Err(ProcessorIdentityError::DuplicateApicId));
    assert_eq!(ProcessorIdentityMap::new(&[u32::MAX, 3, u32::MAX]),
        Err(ProcessorIdentityError::DuplicateApicId));
}
