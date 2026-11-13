//! Pinned LiberNT full-WDDM standard allocation DDI, including both size and data passes.

use nt_hosted_runtime::{DxgDdiSignature, DxgStandardAllocationLayout};

fn request(kind: u32, surface: u64, allocation: (u64, u32), resource: (u64, u32)) -> [u8; 0x30] {
    let mut bytes = [0u8; 0x30];
    bytes[..4].copy_from_slice(&kind.to_le_bytes());
    bytes[8..16].copy_from_slice(&surface.to_le_bytes());
    bytes[0x10..0x18].copy_from_slice(&allocation.0.to_le_bytes());
    bytes[0x18..0x1c].copy_from_slice(&allocation.1.to_le_bytes());
    bytes[0x20..0x28].copy_from_slice(&resource.0.to_le_bytes());
    bytes[0x28..0x2c].copy_from_slice(&resource.1.to_le_bytes());
    bytes
}

#[test]
fn standard_allocation_two_phase_projection_is_bounded_and_versioned() {
    for version in [0x5022, 0x5023, 0x11007] {
        assert_eq!(DxgDdiSignature::for_offset(version, 0xb0),
            Some(DxgDdiSignature::GetStandardAllocationDriverData));
        assert_eq!(DxgDdiSignature::GetStandardAllocationDriverData.argument_count(), 2);
        let first = DxgStandardAllocationLayout::parse(version,
            &request(1, 0x1000, (0, 0), (0, 0)), 0x2000).unwrap();
        assert_eq!(first.surface_bytes(), 0x18);
        assert_eq!(first.allocation_private(), (0, 0));
        assert_eq!(first.resource_private(), (0, 0));
        assert_eq!(first.request_bytes(), 0x30);
        let second = DxgStandardAllocationLayout::parse(version,
            &request(1, 0x1000, (0x2000, 0x60), (0, 0)), 0x2000).unwrap();
        assert_eq!(second.allocation_private(), (0x2000, 0x60));
        assert!(second.marshal_bytes() <= 0x2000);
        let mut multi_adapter = request(1, 0x1000, (0, 0), (0, 0));
        multi_adapter[0x2c..0x30].copy_from_slice(&7u32.to_le_bytes());
        assert!(DxgStandardAllocationLayout::parse(version,
            &multi_adapter, 0x2000).is_some());
        let shadow = DxgStandardAllocationLayout::parse(version,
            &request(2, 0x1000, (0, 0), (0, 0)), 0x2000).unwrap();
        assert_eq!(shadow.surface_bytes(), 0x10);
    }
    assert!(DxgStandardAllocationLayout::parse(0x11008,
        &request(1, 0x1000, (0, 0), (0, 0)), 0x2000).is_none());
    assert!(DxgStandardAllocationLayout::parse(0x11007,
        &request(3, 0x1000, (0, 0), (0, 0)), 0x2000).is_none());
    assert!(DxgStandardAllocationLayout::parse(0x11007,
        &request(1, 0, (0, 0), (0, 0)), 0x2000).is_none());
    assert!(DxgStandardAllocationLayout::parse(0x11007,
        &request(1, 0x1000, (0, 0x60), (0, 0)), 0x2000).is_none());
    assert!(DxgStandardAllocationLayout::parse(0x11007,
        &request(1, 0x1000, (0x2000, 0x2000), (0, 0)), 0x2000).is_none());
    assert!(DxgStandardAllocationLayout::parse(0x11007,
        &request(1, 0x1000, (0x1008, 0x60), (0, 0)), 0x2000).is_none());
}

#[test]
fn standard_allocation_copyback_preserves_provider_pointer_identity() {
    let layout = DxgStandardAllocationLayout::parse(0x11007,
        &request(2, 0x1000, (0x2000, 0x40), (0, 0)), 0x2000).unwrap();
    let mut original = request(2, 0x1000, (0x2000, 0x40), (0, 0));
    let mut returned = original;
    returned[0x18..0x1c].copy_from_slice(&0x38u32.to_le_bytes());
    returned[0x28..0x2c].copy_from_slice(&0u32.to_le_bytes());
    returned[8..16].copy_from_slice(&0x9000u64.to_le_bytes());
    assert!(!layout.copyback_sizes(&mut original, &returned));
    returned[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    assert!(layout.copyback_sizes(&mut original, &returned));
    assert_eq!(u64::from_le_bytes(original[8..16].try_into().unwrap()), 0x1000);
    assert_eq!(u64::from_le_bytes(original[0x10..0x18].try_into().unwrap()), 0x2000);
    assert_eq!(u32::from_le_bytes(original[0x18..0x1c].try_into().unwrap()), 0x38);
    assert!(!layout.copyback_sizes(&mut original[..0x2f], &returned));
}
