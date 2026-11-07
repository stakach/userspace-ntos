//! Pinned LiberNT WDDM 2.0 fixed POD QueryAdapterInfo contracts.

use super::{dxg_query_restores_nested_pointer, DxgFixedQueryLayout, DxgQueryAdapterInfoPrefix};

fn prefix(
    kind: u32,
    input_address: u64,
    input_bytes: u32,
    output_address: u64,
    output_bytes: u32,
    capacity: u64,
) -> Option<DxgQueryAdapterInfoPrefix> {
    let mut wire = [0u8; 0x28];
    wire[0..4].copy_from_slice(&kind.to_le_bytes());
    wire[8..16].copy_from_slice(&input_address.to_le_bytes());
    wire[0x10..0x14].copy_from_slice(&input_bytes.to_le_bytes());
    wire[0x18..0x20].copy_from_slice(&output_address.to_le_bytes());
    wire[0x20..0x24].copy_from_slice(&output_bytes.to_le_bytes());
    DxgQueryAdapterInfoPrefix::parse(&wire, capacity)
}

#[test]
fn gpu_mmu_caps_and_level_descriptor_use_exact_fixed_pod_extents() {
    // DXGKQAITYPE_GPUMMUCAPS: QUERYGPUMMUCAPSIN (4) -> GPUMMUCAPS (0x18).
    // DXGKQAITYPE_PAGETABLELEVELDESC: QUERY...IN (4) -> LEVEL_DESC (0x14).
    for (kind, output_bytes) in [(13, 0x18), (14, 0x14)] {
        let request = prefix(kind, 0x1000, 4, 0x2000, output_bytes, 0x100).unwrap();
        let layout = DxgFixedQueryLayout::parse(request, 0x100)
            .expect("released SoftGpu fixed query must be admitted");
        assert_eq!(layout.input_bytes(), 4);
        assert_eq!(layout.output_bytes(), output_bytes as u64);
        assert!(!dxg_query_restores_nested_pointer(kind),
            "fixed POD output has no descriptor pointer to rewrite");

        for short in 0..4 {
            let request = prefix(kind, 0x1000, short, 0x2000, output_bytes, 0x100).unwrap();
            assert!(DxgFixedQueryLayout::parse(request, 0x100).is_none());
        }
        let request = prefix(kind, 0x1000, 4, 0x2000, output_bytes - 1, 0x100).unwrap();
        assert!(DxgFixedQueryLayout::parse(request, 0x100).is_none());
        let request = prefix(kind, 0x1000, 4, 0x2000, output_bytes + 1, 0x100).unwrap();
        assert!(DxgFixedQueryLayout::parse(request, 0x100).is_none());
    }
}

#[test]
fn fixed_query_refuses_unowned_or_unsupported_shapes_before_callback() {
    for kind in [0, 1, 2, 5, 11, 12, 15] {
        let request = prefix(kind, 0x1000, 4, 0x2000, 0x18, 0x100).unwrap();
        assert!(DxgFixedQueryLayout::parse(request, 0x100).is_none());
    }
    assert!(prefix(13, 0, 4, 0x2000, 0x18, 0x100).is_none());
    assert!(prefix(13, 0x1000, 4, 0, 0x18, 0x100).is_none());
    assert!(prefix(13, 0x1000, 4, 0x2000, 0x18, 0x17).is_none());
    assert!(prefix(13, u64::MAX - 1, 4, 0x2000, 0x18, 0x100).is_none());
}
