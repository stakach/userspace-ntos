//! Pinned LiberNT WDDM node-metadata callback and bounded output ABI.

use nt_hosted_runtime::{DxgDdiSignature, DxgNodeMetadataLayout};

#[test]
fn get_node_metadata_is_a_three_argument_versioned_callback() {
    for version in [0x5022, 0x5023, 0x11007] {
        assert_eq!(DxgDdiSignature::for_offset(version, 0x298),
            Some(DxgDdiSignature::GetNodeMetadata));
        assert_eq!(DxgDdiSignature::GetNodeMetadata.argument_count(), 3);
        let layout = DxgNodeMetadataLayout::new(version, 0, 0x1000, 0x1000).unwrap();
        assert_eq!(layout.node_ordinal(), 0);
        assert_eq!(layout.output_address(), 0x1000);
        assert_eq!(layout.bytes(), 0x4a);
        assert!(DxgNodeMetadataLayout::new(version, 0, 0x1000, 0x49).is_none());
        assert!(DxgNodeMetadataLayout::new(version, 0, 0, 0x1000).is_none());
        assert!(DxgNodeMetadataLayout::new(version, u32::MAX as u64 + 1,
            0x1000, 0x1000).is_none());
    }
    assert!(DxgNodeMetadataLayout::new(0x5023, 0,
        u64::MAX - 0x40, 0x1000).is_none());
    assert!(DxgNodeMetadataLayout::new(0x7777, 0, 0x1000, 0x1000).is_none());
}

#[test]
fn node_metadata_copyback_writes_only_the_exact_0x4a_byte_output() {
    let layout = DxgNodeMetadataLayout::new(0x5023, 0, 0x1000, 0x1000).unwrap();
    let mut output = [0xa5; 0x50];
    assert!(layout.initialize_output(&mut output));
    assert_eq!(&output[..0x4a], &[0; 0x4a]);
    assert_eq!(&output[0x4a..], &[0xa5; 6]);
    let mut returned = [0u8; 0x4a];
    returned[0..4].copy_from_slice(&1u32.to_le_bytes()); // 3D engine
    returned[0x48] = 1; // GPU MMU support
    assert!(layout.copyback(&mut output, &returned));
    assert_eq!(&output[..0x4a], &returned);
    assert_eq!(&output[0x4a..], &[0xa5; 6]);
    assert!(!layout.copyback(&mut output[..0x49], &returned));
}
