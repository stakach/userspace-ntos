use nt_kernel_exec::processor_topology::{
    write_relation_group, RelationGroupError, RELATION_GROUP_RECORD_BYTES,
};

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn relation_group_matches_x64_wdk_layout_for_single_processor() {
    let mut bytes = [0xa5; RELATION_GROUP_RECORD_BYTES + 8];
    assert_eq!(write_relation_group(1, Some(&mut bytes)), Ok(80));
    assert_eq!(u32_at(&bytes, 0), 4); // RelationGroup
    assert_eq!(u32_at(&bytes, 4), 80);
    assert_eq!(u16_at(&bytes, 8), 1); // MaximumGroupCount
    assert_eq!(u16_at(&bytes, 10), 1); // ActiveGroupCount
    assert!(bytes[12..32].iter().all(|byte| *byte == 0));
    assert_eq!(bytes[32], 1); // MaximumProcessorCount
    assert_eq!(bytes[33], 1); // ActiveProcessorCount
    assert!(bytes[34..72].iter().all(|byte| *byte == 0));
    assert_eq!(u64_at(&bytes, 72), 1);
    assert_eq!(&bytes[80..], &[0xa5; 8]);
}

#[test]
fn relation_group_reports_actual_one_group_mask_without_truncation() {
    for (count, mask) in [(4, 0xf), (64, u64::MAX)] {
        let mut bytes = [0u8; RELATION_GROUP_RECORD_BYTES];
        assert_eq!(write_relation_group(count, Some(&mut bytes)), Ok(80));
        assert_eq!(bytes[32], count as u8);
        assert_eq!(bytes[33], count as u8);
        assert_eq!(u64_at(&bytes, 72), mask);
    }
}

#[test]
fn probe_and_short_buffer_report_exact_required_size_without_writing() {
    assert_eq!(
        write_relation_group(1, None),
        Err(RelationGroupError::BufferTooSmall { required: 80 })
    );
    let mut short = [0xa5; RELATION_GROUP_RECORD_BYTES - 1];
    assert_eq!(
        write_relation_group(1, Some(&mut short)),
        Err(RelationGroupError::BufferTooSmall { required: 80 })
    );
    assert!(short.iter().all(|byte| *byte == 0xa5));
}

#[test]
fn unsupported_boot_topology_fails_without_touching_output() {
    for count in [0, 65, u64::MAX] {
        let mut bytes = [0xa5; RELATION_GROUP_RECORD_BYTES];
        assert_eq!(
            write_relation_group(count, Some(&mut bytes)),
            Err(RelationGroupError::InvalidTopology)
        );
        assert!(bytes.iter().all(|byte| *byte == 0xa5));
    }
}
