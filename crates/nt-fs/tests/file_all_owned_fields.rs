use nt_fs::*;

#[test]
fn file_all_seed_capture_changes_only_access_mode_and_alignment() {
    let seeded = QueryMetadata {
        access_flags: 0x0012_0189,
        mode: FILE_SYNCHRONOUS_IO_ALERT | FILE_WRITE_THROUGH | FILE_SEQUENTIAL_ONLY,
        alignment_requirement: 511,
        ..QueryMetadata::default()
    };
    let mut input = [0xa5; 128];
    assert_eq!(encode_file_all_io_manager_information(seeded, &mut input), Ok(12));
    let before = input;
    let mut filesystem = QueryMetadata {
        current_byte_offset: 123,
        end_of_file: 456,
        allocation_size: 512,
        file_attributes: FILE_ATTRIBUTE_NORMAL,
        file_id: 77,
        number_of_links: 2,
        access_flags: u32::MAX,
        mode: FILE_SYNCHRONOUS_IO_NONALERT,
        alignment_requirement: 0,
        ..QueryMetadata::default()
    };
    let original = filesystem;
    assert_eq!(capture_file_all_io_manager_information(&input, &mut filesystem), Ok(()));
    assert_eq!(filesystem, QueryMetadata {
        access_flags: seeded.access_flags,
        mode: seeded.mode,
        alignment_requirement: seeded.alignment_requirement,
        ..original
    });
    assert_eq!(input, before, "capture must not rewrite the seeded transport");
    let mut output = [0x5a; 128];
    let name = [b'\\' as u16, b'a' as u16];
    let result = encode_named_query_information(
        FILE_ALL_INFORMATION, filesystem, &name, &mut output,
    ).unwrap();
    assert_eq!(result.status, STATUS_SUCCESS);
    assert_eq!(&output[76..80], &seeded.access_flags.to_le_bytes());
    assert_eq!(&output[80..88], &123u64.to_le_bytes());
    assert_eq!(&output[88..92], &seeded.mode.to_le_bytes());
    assert_eq!(&output[92..96], &511u32.to_le_bytes());
    assert!(output[result.information..].iter().all(|byte| *byte == 0x5a));
}

#[test]
fn truncated_file_all_seed_is_rejected_before_any_metadata_mutation() {
    let input = [0xff; FILE_ALL_INFORMATION_MINIMUM_LENGTH];
    for length in 0..FILE_ALL_INFORMATION_MINIMUM_LENGTH {
        let mut metadata = QueryMetadata { access_flags: 91, mode: 92,
            alignment_requirement: 93, current_byte_offset: 94, ..QueryMetadata::default() };
        let before = metadata;
        assert_eq!(capture_file_all_io_manager_information(&input[..length], &mut metadata),
            Err(STATUS_INFO_LENGTH_MISMATCH));
        assert_eq!(metadata, before);
    }
}
