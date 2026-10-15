use nt_fs::*;

fn entry(index: u32, id: u64) -> DirectoryEntry {
    let mut entry = DirectoryEntry {
        file_index: index,
        file_id: id,
        ..Default::default()
    };
    let name = format!("FILE{index:04}.TXT")
        .encode_utf16()
        .collect::<Vec<_>>();
    assert!(entry.set_name(&name));
    entry
}

fn snapshot() -> Vec<DirectoryEntry> {
    let installed = (0..1024)
        .map(|index| entry(index, index as u64))
        .collect::<Vec<_>>();
    let overlay = [entry(512, 9000), entry(1024, 9001)];
    merge_layered_directory_entries(&installed, &overlay).unwrap()
}

#[test]
fn x64_directory_allocation_geometry_matches_observed_request() {
    if cfg!(target_pointer_width = "64") {
        assert_eq!(core::mem::size_of::<DirectoryEntry>(), 616);
        assert_eq!(core::mem::size_of::<DirectoryEntry>() * 1024, 630784);
    }
}

#[test]
fn large_query_retains_only_copied_cursor_between_rebuilt_snapshots() {
    let mut state = DirectoryQueryState::new();
    let mut output = [0u8; 512];
    let mut expected = 0;
    loop {
        let entries = snapshot();
        assert_eq!(entries.len(), 1025);
        assert_eq!(entries[512].file_id, 9000);
        let result = query_directory(
            &mut state,
            &entries,
            FILE_ID_FULL_DIRECTORY_INFORMATION,
            false,
            None,
            false,
            &mut output,
        );
        drop(entries);
        if result.status == STATUS_NO_MORE_FILES {
            assert_eq!(expected, 1025);
            assert_eq!(result.information, 0);
            break;
        }
        assert_eq!(result.status, STATUS_SUCCESS);
        let mut offset = 0;
        loop {
            let index = u32::from_le_bytes(output[offset + 4..offset + 8].try_into().unwrap());
            let id = u64::from_le_bytes(output[offset + 72..offset + 80].try_into().unwrap());
            assert_eq!(index, expected);
            assert_eq!(
                id,
                match expected {
                    512 => 9000,
                    1024 => 9001,
                    other => other as u64,
                }
            );
            expected += 1;
            let next = u32::from_le_bytes(output[offset..offset + 4].try_into().unwrap()) as usize;
            if next == 0 {
                break;
            }
            assert_eq!(next % 8, 0);
            offset += next;
            assert!(offset < result.information);
        }
        assert_eq!(state.cursor(), expected);
    }
}

#[test]
fn failed_and_partial_queries_preserve_retry_cursor_on_large_directory() {
    let entries = snapshot();
    let mut state = DirectoryQueryState::new();
    let initial = state;
    let mut short = [0u8; 4];
    let result = query_directory(
        &mut state,
        &entries,
        FILE_NAMES_INFORMATION,
        false,
        None,
        false,
        &mut short,
    );
    assert_eq!(result.status, STATUS_INFO_LENGTH_MISMATCH);
    assert_eq!(state, initial);
    let mut partial = [0u8; 16];
    let result = query_directory(
        &mut state,
        &entries,
        FILE_NAMES_INFORMATION,
        false,
        None,
        false,
        &mut partial,
    );
    assert_eq!(result.status, STATUS_BUFFER_OVERFLOW);
    assert_eq!(state.cursor(), 0);
    let before_invalid = state;
    let result = query_directory(
        &mut state,
        &entries,
        u32::MAX,
        false,
        None,
        false,
        &mut partial,
    );
    assert_eq!(result.status, STATUS_INVALID_INFO_CLASS);
    assert_eq!(state, before_invalid);
    let mut output = [0u8; 128];
    let result = query_directory(
        &mut state,
        &entries,
        FILE_NAMES_INFORMATION,
        true,
        None,
        false,
        &mut output,
    );
    assert_eq!(result.status, STATUS_SUCCESS);
    assert_eq!(state.cursor(), 1);
    let result = query_directory(
        &mut state,
        &entries,
        FILE_NAMES_INFORMATION,
        true,
        None,
        true,
        &mut output,
    );
    assert_eq!(result.status, STATUS_SUCCESS);
    assert_eq!(state.cursor(), 1);
}
