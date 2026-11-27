use nt_fs::*;

#[test]
fn exact_find_first_query_reports_directory_and_file_from_overlay_parent() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\Users\User\basicproof"));
    let file = fs.zw_create_file(
        r"\??\C:\Users\User\basicproof.txt", FILE_WRITE_DATA | SYNCHRONIZE,
        0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_CREATE, FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(file.status, STATUS_SUCCESS);
    let parent = fs.zw_create_file(
        r"\??\C:\Users\User", FILE_READ_DATA, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_DIRECTORY_FILE,
    );
    assert_eq!(parent.status, STATUS_SUCCESS);

    for (name, is_directory) in [("basicproof", true), ("basicproof.txt", false)] {
        let pattern: Vec<u16> = name.encode_utf16().collect();
        let mut output = [0u8; 512];
        let result = fs.zw_query_directory_file(
            parent.handle, FILE_BOTH_DIRECTORY_INFORMATION, true,
            Some(&pattern), true, &mut output,
        );
        assert_eq!(result.status, STATUS_SUCCESS, "exact query for {name}");
        let name_len = u32::from_le_bytes(output[60..64].try_into().unwrap()) as usize;
        let actual = String::from_utf16(
            &output[94..94 + name_len].chunks_exact(2)
                .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
                .collect::<Vec<_>>(),
        ).unwrap();
        assert_eq!(actual, name);
        let attributes = u32::from_le_bytes(output[56..60].try_into().unwrap());
        assert_eq!(attributes & FILE_ATTRIBUTE_DIRECTORY != 0, is_directory);
    }
}

#[test]
fn synchronize_only_open_can_set_file_basic_attributes() {
    let path = r"\??\C:\Users\User\basicproof.txt";
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\Users\User"));
    let created = fs.zw_create_file(
        path, FILE_WRITE_DATA | SYNCHRONIZE, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_CREATE, FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(created.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_close(created.handle), STATUS_SUCCESS);

    // LiberNT's SetFileAttributesW opens the target with SYNCHRONIZE alone.
    let opened = fs.zw_create_file(
        path, SYNCHRONIZE, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    let mut basic = [0u8; 40];
    basic[32..36].copy_from_slice(&FILE_ATTRIBUTE_READONLY.to_le_bytes());
    assert_eq!(fs.zw_set_information_file(opened.handle, FILE_BASIC_INFORMATION, &basic),
        STATUS_SUCCESS);
    assert_eq!(fs.query_metadata(path).unwrap().attributes & FILE_ATTRIBUTE_READONLY,
        FILE_ATTRIBUTE_READONLY);
}
