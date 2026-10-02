use nt_fs::*;

#[test]
fn missing_directory_dispositions_require_real_create_or_report_absence() {
    let expected = [
        Err(STATUS_INVALID_PARAMETER),
        Err(STATUS_OBJECT_NAME_NOT_FOUND),
        Ok(LayeredDirectoryOpenDecision::CreateOverlay),
        Ok(LayeredDirectoryOpenDecision::CreateOverlay),
        Err(STATUS_INVALID_PARAMETER),
        Err(STATUS_INVALID_PARAMETER),
    ];
    for (disposition, expected) in expected.into_iter().enumerate() {
        assert_eq!(
            layered_directory_open_decision(None, None, disposition as u32, FILE_DIRECTORY_FILE, false),
            expected,
            "disposition={disposition}",
        );
    }
}

#[test]
fn existing_directory_dispositions_preserve_selected_layer_and_collisions() {
    for (installed, overlay, selected) in [
        (Some(true), None, LayeredDirectoryOpenDecision::Installed),
        (None, Some(true), LayeredDirectoryOpenDecision::Overlay),
        (Some(true), Some(true), LayeredDirectoryOpenDecision::Overlay),
    ] {
        for disposition in FILE_SUPERSEDE..=FILE_OVERWRITE_IF {
            let expected = match disposition {
                FILE_OPEN | FILE_OPEN_IF => Ok(selected),
                FILE_CREATE => Err(STATUS_OBJECT_NAME_COLLISION),
                _ => Err(STATUS_INVALID_PARAMETER),
            };
            assert_eq!(
                layered_directory_open_decision(installed, overlay, disposition, FILE_DIRECTORY_FILE, false),
                expected,
                "installed={installed:?} overlay={overlay:?} disposition={disposition}",
            );
        }
    }
}

#[test]
fn directory_layer_precedence_never_opens_a_shadowed_file_as_a_directory() {
    for disposition in [FILE_OPEN, FILE_CREATE, FILE_OPEN_IF] {
        for (installed, overlay) in [(Some(false), None), (None, Some(false)), (Some(true), Some(false))] {
            assert_eq!(
                layered_directory_open_decision(installed, overlay, disposition, FILE_DIRECTORY_FILE, false),
                Err(STATUS_NOT_A_DIRECTORY),
            );
        }
    }
    assert_eq!(
        layered_directory_open_decision(Some(false), Some(true), FILE_OPEN, FILE_DIRECTORY_FILE, false),
        Ok(LayeredDirectoryOpenDecision::Overlay),
        "a real upper directory shadows an installed file",
    );
    assert_eq!(
        layered_directory_open_decision(Some(true), None, FILE_OPEN, FILE_NON_DIRECTORY_FILE, false),
        Err(STATUS_FILE_IS_A_DIRECTORY),
    );
}

#[test]
fn directory_policy_rejects_invalid_disposition_and_root_delete_on_close() {
    assert_eq!(
        layered_directory_open_decision(None, None, FILE_MAXIMUM_DISPOSITION + 1, FILE_DIRECTORY_FILE, false),
        Err(STATUS_INVALID_PARAMETER),
    );
    for (installed, overlay) in [(Some(true), None), (None, Some(true))] {
        assert_eq!(
            layered_directory_open_decision(installed, overlay, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE, true),
            Err(STATUS_CANNOT_DELETE),
        );
    }
    assert_eq!(
        layered_directory_open_decision(Some(true), None, FILE_OPEN, FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE, false),
        Err(STATUS_INVALID_PARAMETER),
    );
}

#[test]
fn selected_overlay_directory_supports_real_relative_child_and_sharing_lifetime() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\profiles"));
    assert_eq!(
        layered_directory_open_decision(None, None, FILE_CREATE, FILE_DIRECTORY_FILE, false),
        Ok(LayeredDirectoryOpenDecision::CreateOverlay),
    );
    let directory = fs.zw_create_file_relative(
        b"profiles\\user", FILE_READ_DATA, FILE_ATTRIBUTE_DIRECTORY, 0,
        FILE_CREATE, FILE_DIRECTORY_FILE,
    );
    assert_eq!((directory.status, directory.information), (STATUS_SUCCESS, FILE_CREATED));
    let conflict = fs.zw_create_file_relative(
        b"profiles\\user", FILE_READ_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ,
        FILE_OPEN, FILE_DIRECTORY_FILE,
    );
    assert_eq!(conflict.status, STATUS_SHARING_VIOLATION);
    let child = fs.zw_create_file_relative_to_directory(
        directory.handle, b"NTUSER.DAT", FILE_READ_DATA | FILE_WRITE_DATA,
        FILE_ATTRIBUTE_HIDDEN, FILE_SHARE_READ, FILE_CREATE, FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!((child.status, child.information), (STATUS_SUCCESS, FILE_CREATED));
    assert_eq!(fs.zw_write_file(child.handle, None, b"regf"), (STATUS_SUCCESS, 4));
    assert_eq!(fs.zw_close(directory.handle), STATUS_SUCCESS);
    assert_eq!(fs.zw_read_file(child.handle, Some(0), 4), (STATUS_SUCCESS, b"regf".to_vec()));
    assert_eq!(fs.zw_close(child.handle), STATUS_SUCCESS);
    assert_eq!(
        layered_directory_open_decision(None, Some(true), FILE_OPEN_IF, FILE_DIRECTORY_FILE, false),
        Ok(LayeredDirectoryOpenDecision::Overlay),
    );
    let reopened = fs.zw_create_file_relative(
        b"profiles\\user", FILE_READ_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ,
        FILE_OPEN_IF, FILE_DIRECTORY_FILE,
    );
    assert_eq!((reopened.status, reopened.information), (STATUS_SUCCESS, FILE_OPENED));
    assert_eq!(fs.zw_close(reopened.handle), STATUS_SUCCESS);
    let absent_parent = fs.zw_create_file_relative(
        b"absent\\child", FILE_READ_DATA, FILE_ATTRIBUTE_DIRECTORY, FILE_SHARE_READ,
        FILE_CREATE, FILE_DIRECTORY_FILE,
    );
    assert_eq!(absent_parent.status, STATUS_OBJECT_PATH_NOT_FOUND);
    assert!(fs.query_metadata_relative(b"absent\\child").is_none());
}
