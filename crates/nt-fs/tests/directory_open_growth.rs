use nt_fs::*;

const INDEX_CAP: usize = MAX_FAT_OPEN_SLOTS;

#[test]
fn directory_table_storage_does_not_scale_with_handle_index_limit() {
    assert_eq!(INDEX_CAP, u16::MAX as usize + 1);
    assert!(core::mem::size_of::<DirectoryOpenTable<INDEX_CAP>>() <= 64,
        "the 16-bit index schema must not allocate 65536 directory descriptions eagerly");
}

#[test]
fn directory_table_grows_past_64_live_descriptions() {
    assert!(core::mem::size_of::<DirectoryOpenTable<160>>() <= 64);
    let mut table = DirectoryOpenTable::<160>::new();
    let mut ids = Vec::new();
    for index in 0..160u32 {
        let path = format!("profiles\\template{index}");
        let id = table.create(index + 1, path.as_bytes(), FILE_READ_DATA, FILE_SHARE_READ,
            FILE_DIRECTORY_FILE, FileMetadata { file_id: u64::from(index + 1),
                is_directory: true, ..FileMetadata::default() }, FatShortName::EMPTY).unwrap();
        assert_eq!(table.get(id).unwrap().volume_relative_path(), path.as_bytes());
        ids.push(id);
    }
    for (index, id) in ids.iter().copied().enumerate() {
        assert_eq!(table.get(id).unwrap().first_cluster, index as u32 + 1);
        table.release(id).unwrap();
    }
}

#[test]
fn directory_growth_preserves_retained_body_and_rejects_recycled_generation() {
    assert!(core::mem::size_of::<DirectoryOpenTable<160>>() <= 64);
    let mut table = DirectoryOpenTable::<160>::new();
    let first = table.create(1, b"profiles\\template", FILE_READ_DATA, FILE_SHARE_READ,
        FILE_DIRECTORY_FILE, FileMetadata { file_id: 1, is_directory: true,
            ..FileMetadata::default() }, FatShortName::EMPTY).unwrap();
    table.retain_io(first).unwrap();
    table.release(first).unwrap();
    let mut others = Vec::new();
    for index in 2..100u32 {
        others.push(table.create(index, b"other", 0, 0, FILE_DIRECTORY_FILE,
            FileMetadata { file_id: u64::from(index), is_directory: true,
                ..FileMetadata::default() }, FatShortName::EMPTY).unwrap());
    }
    assert_eq!(table.get(first).unwrap().first_cluster, 1);
    table.release_io(first).unwrap();
    let recycled = table.create(200, b"replacement", 0, 0, FILE_DIRECTORY_FILE,
        FileMetadata { file_id: 200, is_directory: true, ..FileMetadata::default() },
        FatShortName::EMPTY).unwrap();
    assert_ne!(first, recycled);
    assert_eq!(table.get(first), Err(STATUS_INVALID_HANDLE));
    assert_eq!(table.release_io(first), Err(STATUS_INVALID_HANDLE));
    assert_eq!(table.get(recycled).unwrap().first_cluster, 200);
    table.release(recycled).unwrap();
    for id in others { table.release(id).unwrap(); }
}

#[test]
fn directory_growth_releases_handle_sharing_without_retiring_retained_body() {
    assert!(core::mem::size_of::<DirectoryOpenTable<160>>() <= 64);
    let mut table = DirectoryOpenTable::<160>::new();
    let metadata = FileMetadata { file_id: 44, is_directory: true, ..FileMetadata::default() };
    let first = table.create(44, b"profiles\\template", FILE_READ_DATA, 0,
        FILE_DIRECTORY_FILE, metadata, FatShortName::EMPTY).unwrap();
    table.retain_io(first).unwrap();
    assert_eq!(table.create(44, b"profiles\\template", FILE_READ_DATA, FILE_SHARE_READ,
        FILE_DIRECTORY_FILE, metadata, FatShortName::EMPTY), Err(STATUS_SHARING_VIOLATION));
    table.release(first).unwrap();
    let next = table.create(44, b"profiles\\template", FILE_READ_DATA, FILE_SHARE_READ,
        FILE_DIRECTORY_FILE, metadata, FatShortName::EMPTY).unwrap();
    assert_eq!(table.get(first).unwrap().first_cluster, 44);
    table.release_io(first).unwrap();
    assert_eq!(table.get(first), Err(STATUS_INVALID_HANDLE));
    assert_eq!(table.get(next).unwrap().first_cluster, 44);
    table.release(next).unwrap();
}
