use super::*;
use crate::NtFileHiveIoProvider;
use core::cell::RefCell;
use nt_hive_core::{HiveBootError, HiveIoError, HiveIoProvider, HiveKind, HiveManager};

const PRIMARY: &str = r"\??\C:\Config\Hive";
const LOG: &str = r"\??\C:\Config\Hive.LOG";

fn fs() -> FileSystem {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\Config"));
    fs
}

#[test]
fn missing_leaf_and_present_empty_file_are_distinct() {
    let mut fs = fs();
    assert_eq!(fs.try_file_len(PRIMARY), Ok(None));
    assert_eq!(fs.try_file_bytes_owned(PRIMARY), Ok(None));
    assert!(fs.provision_file(PRIMARY, &[]));
    assert_eq!(fs.try_file_len(PRIMARY), Ok(Some(0)));
    assert_eq!(fs.try_file_bytes_owned(PRIMARY), Ok(Some(Vec::new())));
}

#[test]
fn relative_reads_copy_contiguous_and_extent_files_without_touching_the_tail() {
    for extent_backed in [false, true] {
        let mut fs = fs();
        if extent_backed {
            assert_eq!(
                fs.append_file_by_path(PRIMARY, b"first"),
                (STATUS_SUCCESS, 5)
            );
            assert_eq!(
                fs.append_file_by_path(PRIMARY, b"second"),
                (STATUS_SUCCESS, 6)
            );
        } else {
            assert!(fs.provision_file(PRIMARY, b"firstsecond"));
        }
        let mut destination = [0xA5; 16];
        assert_eq!(
            fs.try_read_file_relative_into(b"config\\hive", &mut destination),
            Ok(Some(11))
        );
        assert_eq!(&destination[..11], b"firstsecond");
        assert_eq!(&destination[11..], &[0xA5; 5]);
        assert_eq!(
            fs.try_query_metadata_relative(b"config\\hive"),
            Ok(fs.query_metadata(PRIMARY))
        );
    }
}

#[test]
fn relative_reads_distinguish_empty_files_and_absent_overlay_subtrees() {
    let mut fs = fs();
    let mut destination = [0xA5; 4];
    for relative in [b"config\\hive".as_slice(), b"missing\\nested\\hive"] {
        assert_eq!(
            fs.try_read_file_relative_into(relative, &mut destination),
            Ok(None)
        );
        assert_eq!(fs.try_query_metadata_relative(relative), Ok(None));
        assert_eq!(destination, [0xA5; 4]);
    }
    assert!(fs.provision_file(PRIMARY, &[]));
    assert_eq!(
        fs.try_read_file_relative_into(b"config\\hive", &mut destination),
        Ok(Some(0))
    );
    assert_eq!(destination, [0xA5; 4]);
    assert_eq!(
        fs.try_read_file_relative_into(b"config\\hive", &mut []),
        Ok(Some(0))
    );
    assert_eq!(
        fs.try_query_metadata_relative(b"config\\hive")
            .unwrap()
            .unwrap()
            .end_of_file,
        0
    );
}

#[test]
fn relative_reads_validate_capacity_before_copying_any_bytes() {
    let mut fs = fs();
    assert_eq!(
        fs.append_file_by_path(PRIMARY, b"first"),
        (STATUS_SUCCESS, 5)
    );
    assert_eq!(
        fs.append_file_by_path(PRIMARY, b"second"),
        (STATUS_SUCCESS, 6)
    );
    let mut destination = [0xA5; 10];
    assert_eq!(
        fs.try_read_file_relative_into(b"config\\hive", &mut destination),
        Err(0xC000_0023)
    );
    assert_eq!(destination, [0xA5; 10]);
}

#[test]
fn relative_queries_preserve_directory_metadata_but_reads_refuse_directories() {
    let fs = fs();
    for relative in [b"".as_slice(), b"config"] {
        assert_eq!(
            fs.try_query_metadata_relative(relative),
            Ok(fs.query_metadata_relative(relative))
        );
        assert!(
            fs.try_query_metadata_relative(relative)
                .unwrap()
                .unwrap()
                .is_directory
        );
        let mut destination = [0xA5; 4];
        assert_eq!(
            fs.try_read_file_relative_into(relative, &mut destination),
            Err(STATUS_FILE_IS_A_DIRECTORY)
        );
        assert_eq!(destination, [0xA5; 4]);
    }
}

#[test]
fn relative_queries_reject_non_directory_ancestors_instead_of_falling_through() {
    let mut fs = fs();
    assert!(fs.provision_file(PRIMARY, b"data"));
    for relative in [
        b"config\\hive\\child".as_slice(),
        b"config\\hive\\missing\\child",
    ] {
        let mut destination = [0xA5; 4];
        assert_eq!(
            fs.try_query_metadata_relative(relative),
            Err(STATUS_NOT_A_DIRECTORY)
        );
        assert_eq!(
            fs.try_read_file_relative_into(relative, &mut destination),
            Err(STATUS_NOT_A_DIRECTORY)
        );
        assert_eq!(destination, [0xA5; 4]);
    }
}

#[test]
fn relative_queries_validate_the_complete_canonical_name_before_lookup() {
    let fs = fs();
    for relative in [
        b"\\config".as_slice(),
        b"config\\",
        b"config\\\\hive",
        b"config/hive",
        b"config\\.\\hive",
        b"config\\..\\hive",
        b"Config\\hive",
        b"config\\hive\0",
        b"config\\\xFF",
        b"c:\\config",
        b"missing\\..\\hive",
        b"missing\\invalid:name",
    ] {
        let mut destination = [0xA5; 4];
        assert_eq!(
            fs.try_query_metadata_relative(relative),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(
            fs.try_read_file_relative_into(relative, &mut destination),
            Err(STATUS_OBJECT_NAME_INVALID)
        );
        assert_eq!(destination, [0xA5; 4]);
    }
}

#[test]
fn relative_queries_report_dangling_directory_entries_as_corruption() {
    let mut fs = fs();
    assert!(fs.provision_file(PRIMARY, b"data"));
    let id = fs.volume.lookup(&fs.to_relative(PRIMARY).unwrap()).unwrap();
    fs.volume.nodes[id as usize] = None;
    for relative in [b"config\\hive".as_slice(), b"config\\hive\\child"] {
        let mut destination = [0xA5; 4];
        assert_eq!(
            fs.try_query_metadata_relative(relative),
            Err(STATUS_DATA_ERROR)
        );
        assert_eq!(
            fs.try_read_file_relative_into(relative, &mut destination),
            Err(STATUS_DATA_ERROR)
        );
        assert_eq!(destination, [0xA5; 4]);
    }
}

#[test]
fn invalid_paths_wrong_volumes_and_directories_are_not_absent_files() {
    let mut fs = fs();
    assert!(fs.provision_file(PRIMARY, b"data"));
    for (path, status) in [
        ("", STATUS_OBJECT_NAME_INVALID),
        ("\0", STATUS_OBJECT_NAME_INVALID),
        (r"\??\Z:\Config\Hive", STATUS_OBJECT_PATH_NOT_FOUND),
        (r"\??\C:\Missing\Hive", STATUS_OBJECT_PATH_NOT_FOUND),
        (r"\??\C:\Config", STATUS_FILE_IS_A_DIRECTORY),
        (r"\??\C:\Config\Hive\Child", STATUS_NOT_A_DIRECTORY),
    ] {
        assert_eq!(fs.try_file_len(path), Err(status), "{path}");
        assert_eq!(fs.try_file_bytes_owned(path), Err(status), "{path}");
    }
}

#[test]
fn extent_backed_files_copy_every_byte_and_report_presence_without_contiguous_storage() {
    let mut fs = fs();
    assert_eq!(
        fs.append_file_by_path(PRIMARY, b"first"),
        (STATUS_SUCCESS, 5)
    );
    assert_eq!(
        fs.append_file_by_path(PRIMARY, b"second"),
        (STATUS_SUCCESS, 6)
    );
    assert!(fs.file_bytes(PRIMARY).is_none());
    assert_eq!(fs.try_file_len(PRIMARY), Ok(Some(11)));
    assert_eq!(
        fs.try_file_bytes_owned(PRIMARY),
        Ok(Some(b"firstsecond".to_vec()))
    );
    let fs = RefCell::new(fs);
    let mut provider = NtFileHiveIoProvider::open(&fs, PRIMARY);
    assert!(provider.get_status().unwrap().image_present);
    assert_eq!(
        provider.read_primary_image(),
        Ok(Some(b"firstsecond".to_vec()))
    );
    assert_eq!(provider.read_log(), Ok(Vec::new()));
}

#[test]
fn canonical_hive_source_path_names_the_same_primary_and_sidecar() {
    let mut fs = fs();
    assert!(fs.provision_file(PRIMARY, b"primary"));
    assert!(fs.provision_file(LOG, b"journal"));
    for source in [r"\??\C:\.\Config\HIVE", r"\DosDevices\C:\Config\.\HIVE"] {
        let name: Vec<u16> = source.encode_utf16().collect();
        let mut folded = [0; 128];
        let mut relative = [0; 128];
        let len =
            crate::nt_path_to_volume_relative_into(&name, b"reactos", &mut folded, &mut relative)
                .unwrap();
        let relative = &relative[..len];
        let mut destination = [0; 7];
        assert_eq!(
            fs.try_read_file_relative_into(relative, &mut destination),
            Ok(Some(7))
        );
        let canonical = alloc::format!(r"\??\C:\{}", core::str::from_utf8(relative).unwrap());
        assert_eq!(fs.try_file_len(&canonical), Ok(Some(7)));
        assert_eq!(
            fs.try_file_bytes_owned(&canonical),
            Ok(Some(destination.to_vec()))
        );
        assert_eq!(
            fs.try_file_bytes_owned(&alloc::format!("{canonical}.LOG")),
            Ok(Some(b"journal".to_vec()))
        );
    }
}

#[test]
fn invalid_or_overflowing_extents_never_shorten_a_log_or_return_empty() {
    let mut fs = fs();
    assert!(fs.provision_file(LOG, b"data"));
    let relative = fs.to_relative(LOG).unwrap();
    let id = fs.volume.lookup(&relative).unwrap();
    let blob = fs.volume.blobs.len();
    fs.volume.blobs.push(b"good".to_vec());
    for extents in [
        alloc::vec![FileExtent {
            blob: blob + 1,
            offset: 0,
            len: 1
        }],
        alloc::vec![FileExtent {
            blob,
            offset: 3,
            len: 2
        }],
        alloc::vec![FileExtent {
            blob,
            offset: usize::MAX,
            len: 2
        }],
        alloc::vec![
            FileExtent {
                blob: ZERO_EXTENT_BLOB,
                offset: 0,
                len: usize::MAX
            },
            FileExtent {
                blob: ZERO_EXTENT_BLOB,
                offset: 0,
                len: 1
            }
        ],
        alloc::vec![
            FileExtent {
                blob,
                offset: 0,
                len: 4
            },
            FileExtent {
                blob: blob + 1,
                offset: 0,
                len: 1
            }
        ],
    ] {
        fs.volume.node_mut(id).unwrap().data = FileData::Extents(extents);
        assert_eq!(fs.try_file_len(LOG), Err(STATUS_DATA_ERROR));
        assert_eq!(fs.try_file_bytes_owned(LOG), Err(STATUS_DATA_ERROR));
        assert_eq!(
            fs.try_query_metadata_relative(b"config\\hive.log"),
            Err(STATUS_DATA_ERROR)
        );
        let mut destination = [0xA5; 16];
        assert_eq!(
            fs.try_read_file_relative_into(b"config\\hive.log", &mut destination),
            Err(STATUS_DATA_ERROR)
        );
        assert_eq!(destination, [0xA5; 16]);
    }
    let fs = RefCell::new(fs);
    let mut provider = NtFileHiveIoProvider::open(&fs, PRIMARY);
    assert_eq!(provider.read_log(), Err(HiveIoError::Io));
    assert_eq!(provider.get_status(), Err(HiveIoError::Io));
}

#[test]
fn unallocatable_file_copy_is_an_error_not_an_absent_log() {
    let mut fs = fs();
    assert!(fs.provision_file(LOG, &[]));
    let id = fs.volume.lookup(&fs.to_relative(LOG).unwrap()).unwrap();
    fs.volume.node_mut(id).unwrap().data = FileData::Extents(alloc::vec![FileExtent {
        blob: ZERO_EXTENT_BLOB,
        offset: 0,
        len: usize::MAX,
    }]);
    assert_eq!(
        fs.try_file_bytes_owned(LOG),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    let fs = RefCell::new(fs);
    let mut provider = NtFileHiveIoProvider::open(&fs, PRIMARY);
    assert_eq!(provider.read_log(), Err(HiveIoError::Io));
}

#[test]
fn empty_primary_is_corrupt_not_a_fresh_hive_and_empty_log_is_valid() {
    let mut fs = fs();
    assert!(fs.provision_file(PRIMARY, &[]));
    assert!(fs.provision_file(LOG, &[]));
    let fs = RefCell::new(fs);
    let mut provider = NtFileHiveIoProvider::open(&fs, PRIMARY);
    assert!(provider.get_status().unwrap().image_present);
    assert_eq!(provider.read_primary_image(), Ok(Some(Vec::new())));
    assert_eq!(provider.read_log(), Ok(Vec::new()));
    assert!(matches!(
        HiveManager::new(provider).boot(HiveKind::System),
        Err(HiveBootError::Decode(_))
    ));
}

#[test]
fn unavailable_provider_and_wrong_kind_log_preserve_status_errors() {
    let mut fs = fs();
    assert!(fs.provision_directory(LOG));
    let fs = RefCell::new(fs);
    let mut provider = NtFileHiveIoProvider::open(&fs, PRIMARY);
    assert_eq!(provider.read_log(), Err(HiveIoError::Io));
    assert_eq!(provider.get_status(), Err(HiveIoError::Io));
    let _exclusive = fs.borrow_mut();
    assert_eq!(provider.read_primary_image(), Err(HiveIoError::Io));
    assert_eq!(provider.read_log(), Err(HiveIoError::Io));
    assert_eq!(provider.get_status(), Err(HiveIoError::Io));
}

#[test]
fn sparse_mixed_extents_preserve_offsets_and_zero_fill() {
    let mut fs = fs();
    assert!(fs.provision_file(LOG, &[]));
    let id = fs.volume.lookup(&fs.to_relative(LOG).unwrap()).unwrap();
    let blob = fs.volume.blobs.len();
    fs.volume.blobs.push(b"xABCDy".to_vec());
    fs.volume.node_mut(id).unwrap().data = FileData::Extents(alloc::vec![
        FileExtent {
            blob,
            offset: 1,
            len: 2
        },
        FileExtent {
            blob: ZERO_EXTENT_BLOB,
            offset: 0,
            len: 3
        },
        FileExtent {
            blob,
            offset: 3,
            len: 2
        },
    ]);
    assert_eq!(fs.try_file_len(LOG), Ok(Some(7)));
    assert_eq!(
        fs.try_file_bytes_owned(LOG),
        Ok(Some(b"AB\0\0\0CD".to_vec()))
    );
    let mut destination = [0xA5; 9];
    assert_eq!(
        fs.try_read_file_relative_into(b"config\\hive.log", &mut destination),
        Ok(Some(7))
    );
    assert_eq!(&destination[..7], b"AB\0\0\0CD");
    assert_eq!(&destination[7..], &[0xA5; 2]);
}

#[test]
fn provider_reads_and_status_obey_exclusive_file_opens() {
    for path in [PRIMARY, LOG] {
        let mut fs = fs();
        assert!(fs.provision_file(path, b"data"));
        let opened = fs.zw_create_file(path, FILE_READ_DATA, 0, 0, FILE_OPEN, 0);
        assert_eq!(opened.status, STATUS_SUCCESS);
        let fs = RefCell::new(fs);
        let mut provider = NtFileHiveIoProvider::open(&fs, PRIMARY);
        assert_eq!(provider.get_status(), Err(HiveIoError::Io));
        if path == PRIMARY {
            assert_eq!(provider.read_primary_image(), Err(HiveIoError::Io));
        } else {
            assert_eq!(provider.read_log(), Err(HiveIoError::Io));
        }
        assert_eq!(fs.borrow_mut().zw_close(opened.handle), STATUS_SUCCESS);
        assert!(provider.get_status().is_ok());
        // Successful and failed checked reads must both release their temporary open.
        let opened = fs
            .borrow_mut()
            .zw_create_file(path, FILE_READ_DATA, 0, 0, FILE_OPEN, 0);
        assert_eq!(opened.status, STATUS_SUCCESS);
        assert_eq!(fs.borrow_mut().zw_close(opened.handle), STATUS_SUCCESS);
    }
}

#[test]
fn provider_does_not_read_delete_pending_primary() {
    let mut fs = fs();
    assert!(fs.provision_file(PRIMARY, b"data"));
    let opened = fs.zw_create_file(
        PRIMARY,
        DELETE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0,
        FILE_OPEN,
        0,
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_set_information_file(opened.handle, FILE_DISPOSITION_INFORMATION, &[1]),
        STATUS_SUCCESS
    );
    let fs = RefCell::new(fs);
    let mut provider = NtFileHiveIoProvider::open(&fs, PRIMARY);
    assert_eq!(provider.read_primary_image(), Err(HiveIoError::Io));
    assert_eq!(provider.get_status(), Err(HiveIoError::Io));
    assert_eq!(fs.borrow_mut().zw_close(opened.handle), STATUS_SUCCESS);
    assert_eq!(provider.read_primary_image(), Ok(None));
}
