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
