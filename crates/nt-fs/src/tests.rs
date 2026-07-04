use super::*;
use core::cell::RefCell;
use nt_hive_core::{HiveKind, HiveLogOp, HiveManager, RegistryValueType};

const SYSTEM_HIVE: &str = r"\SystemRoot\System32\Config\SYSTEM";

#[test]
fn mount_resolver() {
    let mm = MountManager::new();
    // \SystemRoot → \Device\MemFsVolume0\Windows (spec §13.2, M1 success).
    let (vol, rel) = mm.resolve(r"\SystemRoot\System32\Config\SYSTEM").unwrap();
    assert_eq!(vol, MEMFS_VOLUME);
    assert_eq!(rel, r"\Windows\System32\Config\SYSTEM");
    // \??\C: → volume root.
    let (vol, rel) = mm.resolve(r"\??\C:\Temp\x").unwrap();
    assert_eq!(vol, MEMFS_VOLUME);
    assert_eq!(rel, r"\Temp\x");
    // Forward slashes normalize.
    assert_eq!(
        mm.resolve("/SystemRoot/System32").unwrap().1,
        r"\Windows\System32"
    );
    assert!(mm.resolve(r"\Registry\Machine").is_none());
}

#[test]
fn create_dispositions() {
    let mut fs = FileSystem::new(MemFs::with_fixture());
    // OPEN an existing fixture hive file.
    let r = fs.zw_create_file(SYSTEM_HIVE, FILE_READ_DATA, 0, 0, FILE_OPEN, 0);
    assert_eq!(r.status, STATUS_SUCCESS);
    assert_eq!(r.information, FILE_OPENED);
    fs.zw_close(r.handle);
    // OPEN a missing file → not found.
    let miss = fs.zw_create_file(
        r"\SystemRoot\System32\Config\NOPE",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        0,
    );
    assert_eq!(miss.status, STATUS_OBJECT_NAME_NOT_FOUND);
    // CREATE a new file → created; CREATE again → collision.
    let c = fs.zw_create_file(
        r"\??\C:\Temp\new.dat",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        0,
    );
    assert_eq!((c.status, c.information), (STATUS_SUCCESS, FILE_CREATED));
    let dup = fs.zw_create_file(
        r"\??\C:\Temp\new.dat",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        0,
    );
    assert_eq!(dup.status, STATUS_OBJECT_NAME_COLLISION);
    // OVERWRITE_IF an existing file truncates.
    let o = fs.zw_create_file(
        r"\??\C:\Temp\new.dat",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_OVERWRITE_IF,
        0,
    );
    assert_eq!(o.information, FILE_OVERWRITTEN);
    // A missing parent directory → path not found.
    let np = fs.zw_create_file(r"\??\C:\NoSuchDir\x", FILE_WRITE_DATA, 0, 0, FILE_CREATE, 0);
    assert_eq!(np.status, STATUS_OBJECT_PATH_NOT_FOUND);
}

#[test]
fn read_write_offset_and_eof() {
    let mut fs = FileSystem::new(MemFs::with_fixture());
    let h = fs
        .zw_create_file(r"\??\C:\Temp\f", FILE_WRITE_DATA, 0, 0, FILE_CREATE, 0)
        .handle;
    // Sequential writes advance the offset.
    assert_eq!(fs.zw_write_file(h, None, b"hello ").0, STATUS_SUCCESS);
    assert_eq!(fs.zw_write_file(h, None, b"world").1, 5);
    assert_eq!(fs.zw_query_standard_information(h).unwrap().end_of_file, 11);
    fs.zw_close(h);
    // Reopen + read explicit offset, then sequential to EOF.
    let h = fs
        .zw_create_file(r"\??\C:\Temp\f", FILE_READ_DATA, 0, 0, FILE_OPEN, 0)
        .handle;
    let (st, bytes) = fs.zw_read_file(h, Some(6), 5);
    assert_eq!((st, &bytes[..]), (STATUS_SUCCESS, &b"world"[..]));
    let (st, all) = fs.zw_read_file(h, None, 11);
    assert_eq!((st, all.len()), (STATUS_SUCCESS, 11));
    assert_eq!(fs.zw_read_file(h, None, 4).0, STATUS_END_OF_FILE); // at EOF
    fs.zw_close(h);
    assert_eq!(fs.zw_read_file(h, None, 4).0, STATUS_INVALID_HANDLE); // closed
}

#[test]
fn directory_rejects_data_ops() {
    let mut fs = FileSystem::new(MemFs::with_fixture());
    let h = fs
        .zw_create_file(
            r"\SystemRoot\System32\Config",
            FILE_READ_DATA,
            0,
            0,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
        )
        .handle;
    assert_eq!(
        fs.zw_read_file(h, Some(0), 4).0,
        STATUS_INVALID_DEVICE_REQUEST
    );
    assert!(fs.zw_query_standard_information(h).unwrap().is_directory);
}

#[test]
fn hive_persists_through_file_apis() {
    // Spec §14.2 acceptance: HiveManager writes/reads a hive image through Zw* file APIs on MemFs.
    let fs = RefCell::new(FileSystem::new(MemFs::with_fixture()));

    // First boot: fresh hive, seed via mutations, checkpoint to the file, journal one more write.
    {
        let provider = NtFileHiveIoProvider::open(&fs, SYSTEM_HIVE);
        let mut mgr = HiveManager::new(provider);
        let mut hive = mgr.boot(HiveKind::System).unwrap();
        mgr.mutate(
            &mut hive,
            HiveLogOp::CreateKey {
                path: r"ControlSet001\Services\Svc",
            },
        )
        .unwrap();
        mgr.mutate(
            &mut hive,
            HiveLogOp::SetValue {
                path: r"ControlSet001\Services\Svc",
                name: "Start",
                value_type: RegistryValueType::Dword,
                data: &3u32.to_le_bytes(),
            },
        )
        .unwrap();
        mgr.flush(&mut hive).unwrap(); // writes the image file, truncates the log file
        mgr.mutate(
            &mut hive,
            HiveLogOp::SetValue {
                path: r"ControlSet001\Services\Svc",
                name: "SeenByDriver",
                value_type: RegistryValueType::Dword,
                data: &1u32.to_le_bytes(),
            },
        )
        .unwrap(); // journaled to SYSTEM.LOG only
    }

    // The image file now exists on the volume.
    {
        let mut f = fs.borrow_mut();
        let r = f.zw_create_file(SYSTEM_HIVE, FILE_READ_DATA, 0, 0, FILE_OPEN, 0);
        assert!(
            f.zw_query_standard_information(r.handle)
                .unwrap()
                .end_of_file
                > 0
        );
        f.zw_close(r.handle);
    }

    // Restart the Hive Manager over the same volume: image + replayed log.
    {
        let provider = NtFileHiveIoProvider::open(&fs, SYSTEM_HIVE);
        let mut mgr = HiveManager::new(provider);
        let hive = mgr.boot(HiveKind::System).unwrap();
        let key = hive.open_key(r"ControlSet001\Services\Svc").unwrap();
        assert_eq!(hive.query_dword(key, "Start"), Some(3)); // from the image file
        assert_eq!(hive.query_dword(key, "SeenByDriver"), Some(1)); // from the replayed log file
    }
}
