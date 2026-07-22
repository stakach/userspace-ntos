use super::*;

#[test]
fn query_information_encodes_standard_layout() {
    let metadata = QueryMetadata {
        allocation_size: 0x2000,
        end_of_file: 0x1234,
        number_of_links: 2,
        delete_pending: true,
        directory: false,
    };
    let mut output = [0xCC; 40];
    assert_eq!(
        encode_query_information(FILE_STANDARD_INFORMATION, metadata, &mut output),
        Ok(24)
    );
    assert_eq!(u64::from_le_bytes(output[0..8].try_into().unwrap()), 0x2000);
    assert_eq!(u64::from_le_bytes(output[8..16].try_into().unwrap()), 0x1234);
    assert_eq!(u32::from_le_bytes(output[16..20].try_into().unwrap()), 2);
    assert_eq!(&output[20..24], &[1, 0, 0, 0]);
}

#[test]
fn query_information_rejects_bad_contracts_without_mutating_output() {
    let metadata = QueryMetadata::default();
    let mut output = [0xCC; 40];
    assert_eq!(
        encode_query_information(FILE_STANDARD_INFORMATION, metadata, &mut output[..23]),
        Err(STATUS_INFO_LENGTH_MISMATCH)
    );
    assert_eq!(&output[..23], &[0xCC; 23]);
    assert_eq!(
        encode_query_information(99, metadata, &mut output),
        Err(STATUS_INVALID_INFO_CLASS)
    );
    assert_eq!(&output, &[0xCC; 40]);
}
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
fn named_pipe_path_classification_is_exact() {
    let utf16 = |path: &str| path.encode_utf16().collect::<alloc::vec::Vec<_>>();
    assert!(is_named_pipe_path(&utf16(r"\??\pipe\ntsvcs")));
    assert!(is_named_pipe_path(&utf16(r"\DosDevices\pipe\ntsvcs")));
    assert!(is_named_pipe_path(&utf16(r"\Device\NamedPipe\lsarpc")));
    assert!(is_named_pipe_path(&utf16(r"\DEVICE\NAMEDPIPE\winreg")));
    assert!(!is_named_pipe_path(&utf16(r"\SystemRoot\System32\pipe.dll")));
    assert!(!is_named_pipe_path(&utf16(r"\Device\NamedPipe")));
}

#[test]
fn local_nt_paths_resolve_to_the_fat_volume() {
    let utf16 = |path: &str| path.encode_utf16().collect::<alloc::vec::Vec<_>>();
    for path in [
        r"\??\C:\ReactOS\WinSxS\Manifests\x.manifest",
        r"\DosDevices\C:\ReactOS\WinSxS\Manifests\x.manifest",
        r"C:/ReactOS/WinSxS/Manifests/x.manifest",
    ] {
        assert_eq!(
            nt_path_to_volume_relative(&utf16(path), b"reactos").unwrap(),
            b"reactos\\winsxs\\manifests\\x.manifest"
        );
    }
    assert_eq!(
        nt_path_to_volume_relative(
            &utf16(r"\SystemRoot\WinSxS\Manifests\x.manifest"),
            b"reactos"
        )
        .unwrap(),
        b"reactos\\winsxs\\manifests\\x.manifest"
    );
    assert_eq!(
        nt_path_to_volume_relative(&utf16(r"\??\C:\Windows\System32"), b"reactos").unwrap(),
        b"reactos\\system32"
    );
    assert_eq!(
        nt_path_to_volume_relative(&utf16(r"\??\C:\"), b"reactos").unwrap(),
        b""
    );
}

#[test]
fn local_nt_path_resolution_rejects_escapes_and_lookalikes() {
    let utf16 = |path: &str| path.encode_utf16().collect::<alloc::vec::Vec<_>>();
    for path in [
        r"\??\D:\ReactOS\x.manifest",
        r"\SystemRooted\x.manifest",
        r"\SystemRoot\..\x.manifest",
        r"\Device\HarddiskVolume1\x.manifest",
    ] {
        assert!(nt_path_to_volume_relative(&utf16(path), b"reactos").is_none());
    }
    assert!(nt_path_to_volume_relative(&[0x0100], b"reactos").is_none());
}

#[test]
fn query_attributes_by_path_no_handle() {
    let fs = FileSystem::new(MemFs::with_fixture());
    // A file resolves and reports non-directory — without allocating a handle.
    let si = fs
        .query_attributes(SYSTEM_HIVE)
        .expect("SYSTEM hive should resolve");
    assert!(!si.is_directory);
    // A directory resolves and reports is_directory.
    let d = fs
        .query_attributes(r"\SystemRoot\System32")
        .expect("System32 dir should resolve");
    assert!(d.is_directory);
    // A missing path → None (→ STATUS_OBJECT_NAME_NOT_FOUND at the syscall seam).
    assert!(fs
        .query_attributes(r"\SystemRoot\System32\Config\NOPE")
        .is_none());
    // A path outside any mount → None (no volume).
    assert!(fs.query_attributes(r"\Registry\Machine").is_none());
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

#[test]
fn cache_manager_over_memfs_file() {
    use nt_cache_manager::{FileSizes, SharedCacheMap};
    let fs = RefCell::new(FileSystem::new(MemFs::with_fixture()));
    // Create the backing file, then cache writes through to it (spec §22).
    {
        let mut f = fs.borrow_mut();
        f.zw_create_file(
            r"\??\C:\Temp\cached.bin",
            FILE_WRITE_DATA,
            0,
            0,
            FILE_CREATE,
            0,
        );
    }
    let sizes = FileSizes {
        allocation_size: 0,
        file_size: 0,
        valid_data_length: 0,
    };
    {
        let backing = FileBacking::open(&fs, r"\??\C:\Temp\cached.bin");
        let mut ccm = SharedCacheMap::cc_initialize_cache_map(backing, sizes, false);
        ccm.cc_copy_write(0, b"cached through memfs", false);
        assert!(ccm.cc_is_there_dirty_data());
        ccm.cc_flush_cache(None, None); // writes dirty pages back to the MemFs file
    }
    // The MemFs file now holds the data (read it directly via Zw*).
    {
        let mut f = fs.borrow_mut();
        let r = f.zw_create_file(
            r"\??\C:\Temp\cached.bin",
            FILE_READ_DATA,
            0,
            0,
            FILE_OPEN,
            0,
        );
        let (_, bytes) = f.zw_read_file(r.handle, Some(0), 20);
        f.zw_close(r.handle);
        assert_eq!(&bytes[..], b"cached through memfs");
    }
    // A fresh cache map faults the same bytes back in.
    {
        let backing = FileBacking::open(&fs, r"\??\C:\Temp\cached.bin");
        let mut ccm = SharedCacheMap::cc_initialize_cache_map(
            backing,
            FileSizes {
                allocation_size: 20,
                file_size: 20,
                valid_data_length: 20,
            },
            false,
        );
        let mut buf = [0u8; 20];
        let (_, n) = ccm.cc_copy_read(0, 20, &mut buf);
        assert_eq!((n, &buf[..]), (20, &b"cached through memfs"[..]));
    }
}
