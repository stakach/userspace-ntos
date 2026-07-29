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
/// `kernel32!CreateDirectoryExW` queries the TEMPLATE directory's `FileBasicInformation` and hands
/// the attributes it reads straight to the `NtCreateFile` that makes the copy, so the class has to
/// exist AND report the real kind. Serving only `FileStandardInformation` made every
/// `CreateDirectoryExW` fail STATUS_INVALID_INFO_CLASS => `GetLastError() == 87`.
#[test]
fn query_information_encodes_basic_information_attributes_by_kind() {
    let mut output = [0xCC; 48];
    let directory = QueryMetadata {
        directory: true,
        ..QueryMetadata::default()
    };
    assert_eq!(
        encode_query_information(FILE_BASIC_INFORMATION, directory, &mut output),
        Ok(40)
    );
    // The four timestamps are "no value" (0); the attributes say DIRECTORY.
    assert_eq!(&output[..32], &[0u8; 32]);
    assert_eq!(u32::from_le_bytes(output[32..36].try_into().unwrap()), 0x10);
    // …and the bytes past the structure are untouched.
    assert_eq!(&output[40..], &[0xCC; 8]);

    let file = QueryMetadata::default();
    assert_eq!(
        encode_query_information(FILE_BASIC_INFORMATION, file, &mut output),
        Ok(40)
    );
    assert_eq!(u32::from_le_bytes(output[32..36].try_into().unwrap()), 0x80);

    // A caller that offers less than the structure is refused, not truncated.
    assert_eq!(
        encode_query_information(FILE_BASIC_INFORMATION, file, &mut output[..39]),
        Err(STATUS_INFO_LENGTH_MISMATCH)
    );
}

/// `FileEaInformation` is the second class `CreateDirectoryExW` needs. A volume with no extended
/// attributes must answer `EaSize == 0` — which is both true and what makes the caller SKIP its
/// `NtQueryEaFile` loop rather than fail.
#[test]
fn query_information_encodes_zero_ea_size() {
    let mut output = [0xCC; 8];
    assert_eq!(
        encode_query_information(FILE_EA_INFORMATION, QueryMetadata::default(), &mut output),
        Ok(4)
    );
    assert_eq!(u32::from_le_bytes(output[0..4].try_into().unwrap()), 0);
    assert_eq!(&output[4..], &[0xCC; 4]);
    assert_eq!(
        encode_query_information(
            FILE_EA_INFORMATION,
            QueryMetadata::default(),
            &mut output[..3]
        ),
        Err(STATUS_INFO_LENGTH_MISMATCH)
    );
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
        nt_path_to_volume_relative(&utf16(r"\??\C:\Windows"), b"reactos").unwrap(),
        b"reactos"
    );
    assert_eq!(
        nt_path_to_volume_relative(&utf16(r"\??\C:\"), b"reactos").unwrap(),
        b""
    );
}

#[test]
fn fat_attributes_translate_to_native_file_attributes() {
    assert_eq!(file_attributes_from_fat(0), FILE_ATTRIBUTE_NORMAL);
    assert_eq!(file_attributes_from_fat(0x10), FILE_ATTRIBUTE_DIRECTORY);
    assert_eq!(file_attributes_from_fat(0x21), 0x21);
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

// ---------------------------------------------------------------------------
// The WRITABLE OVERLAY seam (spec §13.4): a general "writable mount at prefix P"
// namespace test, plus the volume operations a real writable file system owes a
// caller — directory create, write, read back, enumerate, set-information, delete.
// ---------------------------------------------------------------------------

fn wide(s: &str) -> alloc::vec::Vec<u16> {
    s.encode_utf16().collect()
}

#[test]
fn writable_mount_covers_a_prefix_subtree_only() {
    const PREFIXES: &[&[u8]] = &[b"profiles"];
    // At the prefix, and under it at any depth.
    assert_eq!(
        writable_mount_relative(&wide(r"\??\C:\Profiles"), b"reactos", PREFIXES).as_deref(),
        Some(&b"profiles"[..])
    );
    assert_eq!(
        writable_mount_relative(&wide(r"\??\C:\Profiles\Administrator\ntuser.dat"), b"reactos", PREFIXES)
            .as_deref(),
        Some(&b"profiles\\administrator\\ntuser.dat"[..])
    );
    // The DosDevices and bare-drive spellings resolve to the same relative path.
    assert_eq!(
        writable_mount_relative(&wide(r"\DosDevices\C:\PROFILES\x"), b"reactos", PREFIXES).as_deref(),
        Some(&b"profiles\\x"[..])
    );
    // OUTSIDE the prefix: the read-only namespace keeps them.
    assert!(writable_mount_relative(&wide(r"\??\C:\Windows\system.ini"), b"reactos", PREFIXES).is_none());
    assert!(writable_mount_relative(&wide(r"\SystemRoot\system32\ntdll.dll"), b"reactos", PREFIXES).is_none());
    // Component-wise: a longer sibling name is NOT under the prefix.
    assert!(writable_mount_relative(&wide(r"\??\C:\Profiles2\x"), b"reactos", PREFIXES).is_none());
    // Escapes are still rejected by the shared canonicaliser.
    assert!(writable_mount_relative(&wide(r"\??\C:\Profiles\..\Windows"), b"reactos", PREFIXES).is_none());
}

#[test]
fn writable_volume_creates_writes_reads_and_enumerates() {
    let mut fs = FileSystem::new(MemFs::new());
    // CreateDirectoryW's syscall: FILE_CREATE + FILE_DIRECTORY_FILE.
    let dir = fs.zw_create_file(
        r"\??\C:\profiles",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!((dir.status, dir.information), (STATUS_SUCCESS, FILE_CREATED));
    // A second CreateDirectoryW on the same name collides (ERROR_ALREADY_EXISTS).
    let again = fs.zw_create_file(
        r"\??\C:\profiles",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(again.status, STATUS_OBJECT_NAME_COLLISION);
    // A file inside it: create, write, read back at an explicit offset.
    let file = fs.zw_create_file(
        r"\??\C:\profiles\ntuser.dat",
        FILE_WRITE_DATA,
        FILE_ATTRIBUTE_HIDDEN,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!((file.status, file.information), (STATUS_SUCCESS, FILE_CREATED));
    assert_eq!(fs.zw_write_file(file.handle, None, b"regf"), (STATUS_SUCCESS, 4));
    assert_eq!(fs.current_offset(file.handle), Some(4));
    let (status, bytes) = fs.zw_read_file(file.handle, Some(0), 16);
    assert_eq!((status, &bytes[..]), (STATUS_SUCCESS, &b"regf"[..]));
    let info = fs.zw_query_standard_information(file.handle).unwrap();
    assert_eq!((info.end_of_file, info.is_directory), (4, false));
    assert_eq!(info.attributes, FILE_ATTRIBUTE_HIDDEN);
    fs.zw_close(file.handle);

    // Enumerate the directory: `.`, `..`, then the child, through the native encoder.
    let mut out = [0u8; 512];
    let r = fs.zw_query_directory_file(dir.handle, FILE_DIRECTORY_INFORMATION, false, None, false, &mut out);
    assert_eq!(r.status, STATUS_SUCCESS);
    let mut names = alloc::vec::Vec::new();
    let mut off = 0usize;
    loop {
        let next = u32::from_le_bytes(out[off..off + 4].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(out[off + 60..off + 64].try_into().unwrap()) as usize;
        let name: alloc::string::String = out[off + 64..off + 64 + name_len]
            .chunks(2)
            .map(|c| char::from(c[0]))
            .collect();
        names.push(name);
        if next == 0 {
            break;
        }
        off += next;
    }
    assert_eq!(names, ["." , "..", "ntuser.dat"]);
    // A second call with no restart is at the end of the scan.
    let more = fs.zw_query_directory_file(dir.handle, FILE_DIRECTORY_INFORMATION, false, None, false, &mut out);
    assert_eq!(more.status, STATUS_NO_MORE_FILES);
    // RestartScan rewinds it.
    let restart = fs.zw_query_directory_file(dir.handle, FILE_DIRECTORY_INFORMATION, false, None, true, &mut out);
    assert_eq!(restart.status, STATUS_SUCCESS);
}

#[test]
fn writable_volume_set_information_and_delete() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\profiles"));
    let f = fs.zw_create_file(r"\??\C:\profiles\a.txt", FILE_WRITE_DATA, 0, 0, FILE_CREATE, 0);
    assert_eq!(fs.zw_write_file(f.handle, None, b"0123456789"), (STATUS_SUCCESS, 10));
    // FileEndOfFileInformation truncates.
    assert_eq!(
        fs.zw_set_information_file(f.handle, FILE_END_OF_FILE_INFORMATION, &4u64.to_le_bytes()),
        STATUS_SUCCESS
    );
    assert_eq!(fs.zw_query_standard_information(f.handle).unwrap().end_of_file, 4);
    // FilePositionInformation moves the file object's offset.
    assert_eq!(
        fs.zw_set_information_file(f.handle, FILE_POSITION_INFORMATION, &2u64.to_le_bytes()),
        STATUS_SUCCESS
    );
    assert_eq!(fs.current_offset(f.handle), Some(2));
    let (_, tail) = fs.zw_read_file(f.handle, None, 8);
    assert_eq!(&tail[..], b"23");
    // An unhandled class is reported honestly, not silently succeeded.
    assert_eq!(
        fs.zw_set_information_file(f.handle, FILE_RENAME_INFORMATION, &[0u8; 24]),
        STATUS_NOT_IMPLEMENTED
    );
    // FileDispositionInformation deletes at close.
    assert_eq!(
        fs.zw_set_information_file(f.handle, FILE_DISPOSITION_INFORMATION, &[1u8]),
        STATUS_SUCCESS
    );
    fs.zw_close(f.handle);
    assert!(fs.query_attributes(r"\??\C:\profiles\a.txt").is_none());
    // The directory itself survived, and is still a directory.
    let d = fs.query_attributes(r"\??\C:\profiles").unwrap();
    assert!(d.is_directory && d.attributes & FILE_ATTRIBUTE_DIRECTORY != 0);
}

#[test]
fn writable_volume_rejects_a_create_whose_parent_is_missing() {
    let mut fs = FileSystem::new(MemFs::new());
    let r = fs.zw_create_file(
        r"\??\C:\profiles\Administrator",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(r.status, STATUS_OBJECT_PATH_NOT_FOUND);
    assert_eq!(r.handle, INVALID_HANDLE);
}

/// PROVISIONING a file (the content an installed volume already carries) creates every missing
/// directory above it, is reachable through the ORDINARY by-path surface, enumerates as a normal
/// child of its parent, and reads back byte-identical through `ZwReadFile`.
#[test]
fn provisioned_file_is_a_real_enumerable_file() {
    const HIVE: &[u8] = b"regf\x02\x00\x00\x00 default-hive body";
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(r"\??\C:\profiles\Default User\ntuser.dat", HIVE));
    // (1) The parent chain really exists, as DIRECTORIES.
    for dir in [r"\??\C:\profiles", r"\??\C:\profiles\Default User"] {
        let info = fs.query_attributes(dir).expect("provisioned parent");
        assert!(info.is_directory);
    }
    // (2) The leaf is a FILE with the right size, by path, with no handle.
    let info = fs.query_attributes(r"\??\C:\profiles\Default User\ntuser.dat").unwrap();
    assert!(!info.is_directory);
    assert_eq!(info.end_of_file, HIVE.len() as u64);
    // (3) It borrows back in place, byte-identical.
    assert_eq!(fs.file_bytes(r"\??\C:\profiles\Default User\ntuser.dat"), Some(HIVE));
    // (4) An ordinary open + read returns the same bytes.
    let f = fs.zw_create_file(
        r"\??\C:\profiles\Default User\ntuser.dat",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(f.status, STATUS_SUCCESS);
    assert_eq!(f.information, FILE_OPENED);
    let (status, bytes) = fs.zw_read_file(f.handle, Some(0), HIVE.len());
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(bytes, HIVE);
    fs.zw_close(f.handle);
    // (5) …and it ENUMERATES as a normal child of its directory (`.`, `..`, ntuser.dat).
    let dir = fs.zw_create_file(
        r"\??\C:\profiles\Default User",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(dir.status, STATUS_SUCCESS);
    let mut out = [0u8; 512];
    let r = fs.zw_query_directory_file(dir.handle, FILE_DIRECTORY_INFORMATION, false, None, true, &mut out);
    assert_eq!(r.status, STATUS_SUCCESS);
    let mut names = alloc::vec::Vec::new();
    let mut off = 0usize;
    loop {
        let next = u32::from_le_bytes(out[off..off + 4].try_into().unwrap()) as usize;
        let name_len = u32::from_le_bytes(out[off + 60..off + 64].try_into().unwrap()) as usize;
        let name: alloc::string::String = out[off + 64..off + 64 + name_len]
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]) as u8 as char)
            .collect();
        names.push(name);
        if next == 0 {
            break;
        }
        off += next;
    }
    assert_eq!(names, [".", "..", "ntuser.dat"]);
    fs.zw_close(dir.handle);
}

/// Provisioning REPLACES an existing file's bytes exactly (no append, no stale tail), refuses a
/// path that names a directory, and refuses a path off this volume. `file_bytes` misses honestly.
#[test]
fn provisioning_replaces_bytes_and_refuses_non_files() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(r"\??\C:\profiles\Default User\ntuser.dat", b"0123456789"));
    assert!(fs.provision_file(r"\??\C:\profiles\Default User\ntuser.dat", b"abc"));
    assert_eq!(fs.file_bytes(r"\??\C:\profiles\Default User\ntuser.dat"), Some(&b"abc"[..]));
    assert_eq!(
        fs.query_attributes(r"\??\C:\profiles\Default User\ntuser.dat").unwrap().end_of_file,
        3
    );
    // A directory is not a file.
    assert!(!fs.provision_file(r"\??\C:\profiles\Default User", b"x"));
    assert_eq!(fs.file_bytes(r"\??\C:\profiles\Default User"), None);
    // A path that never resolved is an honest miss.
    assert_eq!(fs.file_bytes(r"\??\C:\profiles\nope.dat"), None);
}
