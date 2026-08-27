use super::*;

struct MemoryBlockDevice {
    sector_size: usize,
    data: alloc::vec::Vec<u8>,
    reads: usize,
    writes: usize,
    fail_write: Option<usize>,
}

impl MemoryBlockDevice {
    fn new(sector_size: usize, sectors: usize) -> Self {
        Self {
            sector_size,
            data: alloc::vec![0; sector_size * sectors],
            reads: 0,
            writes: 0,
            fail_write: None,
        }
    }

    fn fail_next_write(&mut self) {
        self.fail_write = Some(self.writes);
    }

    fn corrupt(&mut self, lba: u64, offset: usize) {
        let index = lba as usize * self.sector_size + offset;
        self.data[index] ^= 0x55;
    }

    fn reset_reads(&mut self) {
        self.reads = 0;
    }
}

impl SnapshotBlockDevice for MemoryBlockDevice {
    fn sector_size(&self) -> usize {
        self.sector_size
    }

    fn sector_count(&self) -> u64 {
        (self.data.len() / self.sector_size) as u64
    }

    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        if out.len() != self.sector_size || lba >= self.sector_count() {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        self.reads += 1;
        let start = lba as usize * self.sector_size;
        out.copy_from_slice(&self.data[start..start + self.sector_size]);
        Ok(())
    }

    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        if data.len() != self.sector_size || lba >= self.sector_count() {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        if self.fail_write == Some(self.writes) {
            self.writes += 1;
            self.fail_write = None;
            return Err(SnapshotBlockStoreError::Io);
        }
        self.writes += 1;
        let start = lba as usize * self.sector_size;
        self.data[start..start + self.sector_size].copy_from_slice(data);
        Ok(())
    }
}

struct BulkCountingBlockDevice {
    inner: MemoryBlockDevice,
    bulk_writes: usize,
    bulk_sectors: usize,
}

impl BulkCountingBlockDevice {
    fn new(sector_size: usize, sectors: usize) -> Self {
        Self {
            inner: MemoryBlockDevice::new(sector_size, sectors),
            bulk_writes: 0,
            bulk_sectors: 0,
        }
    }
}

impl SnapshotBlockDevice for BulkCountingBlockDevice {
    fn sector_size(&self) -> usize {
        self.inner.sector_size()
    }

    fn sector_count(&self) -> u64 {
        self.inner.sector_count()
    }

    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        self.inner.read_sector(lba, out)
    }

    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        self.inner.write_sector(lba, data)
    }

    fn write_sectors(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        let sector_size = self.sector_size();
        if sector_size == 0 || data.len() % sector_size != 0 {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        self.bulk_writes += 1;
        self.bulk_sectors += data.len() / sector_size;
        let mut next_lba = lba;
        for sector in data.chunks_exact(sector_size) {
            self.inner.write_sector(next_lba, sector)?;
            next_lba += 1;
        }
        Ok(())
    }
}

#[test]
fn query_information_encodes_standard_layout() {
    let metadata = QueryMetadata {
        allocation_size: 0x2000,
        end_of_file: 0x1234,
        current_byte_offset: 0,
        access_flags: 0,
        mode: 0,
        alignment_requirement: 0,
        number_of_links: 2,
        delete_pending: true,
        directory: false,
        ..QueryMetadata::default()
    };
    let mut output = [0xCC; 40];
    assert_eq!(
        encode_query_information(FILE_STANDARD_INFORMATION, metadata, &mut output),
        Ok(24)
    );
    assert_eq!(u64::from_le_bytes(output[0..8].try_into().unwrap()), 0x2000);
    assert_eq!(
        u64::from_le_bytes(output[8..16].try_into().unwrap()),
        0x1234
    );
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

#[test]
fn query_information_encodes_filesystem_owned_metadata() {
    let metadata = QueryMetadata {
        creation_time: 0x0102_0304_0506_0708,
        last_access_time: 0x1112_1314_1516_1718,
        last_write_time: 0x2122_2324_2526_2728,
        change_time: 0x3132_3334_3536_3738,
        allocation_size: 0x5000,
        end_of_file: 0x4321,
        file_id: 0x4142_4344_4546_4748,
        file_attributes: FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE,
        reparse_tag: 0xA000_000C,
        ..QueryMetadata::default()
    };

    let mut internal = [0xCC; 12];
    assert_eq!(
        encode_query_information(FILE_INTERNAL_INFORMATION, metadata, &mut internal),
        Ok(8)
    );
    assert_eq!(
        u64::from_le_bytes(internal[..8].try_into().unwrap()),
        metadata.file_id
    );
    assert_eq!(&internal[8..], &[0xCC; 4]);

    let mut network = [0xCC; 60];
    assert_eq!(
        encode_query_information(FILE_NETWORK_OPEN_INFORMATION, metadata, &mut network),
        Ok(56)
    );
    for (offset, expected) in [
        (0, metadata.creation_time),
        (8, metadata.last_access_time),
        (16, metadata.last_write_time),
        (24, metadata.change_time),
        (32, metadata.allocation_size),
        (40, metadata.end_of_file),
    ] {
        assert_eq!(
            u64::from_le_bytes(network[offset..offset + 8].try_into().unwrap()),
            expected
        );
    }
    assert_eq!(
        u32::from_le_bytes(network[48..52].try_into().unwrap()),
        metadata.file_attributes
    );
    assert_eq!(&network[52..56], &[0; 4]);
    assert_eq!(&network[56..], &[0xCC; 4]);

    let mut tag = [0xCC; 8];
    assert_eq!(
        encode_query_information(FILE_ATTRIBUTE_TAG_INFORMATION, metadata, &mut tag),
        Ok(8)
    );
    assert_eq!(
        u32::from_le_bytes(tag[..4].try_into().unwrap()),
        metadata.file_attributes
    );
    assert_eq!(u32::from_le_bytes(tag[4..].try_into().unwrap()), 0);

    let reparsed = QueryMetadata {
        file_attributes: FILE_ATTRIBUTE_REPARSE_POINT,
        ..metadata
    };
    assert_eq!(
        encode_query_information(FILE_ATTRIBUTE_TAG_INFORMATION, reparsed, &mut tag),
        Ok(8)
    );
    assert_eq!(
        u32::from_le_bytes(tag[4..].try_into().unwrap()),
        metadata.reparse_tag
    );

    for (class, short) in [
        (FILE_INTERNAL_INFORMATION, 7usize),
        (FILE_NETWORK_OPEN_INFORMATION, 55),
        (FILE_ATTRIBUTE_TAG_INFORMATION, 7),
    ] {
        let mut output = [0xCC; 56];
        assert_eq!(
            encode_query_information(class, metadata, &mut output[..short]),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
        assert!(output[..short].iter().all(|byte| *byte == 0xCC));
    }
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

#[test]
fn query_information_encodes_file_position() {
    let mut output = [0xCC; 16];
    let metadata = QueryMetadata {
        current_byte_offset: 0x1122_3344_5566_7788,
        ..QueryMetadata::default()
    };
    assert_eq!(
        encode_query_information(FILE_POSITION_INFORMATION, metadata, &mut output),
        Ok(8)
    );
    assert_eq!(
        u64::from_le_bytes(output[0..8].try_into().unwrap()),
        0x1122_3344_5566_7788
    );
    assert_eq!(&output[8..], &[0xCC; 8]);
    assert_eq!(
        encode_query_information(FILE_POSITION_INFORMATION, metadata, &mut output[..7]),
        Err(STATUS_INFO_LENGTH_MISMATCH)
    );
}

#[test]
fn query_information_encodes_io_manager_owned_fields() {
    let metadata = QueryMetadata {
        access_flags: 0x0012_0089,
        mode: FILE_WRITE_THROUGH | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
        alignment_requirement: 0x1ff,
        ..QueryMetadata::default()
    };
    let mut output = [0xCC; 8];
    for (class, expected) in [
        (FILE_ACCESS_INFORMATION, metadata.access_flags),
        (FILE_MODE_INFORMATION, metadata.mode),
        (FILE_ALIGNMENT_INFORMATION, metadata.alignment_requirement),
    ] {
        output.fill(0xCC);
        assert_eq!(
            encode_query_information(class, metadata, &mut output),
            Ok(4)
        );
        assert_eq!(
            u32::from_le_bytes(output[..4].try_into().unwrap()),
            expected
        );
        assert_eq!(&output[4..], &[0xCC; 4]);
        assert_eq!(
            encode_query_information(class, metadata, &mut output[..3]),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
    }
}

#[test]
fn query_information_encodes_name_and_overflow_prefix() {
    let name = wide(r"\ReactOS\System32\ntdll.dll");
    let full_len = 4 + name.len() * 2;
    let mut full = alloc::vec![0xCC; full_len + 4];
    assert_eq!(
        encode_named_query_information(
            FILE_NAME_INFORMATION,
            QueryMetadata::default(),
            &name,
            &mut full,
        ),
        Ok(QueryInformationResult {
            status: STATUS_SUCCESS,
            information: full_len,
        })
    );
    assert_eq!(
        u32::from_le_bytes(full[..4].try_into().unwrap()),
        (name.len() * 2) as u32
    );
    assert_eq!(&full[full_len..], &[0xCC; 4]);

    let mut short = [0xCC; 15];
    assert_eq!(
        encode_named_query_information(
            FILE_NAME_INFORMATION,
            QueryMetadata::default(),
            &name,
            &mut short,
        ),
        Ok(QueryInformationResult {
            status: STATUS_BUFFER_OVERFLOW,
            information: short.len(),
        })
    );
    assert_eq!(
        u32::from_le_bytes(short[..4].try_into().unwrap()),
        (name.len() * 2) as u32
    );
    assert_eq!(&short[4..14], &full[4..14]);
    assert_eq!(short[14], full[14]);

    let mut too_short = [0xCC; 7];
    assert_eq!(
        encode_named_query_information(
            FILE_NAME_INFORMATION,
            QueryMetadata::default(),
            &name,
            &mut too_short,
        ),
        Err(STATUS_INFO_LENGTH_MISMATCH)
    );
    assert_eq!(too_short, [0xCC; 7]);
}

#[test]
fn query_information_encodes_fat_alternate_name_and_overflow_prefix() {
    let name = wide(r"LONGNA~1.TXT");
    let full_len = 4 + name.len() * 2;
    let mut full = alloc::vec![0xCC; full_len + 4];
    assert_eq!(
        encode_named_query_information(
            FILE_ALTERNATE_NAME_INFORMATION,
            QueryMetadata::default(),
            &name,
            &mut full,
        ),
        Ok(QueryInformationResult {
            status: STATUS_SUCCESS,
            information: full_len,
        })
    );
    assert_eq!(
        u32::from_le_bytes(full[..4].try_into().unwrap()),
        (name.len() * 2) as u32
    );
    assert_eq!(&full[full_len..], &[0xCC; 4]);

    let mut short = [0xCC; 11];
    assert_eq!(
        encode_named_query_information(
            FILE_ALTERNATE_NAME_INFORMATION,
            QueryMetadata::default(),
            &name,
            &mut short,
        ),
        Ok(QueryInformationResult {
            status: STATUS_BUFFER_OVERFLOW,
            information: short.len(),
        })
    );
    assert_eq!(
        u32::from_le_bytes(short[..4].try_into().unwrap()),
        (name.len() * 2) as u32
    );
    assert_eq!(&short[4..], &full[4..short.len()]);
}

#[test]
fn query_information_encodes_the_local_unnamed_data_stream() {
    let metadata = QueryMetadata {
        end_of_file: 0x1234,
        allocation_size: 0x2000,
        ..QueryMetadata::default()
    };
    let mut output = [0xCC; 42];
    assert_eq!(
        encode_stream_information(metadata, &mut output),
        Ok(QueryInformationResult {
            status: STATUS_SUCCESS,
            information: 38,
        })
    );
    assert_eq!(u32::from_le_bytes(output[0..4].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(output[4..8].try_into().unwrap()), 14);
    assert_eq!(
        u64::from_le_bytes(output[8..16].try_into().unwrap()),
        0x1234
    );
    assert_eq!(
        u64::from_le_bytes(output[16..24].try_into().unwrap()),
        0x2000
    );
    assert_eq!(&output[24..38], b":\0:\0$\0D\0A\0T\0A\0");
    assert_eq!(&output[38..], &[0xCC; 4]);

    let mut truncated = [0xCC; FILE_STREAM_INFORMATION_MINIMUM_LENGTH];
    assert_eq!(
        encode_stream_information(metadata, &mut truncated),
        Ok(QueryInformationResult {
            status: STATUS_BUFFER_OVERFLOW,
            information: 0,
        })
    );
    assert_eq!(truncated, [0xCC; FILE_STREAM_INFORMATION_MINIMUM_LENGTH]);

    let mut directory = [0xCC; FILE_STREAM_INFORMATION_MINIMUM_LENGTH];
    assert_eq!(
        encode_stream_information(
            QueryMetadata {
                directory: true,
                ..metadata
            },
            &mut directory,
        ),
        Ok(QueryInformationResult {
            status: STATUS_SUCCESS,
            information: 0,
        })
    );
    assert_eq!(directory, [0xCC; FILE_STREAM_INFORMATION_MINIMUM_LENGTH]);
}

#[test]
fn query_information_encodes_uncompressed_and_reparse_capabilities() {
    let metadata = QueryMetadata {
        end_of_file: 0x1234,
        file_id: 0x5566,
        file_attributes: FILE_ATTRIBUTE_REPARSE_POINT,
        reparse_tag: 0xA000_000C,
        ..QueryMetadata::default()
    };
    let mut compression = [0xCC; FILE_COMPRESSION_INFORMATION_LENGTH];
    assert_eq!(
        encode_query_information(FILE_COMPRESSION_INFORMATION, metadata, &mut compression),
        Ok(FILE_COMPRESSION_INFORMATION_LENGTH)
    );
    assert_eq!(
        u64::from_le_bytes(compression[0..8].try_into().unwrap()),
        metadata.end_of_file
    );
    assert_eq!(&compression[8..], &[0; 8]);

    let mut reparse = [0xCC; FILE_REPARSE_POINT_INFORMATION_LENGTH];
    assert_eq!(
        encode_reparse_point_information(metadata, &mut reparse),
        Ok(FILE_REPARSE_POINT_INFORMATION_LENGTH)
    );
    assert_eq!(
        u64::from_le_bytes(reparse[0..8].try_into().unwrap()),
        0x5566
    );
    assert_eq!(
        u32::from_le_bytes(reparse[8..12].try_into().unwrap()),
        0xA000_000C
    );
    assert_eq!(&reparse[12..], &[0; 4]);
    assert_eq!(
        encode_reparse_point_information(
            QueryMetadata {
                file_attributes: FILE_ATTRIBUTE_NORMAL,
                reparse_tag: 0,
                ..metadata
            },
            &mut reparse,
        ),
        Err(STATUS_NOT_A_REPARSE_POINT)
    );
}

#[test]
fn query_information_rejects_absent_optional_filesystem_facilities_after_dispatch() {
    assert_eq!(
        absent_optional_query_facility_status(FILE_OBJECT_ID_INFORMATION),
        Some(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        absent_optional_query_facility_status(FILE_QUOTA_INFORMATION),
        Some(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        absent_optional_query_facility_status(FILE_INTERNAL_INFORMATION),
        None
    );
}

#[test]
fn query_information_composes_file_all_information() {
    let metadata = QueryMetadata {
        creation_time: 1,
        last_access_time: 2,
        last_write_time: 3,
        change_time: 4,
        allocation_size: 0x2000,
        end_of_file: 0x1234,
        file_id: 0x5566,
        file_attributes: FILE_ATTRIBUTE_ARCHIVE,
        current_byte_offset: 0x88,
        access_flags: 0x0012_0089,
        mode: FILE_SYNCHRONOUS_IO_NONALERT,
        alignment_requirement: 0x1ff,
        number_of_links: 3,
        delete_pending: true,
        directory: false,
        ..QueryMetadata::default()
    };
    let name = wide(r"\x");
    let mut output = [0xCC; 104];
    assert_eq!(
        encode_named_query_information(FILE_ALL_INFORMATION, metadata, &name, &mut output),
        Ok(QueryInformationResult {
            status: STATUS_SUCCESS,
            information: 104,
        })
    );
    assert_eq!(u64::from_le_bytes(output[0..8].try_into().unwrap()), 1);
    assert_eq!(
        u64::from_le_bytes(output[40..48].try_into().unwrap()),
        0x2000
    );
    assert_eq!(
        u64::from_le_bytes(output[64..72].try_into().unwrap()),
        0x5566
    );
    assert_eq!(
        u32::from_le_bytes(output[76..80].try_into().unwrap()),
        metadata.access_flags
    );
    assert_eq!(
        u64::from_le_bytes(output[80..88].try_into().unwrap()),
        metadata.current_byte_offset
    );
    assert_eq!(
        u32::from_le_bytes(output[88..92].try_into().unwrap()),
        metadata.mode
    );
    assert_eq!(
        u32::from_le_bytes(output[92..96].try_into().unwrap()),
        metadata.alignment_requirement
    );
    assert_eq!(u32::from_le_bytes(output[96..100].try_into().unwrap()), 4);
    assert_eq!(&output[100..104], &[b'\\', 0, b'x', 0]);

    let long_name = wide(r"\directory\file.txt");
    let mut short = [0xCC; 105];
    assert_eq!(
        encode_named_query_information(FILE_ALL_INFORMATION, metadata, &long_name, &mut short),
        Ok(QueryInformationResult {
            status: STATUS_BUFFER_OVERFLOW,
            information: short.len(),
        })
    );
    assert_eq!(
        u32::from_le_bytes(short[96..100].try_into().unwrap()),
        (long_name.len() * 2) as u32
    );
    assert_eq!(&short[100..104], &[b'\\', 0, b'd', 0]);

    let mut too_short = [0xCC; 103];
    assert_eq!(
        encode_named_query_information(FILE_ALL_INFORMATION, metadata, &long_name, &mut too_short,),
        Err(STATUS_INFO_LENGTH_MISMATCH)
    );
    assert_eq!(too_short, [0xCC; 103]);
}

#[test]
fn file_all_information_seeds_only_io_manager_owned_fields() {
    let metadata = QueryMetadata {
        access_flags: 0x0012_0089,
        mode: FILE_SYNCHRONOUS_IO_NONALERT,
        alignment_requirement: 0x1ff,
        ..QueryMetadata::default()
    };
    let mut output = [0xCC; FILE_ALL_INFORMATION_MINIMUM_LENGTH];
    assert_eq!(
        encode_file_all_io_manager_information(metadata, &mut output),
        Ok(())
    );
    assert!(output[..76].iter().all(|byte| *byte == 0xCC));
    assert_eq!(&output[76..80], &metadata.access_flags.to_le_bytes());
    assert!(output[80..88].iter().all(|byte| *byte == 0xCC));
    assert_eq!(&output[88..92], &metadata.mode.to_le_bytes());
    assert_eq!(
        &output[92..96],
        &metadata.alignment_requirement.to_le_bytes()
    );
    assert!(output[96..].iter().all(|byte| *byte == 0xCC));

    let mut short = [0xCC; FILE_ALL_INFORMATION_MINIMUM_LENGTH - 1];
    assert_eq!(
        encode_file_all_io_manager_information(metadata, &mut short),
        Err(STATUS_INFO_LENGTH_MISMATCH)
    );
    assert_eq!(short, [0xCC; FILE_ALL_INFORMATION_MINIMUM_LENGTH - 1]);
}

#[test]
fn file_mode_retains_only_file_object_mode_options() {
    let persistent = FILE_WRITE_THROUGH
        | FILE_SEQUENTIAL_ONLY
        | FILE_NO_INTERMEDIATE_BUFFERING
        | FILE_SYNCHRONOUS_IO_ALERT
        | FILE_DELETE_ON_CLOSE;
    let transient = FILE_NON_DIRECTORY_FILE | 0x0000_0800 | 0x0020_0000;
    assert_eq!(
        file_mode_from_create_options(persistent | transient),
        persistent
    );

    let mut fs = FileSystem::new(MemFs::with_fixture());
    let opened = fs.zw_create_file(
        SYSTEM_HIVE,
        FILE_READ_DATA | DELETE | SYNCHRONIZE,
        0,
        0,
        FILE_OPEN,
        persistent | transient,
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    assert_eq!(fs.file_mode(opened.handle), Some(persistent));
}

use core::cell::RefCell;
use nt_hive_core::{HiveIoProvider, HiveKind, HiveLogOp, HiveManager, RegistryValueType};

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
    let (drive_map, drive_type) = mm.process_device_map();
    assert_eq!(drive_map & (1 << 2), 1 << 2);
    assert_eq!(drive_type[2], DOS_DRIVE_FIXED);
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
    assert!(!is_named_pipe_path(&utf16(
        r"\SystemRoot\System32\pipe.dll"
    )));
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
        nt_path_to_volume_relative(&utf16(r"\??\C:\Program Files\Common Files"), b"reactos")
            .unwrap(),
        b"program files\\common files"
    );
    assert_eq!(
        nt_path_to_volume_relative(&utf16(r"\??\C:\"), b"reactos").unwrap(),
        b""
    );
    assert_eq!(
        nt_path_to_volume_relative(&utf16(r"\??\C:"), b"reactos").unwrap(),
        b""
    );
    assert_eq!(
        nt_path_to_volume_relative(&utf16(r"\DosDevices\C:"), b"reactos").unwrap(),
        b""
    );
}

#[test]
fn mounted_dos_drives_publish_process_device_map() {
    let mut mm = MountManager::new();
    mm.mount(r"\??\D:", MEMFS_VOLUME);
    let (drive_map, drive_type) = mm.process_device_map();
    assert_eq!(drive_map & (1 << 2), 1 << 2);
    assert_eq!(drive_map & (1 << 3), 1 << 3);
    assert_eq!(drive_type[2], DOS_DRIVE_FIXED);
    assert_eq!(drive_type[3], DOS_DRIVE_FIXED);
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
fn path_to_volume_relative_into_matches_allocating_api() {
    let path = wide(r"\??\C:\Windows\System32\Config\SYSTEM");
    let mut folded = [0u8; 128];
    let mut out = [0u8; 128];
    let len = nt_path_to_volume_relative_into(&path, b"reactos", &mut folded, &mut out)
        .expect("path should resolve");
    assert_eq!(&out[..len], b"reactos\\system32\\config\\system");
    assert_eq!(
        nt_path_to_volume_relative(&path, b"reactos").as_deref(),
        Some(&out[..len])
    );

    let root = wide(r"\??\C:\");
    let len = nt_path_to_volume_relative_into(&root, b"reactos", &mut folded, &mut out)
        .expect("drive root should resolve");
    assert_eq!(&out[..len], b"");
}

#[test]
fn file_relative_path_into_is_bounded_and_canonical() {
    let path = wide(r"Profiles//.\Administrator\NTUSER.DAT");
    let mut folded = [0u8; 64];
    let mut out = [0u8; 64];
    let len = nt_file_relative_path_into(&path, &mut folded, &mut out).unwrap();
    assert_eq!(&out[..len], b"profiles\\administrator\\ntuser.dat");
    assert!(nt_file_relative_path_into(&wide(r"\absolute"), &mut folded, &mut out).is_none());
    assert!(nt_file_relative_path_into(&wide(r"..\escape"), &mut folded, &mut out).is_none());
    assert!(nt_file_relative_path_into(&wide(r"c:leaf"), &mut folded, &mut out).is_none());
    assert!(nt_file_relative_path_into(&[], &mut folded, &mut out).is_none());
    assert!(nt_file_relative_path_into(&wide("toolong"), &mut [0u8; 4], &mut out).is_none());
}

#[test]
fn writable_mount_relative_into_and_relative_query_are_canonical() {
    const PREFIXES: &[&[u8]] = &[b"profiles"];
    let path = wide(r"\DosDevices\C:\PROFILES\Administrator\ntuser.dat");
    let mut folded = [0u8; 128];
    let mut relative = [0u8; 128];
    let len = writable_mount_relative_into(&path, b"reactos", PREFIXES, &mut folded, &mut relative)
        .expect("path should resolve under writable prefix");
    assert_eq!(&relative[..len], b"profiles\\administrator\\ntuser.dat");

    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\profiles\Administrator"));
    assert!(fs.provision_file(r"\??\C:\profiles\Administrator\ntuser.dat", b"regf"));
    let attrs = fs
        .query_attributes_relative(&relative[..len])
        .expect("relative query should find provisioned file");
    assert!(!attrs.is_directory);
}

#[test]
fn relative_create_uses_folded_volume_paths_directly() {
    let mut fs = FileSystem::new(MemFs::new());
    let dir = fs.zw_create_file_relative(
        b"profiles",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(
        (dir.status, dir.information),
        (STATUS_SUCCESS, FILE_CREATED)
    );

    let file = fs.zw_create_file_relative(
        b"profiles\\administrator\\ntuser.dat",
        FILE_WRITE_DATA,
        FILE_ATTRIBUTE_HIDDEN,
        0,
        FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(
        (file.status, file.information),
        (STATUS_OBJECT_PATH_NOT_FOUND, 0)
    );

    assert!(fs.provision_directory(r"\??\C:\profiles\administrator"));
    let file = fs.zw_create_file_relative(
        b"profiles\\administrator\\ntuser.dat",
        FILE_WRITE_DATA,
        FILE_ATTRIBUTE_HIDDEN,
        0,
        FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(
        (file.status, file.information),
        (STATUS_SUCCESS, FILE_CREATED)
    );
    assert_eq!(
        fs.zw_write_file(file.handle, None, b"regf"),
        (STATUS_SUCCESS, 4)
    );
    let info = fs.zw_query_standard_information(file.handle).unwrap();
    assert_eq!(
        (info.end_of_file, info.attributes),
        (4, FILE_ATTRIBUTE_HIDDEN)
    );
}

#[test]
fn directory_file_object_is_a_real_relative_create_root() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\profiles\Administrator"));
    let root = fs.zw_create_file_relative(
        b"profiles\\administrator",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(root.status, STATUS_SUCCESS);

    let child = fs.zw_create_file_relative_to_directory(
        root.handle,
        b"NTUSER.DAT",
        FILE_WRITE_DATA,
        FILE_ATTRIBUTE_HIDDEN,
        0,
        FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(
        (child.status, child.information),
        (STATUS_SUCCESS, FILE_CREATED)
    );
    assert_eq!(
        fs.zw_write_file(child.handle, None, b"regf"),
        (STATUS_SUCCESS, 4)
    );
    assert_eq!(fs.zw_close(root.handle), STATUS_SUCCESS);
    assert_eq!(
        fs.zw_read_file(child.handle, Some(0), 4),
        (STATUS_SUCCESS, b"regf".to_vec())
    );
    assert_eq!(
        fs.file_bytes(r"\??\C:\profiles\administrator\ntuser.dat"),
        Some(&b"regf"[..])
    );
}

#[test]
fn directory_relative_create_rejects_invalid_roots_and_names() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\profiles"));
    assert!(fs.provision_file(r"\??\C:\profiles\ordinary.bin", b"x"));
    let directory = fs.zw_create_file_relative(
        b"profiles",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_DIRECTORY_FILE,
    );
    let file = fs.zw_create_file_relative(
        b"profiles\\ordinary.bin",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );

    let open = |fs: &mut FileSystem, root, name: &[u8]| {
        fs.zw_create_file_relative_to_directory(root, name, FILE_READ_DATA, 0, 0, FILE_OPEN, 0)
    };
    assert_eq!(
        open(&mut fs, file.handle, b"child").status,
        STATUS_NOT_A_DIRECTORY
    );
    assert_eq!(
        open(&mut fs, directory.handle, b"\\child").status,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        open(&mut fs, directory.handle, b"").status,
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        open(&mut fs, u64::MAX - 1, b"child").status,
        STATUS_INVALID_HANDLE
    );
    assert_eq!(fs.zw_close(directory.handle), STATUS_SUCCESS);
    assert_eq!(
        open(&mut fs, directory.handle, b"child").status,
        STATUS_INVALID_HANDLE
    );
}

#[test]
fn directory_file_object_is_a_real_relative_attribute_root() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\profiles\Administrator"));
    assert!(fs.provision_file(r"\??\C:\profiles\Administrator\ntuser.dat", b"regf"));
    let directory = fs.zw_create_file_relative(
        b"profiles\\administrator",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_DIRECTORY_FILE,
    );
    let file = fs.zw_create_file_relative(
        b"profiles\\administrator\\ntuser.dat",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );

    let info = fs
        .query_attributes_relative_to_directory(directory.handle, b"NTUSER.DAT")
        .unwrap();
    assert_eq!(info.end_of_file, 4);
    assert!(!info.is_directory);
    assert_eq!(
        fs.query_attributes_relative_to_directory(file.handle, b"child"),
        Err(STATUS_NOT_A_DIRECTORY)
    );
    assert_eq!(
        fs.query_attributes_relative_to_directory(directory.handle, b"missing"),
        Err(STATUS_OBJECT_NAME_NOT_FOUND)
    );
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
    assert_eq!(fs.zw_close(c.handle), STATUS_SUCCESS);
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
fn create_parameter_validation_matches_nt5_io_manager_contract() {
    let valid = |access, attributes, share, disposition, options| {
        validate_file_create_parameters(access, attributes, share, disposition, options)
    };
    assert_eq!(valid(FILE_READ_DATA, 0, 0, FILE_OPEN, 0), Ok(()));
    assert_eq!(
        valid(
            FILE_READ_DATA | SYNCHRONIZE,
            FILE_ATTRIBUTE_HIDDEN,
            FILE_SHARE_READ,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
        ),
        Ok(())
    );
    assert_eq!(
        valid(FILE_READ_DATA, 0x8000_0000, 0, FILE_OPEN, 0),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        valid(FILE_READ_DATA, 0, 0x8, FILE_OPEN, 0),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        valid(FILE_READ_DATA, 0, 0, FILE_MAXIMUM_DISPOSITION + 1, 0),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        valid(FILE_READ_DATA, 0, 0, FILE_OPEN, 0x0100_0000),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        valid(
            FILE_READ_DATA,
            0,
            0,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT,
        ),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        valid(
            FILE_READ_DATA | SYNCHRONIZE,
            0,
            0,
            FILE_OPEN,
            FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT,
        ),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        valid(FILE_READ_DATA, 0, 0, FILE_OPEN, FILE_DELETE_ON_CLOSE),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        valid(
            FILE_READ_DATA,
            0,
            0,
            FILE_OPEN,
            FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE,
        ),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        valid(FILE_READ_DATA, 0, 0, FILE_OVERWRITE, FILE_DIRECTORY_FILE),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        valid(
            FILE_READ_DATA,
            0,
            0,
            FILE_OPEN,
            FILE_COMPLETE_IF_OPLOCKED | FILE_RESERVE_OPFILTER,
        ),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        valid(
            FILE_APPEND_DATA,
            0,
            0,
            FILE_OPEN,
            FILE_NO_INTERMEDIATE_BUFFERING,
        ),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn share_access_is_symmetric_precedes_truncate_and_lives_until_final_close() {
    let mut fs = FileSystem::new(MemFs::with_fixture());
    assert!(fs.provision_file(r"\??\C:\Temp\shared.dat", b"payload"));

    let reader = fs.zw_create_file(
        r"\??\C:\Temp\shared.dat",
        FILE_READ_DATA,
        0,
        FILE_SHARE_READ,
        FILE_OPEN,
        0,
    );
    assert_eq!(reader.status, STATUS_SUCCESS);
    let denied_writer = fs.zw_create_file(
        r"\??\C:\Temp\shared.dat",
        FILE_WRITE_DATA,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OVERWRITE,
        0,
    );
    assert_eq!(denied_writer.status, STATUS_SHARING_VIOLATION);
    assert_eq!(
        fs.file_bytes(r"\??\C:\Temp\shared.dat"),
        Some(&b"payload"[..])
    );
    assert_eq!(fs.zw_close(reader.handle), STATUS_SUCCESS);

    let first = fs.zw_create_file(
        r"\??\C:\Temp\shared.dat",
        FILE_READ_DATA,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        0,
    );
    assert_eq!(first.status, STATUS_SUCCESS);
    let symmetric_denial = fs.zw_create_file(
        r"\??\C:\Temp\shared.dat",
        FILE_WRITE_DATA,
        0,
        FILE_SHARE_WRITE,
        FILE_OPEN,
        0,
    );
    assert_eq!(symmetric_denial.status, STATUS_SHARING_VIOLATION);
    let writer = fs.zw_create_file(
        r"\??\C:\Temp\shared.dat",
        FILE_WRITE_DATA,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        0,
    );
    assert_eq!(writer.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_close(writer.handle), STATUS_SUCCESS);

    assert_eq!(fs.zw_retain(first.handle), STATUS_SUCCESS);
    assert_eq!(fs.zw_is_final_reference(first.handle), Ok(false));
    assert_eq!(fs.zw_close(first.handle), STATUS_SUCCESS);
    assert_eq!(fs.zw_is_final_reference(first.handle), Ok(true));
    assert_eq!(
        fs.zw_create_file(
            r"\??\C:\Temp\shared.dat",
            FILE_WRITE_DATA,
            0,
            FILE_SHARE_WRITE,
            FILE_OPEN,
            0,
        )
        .status,
        STATUS_SHARING_VIOLATION
    );
    assert_eq!(fs.zw_close(first.handle), STATUS_SUCCESS);
    assert_eq!(
        fs.zw_create_file(
            r"\??\C:\Temp\shared.dat",
            FILE_WRITE_DATA,
            0,
            FILE_SHARE_WRITE,
            FILE_OPEN,
            0,
        )
        .status,
        STATUS_SUCCESS
    );
}

#[test]
fn metadata_only_open_does_not_participate_in_share_accounting() {
    const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
    let mut fs = FileSystem::new(MemFs::with_fixture());
    assert!(fs.provision_file(r"\??\C:\Temp\metadata.dat", b"x"));
    let metadata = fs.zw_create_file(
        r"\??\C:\Temp\metadata.dat",
        FILE_READ_ATTRIBUTES,
        0,
        0,
        FILE_OPEN,
        0,
    );
    assert_eq!(metadata.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_create_file(
            r"\??\C:\Temp\metadata.dat",
            FILE_WRITE_DATA,
            0,
            0,
            FILE_OPEN,
            0,
        )
        .status,
        STATUS_SUCCESS
    );
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
fn flush_buffers_file_validates_the_file_object() {
    let mut fs = FileSystem::new(MemFs::with_fixture());
    let h = fs
        .zw_create_file(r"\??\C:\Temp\f", FILE_WRITE_DATA, 0, 0, FILE_CREATE, 0)
        .handle;
    assert_eq!(fs.zw_write_file(h, None, b"pending").0, STATUS_SUCCESS);
    assert_eq!(fs.zw_flush_buffers_file(h), STATUS_SUCCESS);
    assert_eq!(fs.zw_query_standard_information(h).unwrap().end_of_file, 7);
    fs.zw_close(h);
    assert_eq!(fs.zw_flush_buffers_file(h), STATUS_INVALID_HANDLE);
}

#[test]
fn read_file_into_uses_and_advances_file_position() {
    let mut fs = FileSystem::new(MemFs::with_fixture());
    let h = fs
        .zw_create_file(r"\??\C:\Temp\f", FILE_WRITE_DATA, 0, 0, FILE_CREATE, 0)
        .handle;
    assert_eq!(fs.zw_write_file(h, None, b"abcdef").0, STATUS_SUCCESS);
    fs.zw_close(h);

    let h = fs
        .zw_create_file(r"\??\C:\Temp\f", FILE_READ_DATA, 0, 0, FILE_OPEN, 0)
        .handle;
    let mut out = [0u8; 4];
    assert_eq!(fs.zw_read_file_into(h, None, &mut out).0, STATUS_SUCCESS);
    assert_eq!(&out, b"abcd");
    assert_eq!(fs.current_offset(h), Some(4));
    let (status, read) = fs.zw_read_file_into(h, None, &mut out);
    assert_eq!((status, read), (STATUS_SUCCESS, 2));
    assert_eq!(&out[..read], b"ef");
    assert_eq!(
        fs.zw_read_file_into(h, None, &mut out).0,
        STATUS_END_OF_FILE
    );
}

#[test]
fn copied_file_chunks_share_provisioned_source_until_modified() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(r"\??\C:\profiles\Default User\ntuser.dat", b"0123456789"));
    assert!(fs.provision_directory(r"\??\C:\profiles\Administrator"));
    assert_eq!(fs.unique_data_blobs(), 1);

    let source = fs.zw_create_file(
        r"\??\C:\profiles\Default User\ntuser.dat",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        0,
    );
    let dest = fs.zw_create_file(
        r"\??\C:\profiles\Administrator\ntuser.dat",
        FILE_WRITE_DATA | FILE_READ_DATA,
        0,
        0,
        FILE_CREATE,
        0,
    );
    let mut chunk = [0u8; 4];
    loop {
        let (status, read) = fs.zw_read_file_into(source.handle, None, &mut chunk);
        if status == STATUS_END_OF_FILE {
            break;
        }
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(
            fs.zw_write_file(dest.handle, None, &chunk[..read]),
            (STATUS_SUCCESS, read)
        );
    }

    assert_eq!(fs.unique_data_blobs(), 1);
    assert_eq!(
        fs.file_bytes(r"\??\C:\profiles\Administrator\ntuser.dat"),
        Some(&b"0123456789"[..])
    );

    assert_eq!(
        fs.zw_write_file(dest.handle, Some(2), b"xx"),
        (STATUS_SUCCESS, 2)
    );
    assert_eq!(
        fs.file_bytes(r"\??\C:\profiles\Default User\ntuser.dat"),
        Some(&b"0123456789"[..])
    );
    assert_eq!(
        fs.file_bytes(r"\??\C:\profiles\Administrator\ntuser.dat"),
        Some(&b"01xx456789"[..])
    );
}

#[test]
fn compact_volume_blobs_reclaims_only_unreferenced_storage() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(r"\??\C:\Temp\live.log", b"header"));
    assert_eq!(
        fs.append_file_by_path(r"\??\C:\Temp\live.log", b"-record"),
        (STATUS_SUCCESS, 7)
    );
    assert!(fs.provision_file(r"\??\C:\Temp\replaced.bin", b"obsolete-payload"));

    let replaced = fs.zw_create_file(
        r"\??\C:\Temp\replaced.bin",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(replaced.status, STATUS_SUCCESS);
    assert_eq!(
        fs.replace_file_data_owned(replaced.handle, b"replacement".to_vec()),
        STATUS_SUCCESS
    );
    fs.zw_close(replaced.handle);

    let snapshot_before = fs.export_volume_snapshot().unwrap();
    assert_eq!(fs.unique_data_blobs(), 3);
    let result = fs.compact_volume_blobs().unwrap();
    assert_eq!(
        result,
        MemFsBlobCompaction {
            blobs_before: 3,
            blobs_after: 2,
            bytes_before: 6 + 7 + 16,
            bytes_after: 6 + 7,
        }
    );
    assert_eq!(result.reclaimed_blobs(), 1);
    assert_eq!(result.reclaimed_bytes(), 16);
    assert_eq!(
        fs.file_bytes_owned(r"\??\C:\Temp\live.log").as_deref(),
        Some(&b"header-record"[..])
    );
    assert_eq!(
        fs.file_bytes(r"\??\C:\Temp\replaced.bin"),
        Some(&b"replacement"[..])
    );
    assert_eq!(fs.export_volume_snapshot().unwrap(), snapshot_before);

    let second = fs.compact_volume_blobs().unwrap();
    assert_eq!(second.reclaimed_blobs(), 0);
    assert_eq!(second.reclaimed_bytes(), 0);
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
fn replace_file_data_owned_installs_complete_file_image() {
    let mut fs = FileSystem::new(MemFs::new());
    let file = fs.zw_create_file(
        r"\??\C:\checkpoint.bin",
        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
        0,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(file.status, STATUS_SUCCESS);

    let image = alloc::vec![0x5a; 8192];
    assert_eq!(
        fs.replace_file_data_owned(file.handle, image),
        STATUS_SUCCESS
    );
    assert_eq!(
        fs.zw_query_standard_information(file.handle)
            .unwrap()
            .end_of_file,
        8192
    );
    assert_eq!(fs.zw_read_file(file.handle, Some(0), 4).1, [0x5a; 4]);

    let dir = fs.zw_create_file(
        r"\??\C:\checkpoint-dir",
        FILE_READ_DATA | FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(dir.status, STATUS_SUCCESS);
    assert_eq!(
        fs.replace_file_data_owned(dir.handle, alloc::vec![0x11]),
        STATUS_INVALID_DEVICE_REQUEST
    );
    assert_eq!(
        fs.replace_file_data_owned(INVALID_HANDLE, alloc::vec![0x22]),
        STATUS_INVALID_HANDLE
    );
}

#[test]
fn memfs_snapshot_round_trips_volume_tree_sparse_data_and_attributes() {
    let mut fs = FileSystem::new(MemFs::new());

    let profiles = fs.zw_create_file(
        r"\??\C:\Profiles",
        FILE_READ_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(profiles.status, STATUS_SUCCESS);
    assert_eq!(profiles.information, FILE_CREATED);
    fs.zw_close(profiles.handle);

    let user = fs.zw_create_file(
        r"\??\C:\Profiles\Administrator",
        FILE_READ_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(user.status, STATUS_SUCCESS);
    fs.zw_close(user.handle);

    let ntuser = fs.zw_create_file(
        r"\??\C:\Profiles\Administrator\ntuser.dat",
        FILE_READ_DATA | FILE_WRITE_DATA,
        FILE_ATTRIBUTE_HIDDEN,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(ntuser.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_write_file(ntuser.handle, None, b"checkpointed hive")
            .0,
        STATUS_SUCCESS
    );

    for dir in [
        r"\??\C:\ReactOS",
        r"\??\C:\ReactOS\System32",
        r"\??\C:\ReactOS\System32\Config",
    ] {
        let r = fs.zw_create_file(dir, FILE_READ_DATA, 0, 0, FILE_OPEN_IF, FILE_DIRECTORY_FILE);
        assert_eq!(r.status, STATUS_SUCCESS);
        fs.zw_close(r.handle);
    }
    let event_log = fs.zw_create_file(
        r"\??\C:\ReactOS\System32\Config\AppEvent.Evt",
        FILE_READ_DATA | FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(event_log.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_set_information_file(
            event_log.handle,
            FILE_END_OF_FILE_INFORMATION,
            &0x20_000u64.to_le_bytes(),
        ),
        STATUS_SUCCESS
    );
    assert_eq!(
        fs.zw_write_file(event_log.handle, Some(0x1000), b"evt").0,
        STATUS_SUCCESS
    );

    let stale = fs.zw_create_file(
        r"\??\C:\Profiles\Administrator\delete-me.tmp",
        FILE_READ_DATA | DELETE,
        0,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
    );
    assert_eq!(stale.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_close(stale.handle), STATUS_SUCCESS);

    let snapshot = fs.export_volume_snapshot().unwrap();
    let info = MemFs::snapshot_info(&snapshot).unwrap();
    assert!(info.record_count >= 7);

    let mut rebooted = FileSystem::from_volume_snapshot(&snapshot).unwrap();
    assert_eq!(
        rebooted.zw_read_file(ntuser.handle, Some(0), 1).0,
        STATUS_INVALID_HANDLE
    );
    let ntuser_info = rebooted
        .query_attributes(r"\??\C:\Profiles\Administrator\ntuser.dat")
        .unwrap();
    assert_eq!(ntuser_info.end_of_file, b"checkpointed hive".len() as u64);
    assert_eq!(
        ntuser_info.attributes & FILE_ATTRIBUTE_HIDDEN,
        FILE_ATTRIBUTE_HIDDEN
    );
    assert!(rebooted
        .query_attributes(r"\??\C:\Profiles\Administrator\delete-me.tmp")
        .is_none());

    let ntuser2 = rebooted.zw_create_file(
        r"\??\C:\Profiles\Administrator\ntuser.dat",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(ntuser2.status, STATUS_SUCCESS);
    assert_eq!(
        rebooted.zw_read_file(ntuser2.handle, Some(0), 64).1,
        b"checkpointed hive"
    );

    let event2 = rebooted.zw_create_file(
        r"\??\C:\ReactOS\System32\Config\AppEvent.Evt",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(event2.status, STATUS_SUCCESS);
    let (status, bytes) = rebooted.zw_read_file(event2.handle, Some(0x0ffe), 6);
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(bytes, &[0, 0, b'e', b'v', b't', 0]);
    assert_eq!(
        rebooted
            .query_attributes(r"\??\C:\ReactOS\System32\Config\AppEvent.Evt")
            .unwrap()
            .end_of_file,
        0x20_000
    );
}

#[test]
fn memfs_snapshot_rejects_corrupt_or_malformed_images() {
    let fs = FileSystem::new(MemFs::with_fixture());
    let snapshot = fs.export_volume_snapshot().unwrap();

    let mut bad_magic = snapshot.clone();
    bad_magic[0] ^= 0x55;
    assert!(matches!(
        MemFs::from_snapshot(&bad_magic),
        Err(MemFsSnapshotError::BadMagic)
    ));

    let mut bad_payload = snapshot.clone();
    let last = bad_payload.len() - 1;
    bad_payload[last] ^= 0x55;
    assert!(matches!(
        MemFs::from_snapshot(&bad_payload),
        Err(MemFsSnapshotError::BadChecksum)
    ));

    assert!(matches!(
        MemFs::from_snapshot(&snapshot[..snapshot.len() - 1]),
        Err(MemFsSnapshotError::Truncated)
    ));

    let mut extra = snapshot.clone();
    extra.push(0);
    assert!(matches!(
        MemFs::from_snapshot(&extra),
        Err(MemFsSnapshotError::InvalidRecord)
    ));
}

#[test]
fn memfs_snapshot_v5_reader_accepts_v1_directory_records() {
    fn crc32c(bytes: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in bytes {
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0x82F6_3B78
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    let path = b"legacy";
    let mut payload = alloc::vec::Vec::new();
    payload.push(1); // SNAP_REC_DIR
    payload.extend_from_slice(&FILE_ATTRIBUTE_DIRECTORY.to_le_bytes());
    payload.extend_from_slice(&(path.len() as u32).to_le_bytes());
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(path);

    let mut snapshot = alloc::vec![0u8; 32];
    snapshot[0..8].copy_from_slice(b"USNTFS\0\x01");
    snapshot[8..10].copy_from_slice(&32u16.to_le_bytes());
    snapshot[10..12].copy_from_slice(&1u16.to_le_bytes());
    snapshot[12..16].copy_from_slice(&1u32.to_le_bytes());
    snapshot[16..24].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    snapshot[24..28].copy_from_slice(&crc32c(&payload).to_le_bytes());
    let header_crc = crc32c(&snapshot[..28]);
    snapshot[28..32].copy_from_slice(&header_crc.to_le_bytes());
    snapshot.extend_from_slice(&payload);

    assert_eq!(MemFs::snapshot_info(&snapshot).unwrap().version, 1);
    let fs = FileSystem::from_volume_snapshot(&snapshot).unwrap();
    assert!(fs.query_attributes(r"\??\C:\legacy").unwrap().is_directory);
}

#[test]
fn memfs_snapshot_v5_reader_derives_sizes_for_v3_files() {
    fn crc32c(bytes: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in bytes {
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0x82F6_3B78
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    let mut payload = alloc::vec::Vec::new();
    payload.push(1); // SNAP_REC_DIR root
    payload.extend_from_slice(&FILE_ATTRIBUTE_DIRECTORY.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u64.to_le_bytes());
    for time in [1u64, 2, 3, 4] {
        payload.extend_from_slice(&time.to_le_bytes());
    }
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());

    let path = b"legacy.bin";
    payload.push(2); // SNAP_REC_FILE
    payload.extend_from_slice(&FILE_ATTRIBUTE_ARCHIVE.to_le_bytes());
    payload.extend_from_slice(&(path.len() as u32).to_le_bytes());
    payload.extend_from_slice(&7u64.to_le_bytes());
    for time in [5u64, 6, 7, 8] {
        payload.extend_from_slice(&time.to_le_bytes());
    }
    payload.extend_from_slice(&3u64.to_le_bytes());
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(path);
    payload.push(1); // SNAP_EXTENT_DATA
    payload.extend_from_slice(&3u64.to_le_bytes());
    payload.extend_from_slice(b"old");

    let mut snapshot = alloc::vec![0u8; 32];
    snapshot[0..8].copy_from_slice(b"USNTFS\0\x01");
    snapshot[8..10].copy_from_slice(&32u16.to_le_bytes());
    snapshot[10..12].copy_from_slice(&3u16.to_le_bytes());
    snapshot[12..16].copy_from_slice(&2u32.to_le_bytes());
    snapshot[16..24].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    snapshot[24..28].copy_from_slice(&crc32c(&payload).to_le_bytes());
    let header_crc = crc32c(&snapshot[..28]);
    snapshot[28..32].copy_from_slice(&header_crc.to_le_bytes());
    snapshot.extend_from_slice(&payload);

    let fs = FileSystem::from_volume_snapshot(&snapshot).unwrap();
    let metadata = fs
        .query_metadata_relative(b"legacy.bin")
        .expect("v3 file restored");
    assert_eq!(metadata.end_of_file, 3);
    assert_eq!(metadata.allocation_size, 4096);
    assert_eq!(metadata.valid_data_length, 3);
    assert_eq!(metadata.creation_time, 5);
    assert_eq!(fs.file_bytes_relative(b"legacy.bin"), Some(&b"old"[..]));
}

#[test]
fn memfs_snapshot_v5_reader_derives_valid_data_length_for_v4_files() {
    fn crc32c(bytes: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in bytes {
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0x82F6_3B78
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    let mut payload = alloc::vec::Vec::new();
    payload.push(1); // SNAP_REC_DIR root
    payload.extend_from_slice(&FILE_ATTRIBUTE_DIRECTORY.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());
    payload.extend_from_slice(&0u64.to_le_bytes());
    for time in [1u64, 2, 3, 4] {
        payload.extend_from_slice(&time.to_le_bytes());
    }
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend_from_slice(&0u64.to_le_bytes());
    payload.extend_from_slice(&0u32.to_le_bytes());

    let path = b"version4.bin";
    payload.push(2); // SNAP_REC_FILE
    payload.extend_from_slice(&FILE_ATTRIBUTE_ARCHIVE.to_le_bytes());
    payload.extend_from_slice(&(path.len() as u32).to_le_bytes());
    payload.extend_from_slice(&11u64.to_le_bytes());
    for time in [5u64, 6, 7, 8] {
        payload.extend_from_slice(&time.to_le_bytes());
    }
    payload.extend_from_slice(&4u64.to_le_bytes());
    payload.extend_from_slice(&8192u64.to_le_bytes());
    payload.extend_from_slice(&1u32.to_le_bytes());
    payload.extend_from_slice(path);
    payload.push(1); // SNAP_EXTENT_DATA
    payload.extend_from_slice(&4u64.to_le_bytes());
    payload.extend_from_slice(b"data");

    let mut snapshot = alloc::vec![0u8; 32];
    snapshot[0..8].copy_from_slice(b"USNTFS\0\x01");
    snapshot[8..10].copy_from_slice(&32u16.to_le_bytes());
    snapshot[10..12].copy_from_slice(&4u16.to_le_bytes());
    snapshot[12..16].copy_from_slice(&2u32.to_le_bytes());
    snapshot[16..24].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    snapshot[24..28].copy_from_slice(&crc32c(&payload).to_le_bytes());
    let header_crc = crc32c(&snapshot[..28]);
    snapshot[28..32].copy_from_slice(&header_crc.to_le_bytes());
    snapshot.extend_from_slice(&payload);

    let fs = FileSystem::from_volume_snapshot(&snapshot).unwrap();
    let metadata = fs
        .query_metadata_relative(b"version4.bin")
        .expect("v4 file restored");
    assert_eq!(metadata.end_of_file, 4);
    assert_eq!(metadata.allocation_size, 8192);
    assert_eq!(metadata.valid_data_length, 4);
    assert_eq!(fs.file_bytes_relative(b"version4.bin"), Some(&b"data"[..]));
}

#[test]
fn snapshot_block_store_commits_latest_valid_slot() {
    let store = SnapshotBlockStore::new(2, 16);
    let mut dev = MemoryBlockDevice::new(512, 24);
    assert_eq!(store.payload_capacity(&dev).unwrap(), 7 * 512);
    assert!(store.read_latest(&mut dev).unwrap().is_none());

    assert_eq!(store.commit_next(&mut dev, b"first").unwrap(), 1);
    let first = store.read_latest(&mut dev).unwrap().unwrap();
    assert_eq!(first.generation, 1);
    assert_eq!(first.payload, b"first");

    let second_payload = alloc::vec![0x5a; 1400];
    dev.reset_reads();
    assert_eq!(store.commit_next(&mut dev, &second_payload).unwrap(), 2);
    assert_eq!(dev.reads, 2, "commit should read only the two slot headers");
    let second = store.read_latest(&mut dev).unwrap().unwrap();
    assert_eq!(second.generation, 2);
    assert_eq!(second.payload, second_payload);
}

#[test]
fn snapshot_block_store_streaming_writer_uses_bulk_sector_writes() {
    let store = SnapshotBlockStore::new(0, 32);
    let mut dev = BulkCountingBlockDevice::new(512, 32);
    let payload = alloc::vec![0x5a; 4096 + 17];

    assert_eq!(store.commit_next(&mut dev, &payload).unwrap(), 1);
    assert!(dev.bulk_writes > 0);
    assert!(dev.bulk_sectors >= 8);

    let restored = store.read_latest(&mut dev).unwrap().unwrap();
    assert_eq!(restored.payload, payload);
}

#[test]
fn snapshot_block_store_keeps_previous_generation_when_update_write_fails() {
    let store = SnapshotBlockStore::new(0, 16);
    let mut dev = MemoryBlockDevice::new(512, 16);
    assert_eq!(store.commit_next(&mut dev, b"committed").unwrap(), 1);

    dev.fail_next_write();
    assert_eq!(
        store.commit_next(&mut dev, b"new generation"),
        Err(SnapshotBlockStoreError::Io)
    );
    let latest = store.read_latest(&mut dev).unwrap().unwrap();
    assert_eq!(latest.generation, 1);
    assert_eq!(latest.payload, b"committed");
}

#[test]
fn snapshot_block_store_rejects_bad_geometry_oversize_and_corruption() {
    let mut dev = MemoryBlockDevice::new(512, 8);
    let bad = SnapshotBlockStore::new(0, 3);
    assert_eq!(
        bad.commit_next(&mut dev, b"x"),
        Err(SnapshotBlockStoreError::InvalidGeometry)
    );

    let store = SnapshotBlockStore::new(0, 8);
    let too_large = alloc::vec![0x5a; store.payload_capacity(&dev).unwrap() + 1];
    assert_eq!(
        store.commit_next(&mut dev, &too_large),
        Err(SnapshotBlockStoreError::OutOfSpace)
    );

    assert_eq!(store.commit_next(&mut dev, b"valid").unwrap(), 1);
    dev.corrupt(1, 0);
    assert_eq!(
        store.read_latest(&mut dev),
        Err(SnapshotBlockStoreError::Corrupt)
    );
}

#[test]
fn memfs_snapshot_restores_from_block_store_payload() {
    let mut fs = FileSystem::new(MemFs::new());
    let dir = fs.zw_create_file(
        r"\??\C:\Profiles",
        FILE_READ_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(dir.status, STATUS_SUCCESS);
    fs.zw_close(dir.handle);
    let file = fs.zw_create_file(
        r"\??\C:\Profiles\persisted.txt",
        FILE_READ_DATA | FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(file.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_write_file(file.handle, None, b"survived storage").0,
        STATUS_SUCCESS
    );

    let snapshot = fs.export_volume_snapshot().unwrap();
    let store = SnapshotBlockStore::new(4, 32);
    let mut dev = MemoryBlockDevice::new(512, 40);
    assert_eq!(store.commit_next(&mut dev, &snapshot).unwrap(), 1);
    let stored = store.read_latest(&mut dev).unwrap().unwrap();
    let mut restored = FileSystem::from_volume_snapshot(&stored.payload).unwrap();

    let reopened = restored.zw_create_file(
        r"\??\C:\Profiles\persisted.txt",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(reopened.status, STATUS_SUCCESS);
    assert_eq!(
        restored.zw_read_file(reopened.handle, Some(0), 64).1,
        b"survived storage"
    );

    let (mut restored, generation, bytes) =
        FileSystem::restore_volume_snapshot_from_store(&store, &mut dev)
            .unwrap()
            .unwrap();
    assert_eq!(generation, 1);
    assert_eq!(bytes, snapshot.len());
    let reopened = restored.zw_create_file(
        r"\??\C:\Profiles\persisted.txt",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(reopened.status, STATUS_SUCCESS);
    assert_eq!(
        restored.zw_read_file(reopened.handle, Some(0), 64).1,
        b"survived storage"
    );
}

#[test]
fn memfs_streaming_snapshot_commit_matches_exported_snapshot() {
    let mut fs = FileSystem::new(MemFs::new());
    let profiles = fs.zw_create_file(
        r"\??\C:\Profiles",
        FILE_READ_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(profiles.status, STATUS_SUCCESS);
    fs.zw_close(profiles.handle);
    let profile = fs.zw_create_file(
        r"\??\C:\Profiles\Administrator",
        FILE_READ_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(profile.status, STATUS_SUCCESS);
    fs.zw_close(profile.handle);
    let file = fs.zw_create_file(
        r"\??\C:\Profiles\Administrator\ntuser.dat",
        FILE_READ_DATA | FILE_WRITE_DATA,
        FILE_ATTRIBUTE_HIDDEN,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(file.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_write_file(file.handle, Some(0), b"streamed hive image")
            .0,
        STATUS_SUCCESS
    );
    assert_eq!(
        fs.zw_set_information_file(
            file.handle,
            FILE_END_OF_FILE_INFORMATION,
            &0x4000u64.to_le_bytes(),
        ),
        STATUS_SUCCESS
    );

    let expected = fs.export_volume_snapshot().unwrap();
    let store = SnapshotBlockStore::new(2, 48);
    let mut dev = MemoryBlockDevice::new(512, 56);
    let (generation, bytes) = fs.commit_volume_snapshot(&store, &mut dev).unwrap();
    assert_eq!(generation, 1);
    assert_eq!(bytes, expected.len());

    let stored = store.read_latest(&mut dev).unwrap().unwrap();
    assert_eq!(stored.payload, expected);
    let (mut restored, generation, bytes) =
        FileSystem::restore_volume_snapshot_from_store(&store, &mut dev)
            .unwrap()
            .unwrap();
    assert_eq!(generation, 1);
    assert_eq!(bytes, expected.len());
    let reopened = restored.zw_create_file(
        r"\??\C:\Profiles\Administrator\ntuser.dat",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(reopened.status, STATUS_SUCCESS);
    let (status, bytes) = restored.zw_read_file(reopened.handle, Some(0), 19);
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(bytes, b"streamed hive image");
}

#[test]
fn memfs_streaming_snapshot_repeated_mutation_round_trips_mixed_storage() {
    const SYSTEM: &str = r"\??\C:\ReactOS\System32\Config\SYSTEM";
    const LOG: &str = r"\??\C:\ReactOS\System32\Config\SYSTEM.LOG";
    const SPARSE: &str = r"\??\C:\Profiles\Administrator\sparse.bin";
    const SPARSE_LEN: u64 = 0x2_0000;

    let mut fs = FileSystem::new(MemFs::new());
    fs.provision_file_owned(SYSTEM, alloc::vec![0x11; 32 * 1024])
        .unwrap();
    fs.provision_file_owned(LOG, alloc::vec::Vec::new())
        .unwrap();
    fs.provision_file_owned(SPARSE, alloc::vec::Vec::new())
        .unwrap();
    for index in 0..48 {
        let directory = alloc::format!(r"\??\C:\Profiles\User{index:02}");
        let file = alloc::format!(r"{directory}\state.bin");
        assert!(fs.provision_directory(&directory));
        fs.provision_file_owned(&file, alloc::vec![index as u8; 64])
            .unwrap();
    }
    assert!(fs.node_count() >= 100);

    let system = fs.zw_create_file(
        SYSTEM,
        FILE_READ_DATA | FILE_WRITE_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(system.status, STATUS_SUCCESS);
    let sparse = fs.zw_create_file(
        SPARSE,
        FILE_READ_DATA | FILE_WRITE_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(sparse.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_set_information_file(
            sparse.handle,
            FILE_END_OF_FILE_INFORMATION,
            &SPARSE_LEN.to_le_bytes(),
        ),
        STATUS_SUCCESS
    );

    let store = SnapshotBlockStore::new(0, 1024);
    let mut dev = MemoryBlockDevice::new(512, 1024);
    let mut expected_log = alloc::vec::Vec::new();
    for generation in 1u64..=12 {
        let image = alloc::vec![generation as u8; 32 * 1024 + generation as usize * 31];
        assert_eq!(
            fs.replace_file_data_owned(system.handle, image.clone()),
            STATUS_SUCCESS
        );
        let record = [generation as u8; 37];
        assert_eq!(fs.append_file_by_path(LOG, &record), (STATUS_SUCCESS, 37));
        expected_log.extend_from_slice(&record);
        let sparse_offset = 0x1000 + generation * 0x100;
        let marker = generation.to_le_bytes();
        assert_eq!(
            fs.zw_write_file(sparse.handle, Some(sparse_offset), &marker),
            (STATUS_SUCCESS, marker.len())
        );

        assert_eq!(fs.file_bytes(SYSTEM), Some(image.as_slice()));
        assert_eq!(
            fs.file_bytes_owned(LOG).as_deref(),
            Some(expected_log.as_slice())
        );
        if generation >= 2 {
            assert_eq!(fs.file_bytes(LOG), None);
        }

        let expected = fs.export_volume_snapshot().unwrap();
        let (actual_generation, bytes) = fs.commit_volume_snapshot(&store, &mut dev).unwrap();
        assert_eq!((actual_generation, bytes), (generation, expected.len()));
        let stored = store.read_latest(&mut dev).unwrap().unwrap();
        assert_eq!(stored.generation, generation);
        assert_eq!(stored.payload.as_slice(), expected.as_slice());

        let (mut restored, restored_generation, restored_bytes) =
            FileSystem::restore_volume_snapshot_from_store(&store, &mut dev)
                .unwrap()
                .unwrap();
        assert_eq!(
            (restored_generation, restored_bytes),
            (generation, expected.len())
        );
        assert_eq!(restored.file_bytes(SYSTEM), Some(image.as_slice()));
        assert_eq!(
            restored.file_bytes_owned(LOG).as_deref(),
            Some(expected_log.as_slice())
        );
        assert_eq!(restored.file_len(SPARSE), Some(SPARSE_LEN));
        let restored_sparse = restored.zw_create_file(
            SPARSE,
            FILE_READ_DATA,
            0,
            0,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
        );
        assert_eq!(restored_sparse.status, STATUS_SUCCESS);
        assert_eq!(
            restored
                .zw_read_file(restored_sparse.handle, Some(sparse_offset), marker.len())
                .1,
            marker
        );
    }
}

#[test]
fn ntfile_hive_provider_installs_primary_image_by_replace_rename() {
    let fs = RefCell::new(FileSystem::new(MemFs::with_fixture()));
    let mut provider = NtFileHiveIoProvider::open(&fs, SYSTEM_HIVE);

    provider.write_primary_image_atomic(b"old image").unwrap();
    assert_eq!(fs.borrow().file_bytes(SYSTEM_HIVE), Some(&b"old image"[..]));
    assert!(fs
        .borrow()
        .query_attributes(r"\SystemRoot\System32\Config\SYSTEM.TMP")
        .is_none());

    provider.append_log_record(b"abc").unwrap();
    provider.append_log_record(b"de").unwrap();
    assert_eq!(provider.get_status().log_len, 5);

    provider.write_primary_image_atomic(b"new image").unwrap();
    assert_eq!(fs.borrow().file_bytes(SYSTEM_HIVE), Some(&b"new image"[..]));
    assert!(fs
        .borrow()
        .query_attributes(r"\SystemRoot\System32\Config\SYSTEM.TMP")
        .is_none());
    assert!(provider.get_status().image_present);
    provider.truncate_log().unwrap();
    assert_eq!(provider.get_status().log_len, 0);
}

#[test]
fn append_file_extends_extent_sidecar_without_blob_search() {
    let mut fs = FileSystem::new(MemFs::new());
    let large_profile_hive = alloc::vec![0x5a; 256 * 1024];
    assert!(fs.provision_file_relative(b"profiles\\Default User\\ntuser.dat", &large_profile_hive));
    assert!(fs.provision_directory_relative(b"reactos\\system32\\config"));
    let blob_count_before = fs.unique_data_blobs();

    let log = fs.zw_create_file(
        r"\??\C:\ReactOS\System32\Config\SYSTEM.LOG",
        FILE_WRITE_DATA | FILE_APPEND_DATA | SYNCHRONIZE,
        0,
        0,
        FILE_OPEN_IF,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(log.status, STATUS_SUCCESS);
    assert_eq!(fs.zw_append_file(log.handle, b"abc"), (STATUS_SUCCESS, 3));
    assert_eq!(fs.zw_append_file(log.handle, b"def"), (STATUS_SUCCESS, 3));
    assert_eq!(
        fs.append_file_by_path(r"\??\C:\ReactOS\System32\Config\SYSTEM.LOG", b"ghi"),
        (STATUS_SUCCESS, 3)
    );
    assert_eq!(
        fs.file_len(r"\??\C:\ReactOS\System32\Config\SYSTEM.LOG"),
        Some(9)
    );
    assert_eq!(
        fs.file_bytes_owned(r"\??\C:\ReactOS\System32\Config\SYSTEM.LOG")
            .as_deref(),
        Some(&b"abcdefghi"[..])
    );
    assert_eq!(
        fs.file_bytes(r"\??\C:\ReactOS\System32\Config\SYSTEM.LOG"),
        None
    );
    assert_eq!(fs.unique_data_blobs(), blob_count_before + 3);
    fs.zw_close(log.handle);
}

#[test]
fn ntfile_hive_provider_preserves_image_when_temp_write_fails() {
    let fs = RefCell::new(FileSystem::new(MemFs::with_fixture()));
    let mut provider = NtFileHiveIoProvider::open(&fs, SYSTEM_HIVE);
    provider.write_primary_image_atomic(b"committed").unwrap();

    assert!(fs
        .borrow_mut()
        .provision_directory(r"\SystemRoot\System32\Config\SYSTEM.TMP"));
    assert_eq!(
        provider.write_primary_image_atomic(b"should not install"),
        Err(nt_hive_core::HiveIoError::Io)
    );
    assert_eq!(fs.borrow().file_bytes(SYSTEM_HIVE), Some(&b"committed"[..]));
    assert!(
        fs.borrow()
            .query_attributes(r"\SystemRoot\System32\Config\SYSTEM.TMP")
            .unwrap()
            .is_directory
    );
}

#[test]
fn cache_manager_over_memfs_file() {
    use nt_cache_manager::{FileSizes, SharedCacheMap};
    let fs = RefCell::new(FileSystem::new(MemFs::with_fixture()));
    // Create the backing file, then cache writes through to it (spec §22).
    {
        let mut f = fs.borrow_mut();
        let created = f.zw_create_file(
            r"\??\C:\Temp\cached.bin",
            FILE_WRITE_DATA,
            0,
            0,
            FILE_CREATE,
            0,
        );
        assert_eq!(created.status, STATUS_SUCCESS);
        assert_eq!(f.zw_close(created.handle), STATUS_SUCCESS);
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

fn rename_information(path: &str, root_directory: u64, replace: bool) -> alloc::vec::Vec<u8> {
    let name = wide(path);
    let mut data = alloc::vec::Vec::new();
    data.resize(20 + name.len() * 2, 0);
    data[0] = u8::from(replace);
    data[8..16].copy_from_slice(&root_directory.to_le_bytes());
    data[16..20].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
    for (index, unit) in name.iter().enumerate() {
        data[20 + index * 2..22 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    data
}

fn move_cluster_information(path: &str, root_directory: u64, clusters: u32) -> alloc::vec::Vec<u8> {
    let mut data = rename_information(path, root_directory, false);
    data[0..4].copy_from_slice(&clusters.to_le_bytes());
    data
}

fn disposition_ex(flags: u32) -> [u8; 4] {
    flags.to_le_bytes()
}

#[test]
fn set_file_name_information_parser_validates_exact_name_extent() {
    let data = rename_information("next.txt", 0x1234, true);
    let parsed = parse_set_file_name_information(&data).unwrap();
    assert!(parsed.replace_if_exists);
    assert_eq!(parsed.root_directory, 0x1234);
    assert_eq!(parsed.file_name, &data[20..]);

    assert_eq!(
        parse_set_file_name_information(&data[..19]),
        Err(STATUS_INFO_LENGTH_MISMATCH)
    );
    let mut odd = data.clone();
    odd[16..20].copy_from_slice(&3u32.to_le_bytes());
    assert_eq!(
        parse_set_file_name_information(&odd),
        Err(STATUS_INFO_LENGTH_MISMATCH)
    );
    let mut oversized = data;
    oversized[16..20].copy_from_slice(&0x1000u32.to_le_bytes());
    assert_eq!(
        parse_set_file_name_information(&oversized),
        Err(STATUS_INFO_LENGTH_MISMATCH)
    );
}

#[test]
fn move_cluster_information_parser_preserves_count_and_target_layout() {
    let data = move_cluster_information("target.bin", 0x8877, 0x1234);
    let parsed = parse_move_cluster_information(&data).unwrap();
    assert_eq!(parsed.cluster_count, 0x1234);
    assert_eq!(parsed.root_directory, 0x8877);
    assert_eq!(parsed.file_name, &data[20..]);

    assert_eq!(
        parse_move_cluster_information(&data[..19]),
        Err(STATUS_INFO_LENGTH_MISMATCH)
    );
    let mut odd = data;
    odd[16..20].copy_from_slice(&3u32.to_le_bytes());
    assert_eq!(
        parse_move_cluster_information(&odd),
        Err(STATUS_INFO_LENGTH_MISMATCH)
    );
}

#[test]
fn memfs_rejects_unowned_optional_set_facilities_after_dispatch() {
    let mut fs = FileSystem::new(MemFs::with_fixture());
    let file = fs.zw_create_file(
        SYSTEM_HIVE,
        FILE_WRITE_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(file.status, STATUS_SUCCESS);
    for (class, length) in [
        (29, 72),
        (FILE_MOVE_CLUSTER_INFORMATION, 24),
        (32, 56),
        (FILE_TRACKING_INFORMATION, 16),
    ] {
        assert_eq!(
            fs.zw_set_information_file(file.handle, class, &alloc::vec![0; length]),
            STATUS_INVALID_PARAMETER,
            "class {class}"
        );
    }
}

#[test]
fn file_basic_information_parser_requires_the_complete_fixed_record() {
    let mut basic = [0u8; 40];
    basic[32..36].copy_from_slice(&FILE_ATTRIBUTE_DIRECTORY.to_le_bytes());
    assert_eq!(
        parse_file_basic_information_attributes(&basic),
        Ok(FILE_ATTRIBUTE_DIRECTORY)
    );
    assert_eq!(
        parse_file_basic_information_attributes(&basic[..39]),
        Err(STATUS_INFO_LENGTH_MISMATCH)
    );
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
        writable_mount_relative(
            &wide(r"\??\C:\Profiles\Administrator\ntuser.dat"),
            b"reactos",
            PREFIXES
        )
        .as_deref(),
        Some(&b"profiles\\administrator\\ntuser.dat"[..])
    );
    // The DosDevices and bare-drive spellings resolve to the same relative path.
    assert_eq!(
        writable_mount_relative(&wide(r"\DosDevices\C:\PROFILES\x"), b"reactos", PREFIXES)
            .as_deref(),
        Some(&b"profiles\\x"[..])
    );
    // OUTSIDE the prefix: the read-only namespace keeps them.
    assert!(
        writable_mount_relative(&wide(r"\??\C:\Windows\system.ini"), b"reactos", PREFIXES)
            .is_none()
    );
    assert!(
        writable_mount_relative(&wide(r"\??\C:\Program Files"), b"reactos", PREFIXES).is_none()
    );
    assert!(writable_mount_relative(
        &wide(r"\SystemRoot\system32\ntdll.dll"),
        b"reactos",
        PREFIXES
    )
    .is_none());
    // Component-wise: a longer sibling name is NOT under the prefix.
    assert!(writable_mount_relative(&wide(r"\??\C:\Profiles2\x"), b"reactos", PREFIXES).is_none());
    // Escapes are still rejected by the shared canonicaliser.
    assert!(
        writable_mount_relative(&wide(r"\??\C:\Profiles\..\Windows"), b"reactos", PREFIXES)
            .is_none()
    );
}

#[test]
fn writable_mount_can_cover_system_config_under_windows_alias() {
    const PREFIXES: &[&[u8]] = &[b"profiles", b"reactos\\system32\\config"];
    assert_eq!(
        writable_mount_relative(
            &wide(r"\??\C:\Windows\system32\config\AppEvent.Evt"),
            b"reactos",
            PREFIXES
        )
        .as_deref(),
        Some(&b"reactos\\system32\\config\\appevent.evt"[..])
    );
    assert_eq!(
        writable_mount_relative(
            &wide(r"\SystemRoot\system32\config\system"),
            b"reactos",
            PREFIXES
        )
        .as_deref(),
        Some(&b"reactos\\system32\\config\\system"[..])
    );
    assert!(writable_mount_relative(
        &wide(r"\??\C:\Windows\system32\notepad.exe"),
        b"reactos",
        PREFIXES
    )
    .is_none());
}

#[test]
fn relative_provisioning_matches_writable_mount_relative_paths() {
    let mut fs = FileSystem::new(MemFs::new());

    assert!(fs.provision_directory_relative(b"reactos\\system32\\config"));
    assert!(fs.provision_file_relative(b"reactos\\system32\\config\\SYSTEM", b"regf-system"));
    assert_eq!(
        fs.file_bytes_relative(b"reactos\\system32\\config\\system"),
        Some(&b"regf-system"[..])
    );

    let event = fs.zw_create_file_relative(
        b"reactos\\system32\\config\\appevent.evt",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_OPEN_IF,
        0,
    );
    assert_eq!(event.status, STATUS_SUCCESS);
    assert_eq!(event.information, FILE_CREATED);

    assert!(fs.provision_directory_relative(b"profiles\\Default User"));
    let profile_child = fs.zw_create_file_relative(
        b"profiles\\default user\\ntuser.dat",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        0,
    );
    assert_eq!(profile_child.status, STATUS_SUCCESS);
}

#[test]
fn end_of_file_growth_on_extent_file_is_sparse_and_writable() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory_relative(b"reactos\\system32\\config"));
    let file = fs.zw_create_file_relative(
        b"reactos\\system32\\config\\appevent.evt",
        FILE_WRITE_DATA | FILE_READ_DATA,
        0,
        0,
        FILE_OPEN_IF,
        0,
    );
    assert_eq!(file.status, STATUS_SUCCESS);

    let eventlog_default_size = 5 * 1024 * 1024u64;
    assert_eq!(
        fs.zw_set_information_file(
            file.handle,
            FILE_END_OF_FILE_INFORMATION,
            &eventlog_default_size.to_le_bytes(),
        ),
        STATUS_SUCCESS
    );
    assert_eq!(
        fs.zw_query_standard_information(file.handle)
            .unwrap()
            .end_of_file,
        eventlog_default_size
    );

    assert_eq!(
        fs.zw_write_file(file.handle, Some(0), b"ElfFile\0"),
        (STATUS_SUCCESS, 8)
    );
    assert_eq!(
        fs.zw_query_standard_information(file.handle)
            .unwrap()
            .end_of_file,
        eventlog_default_size
    );
    let (status, head) = fs.zw_read_file(file.handle, Some(0), 12);
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(&head[..], b"ElfFile\0\0\0\0\0");
    let (status, tail) = fs.zw_read_file(file.handle, Some(eventlog_default_size - 4), 4);
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(&tail[..], &[0, 0, 0, 0]);
    assert_eq!(fs.unique_data_blobs(), 1);
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
    assert_eq!(
        (dir.status, dir.information),
        (STATUS_SUCCESS, FILE_CREATED)
    );
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
    assert_eq!(
        (file.status, file.information),
        (STATUS_SUCCESS, FILE_CREATED)
    );
    assert_eq!(
        fs.zw_write_file(file.handle, None, b"regf"),
        (STATUS_SUCCESS, 4)
    );
    assert_eq!(fs.current_offset(file.handle), Some(4));
    let (status, bytes) = fs.zw_read_file(file.handle, Some(0), 16);
    assert_eq!((status, &bytes[..]), (STATUS_SUCCESS, &b"regf"[..]));
    let info = fs.zw_query_standard_information(file.handle).unwrap();
    assert_eq!((info.end_of_file, info.is_directory), (4, false));
    assert_eq!(info.attributes, FILE_ATTRIBUTE_HIDDEN);
    fs.zw_close(file.handle);

    // Enumerate the directory: `.`, `..`, then the child, through the native encoder.
    let mut out = [0u8; 512];
    let r = fs.zw_query_directory_file(
        dir.handle,
        FILE_DIRECTORY_INFORMATION,
        false,
        None,
        false,
        &mut out,
    );
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
    assert_eq!(names, [".", "..", "ntuser.dat"]);
    // A second call with no restart is at the end of the scan.
    let more = fs.zw_query_directory_file(
        dir.handle,
        FILE_DIRECTORY_INFORMATION,
        false,
        None,
        false,
        &mut out,
    );
    assert_eq!(more.status, STATUS_NO_MORE_FILES);
    // RestartScan rewinds it.
    let restart = fs.zw_query_directory_file(
        dir.handle,
        FILE_DIRECTORY_INFORMATION,
        false,
        None,
        true,
        &mut out,
    );
    assert_eq!(restart.status, STATUS_SUCCESS);
}

#[test]
fn writable_volume_set_information_and_delete() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\profiles"));
    let f = fs.zw_create_file(
        r"\??\C:\profiles\a.txt",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        0,
    );
    assert_eq!(
        fs.zw_write_file(f.handle, None, b"0123456789"),
        (STATUS_SUCCESS, 10)
    );
    assert_eq!(
        fs.zw_query_opened_name(f.handle).as_deref(),
        Some(r"\profiles\a.txt")
    );
    // FileEndOfFileInformation truncates.
    assert_eq!(
        fs.zw_set_information_file(f.handle, FILE_END_OF_FILE_INFORMATION, &4u64.to_le_bytes()),
        STATUS_SUCCESS
    );
    assert_eq!(
        fs.zw_query_standard_information(f.handle)
            .unwrap()
            .end_of_file,
        4
    );
    // FilePositionInformation moves the file object's offset.
    assert_eq!(
        fs.zw_set_information_file(f.handle, FILE_POSITION_INFORMATION, &2u64.to_le_bytes()),
        STATUS_SUCCESS
    );
    assert_eq!(fs.current_offset(f.handle), Some(2));
    let (_, tail) = fs.zw_read_file(f.handle, None, 8);
    assert_eq!(&tail[..], b"23");
    // FileRenameInformation renames the FILE_OBJECT's node; the open handle continues to name it.
    assert_eq!(
        fs.zw_set_information_file(
            f.handle,
            FILE_RENAME_INFORMATION,
            &rename_information(r"\??\C:\profiles\b.txt", 0, false),
        ),
        STATUS_SUCCESS
    );
    assert!(fs.query_attributes(r"\??\C:\profiles\a.txt").is_none());
    assert_eq!(
        fs.query_attributes(r"\??\C:\profiles\b.txt")
            .unwrap()
            .end_of_file,
        4
    );
    assert_eq!(
        fs.zw_query_opened_name(f.handle).as_deref(),
        Some(r"\profiles\b.txt")
    );

    let dir = fs.zw_create_file(
        r"\??\C:\profiles",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(dir.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_set_information_file(
            f.handle,
            FILE_RENAME_INFORMATION,
            &rename_information("nested.txt", dir.handle, false),
        ),
        STATUS_SUCCESS
    );
    assert!(fs.query_attributes(r"\??\C:\profiles\b.txt").is_none());
    assert_eq!(
        fs.query_attributes(r"\??\C:\profiles\nested.txt")
            .unwrap()
            .end_of_file,
        4
    );
    let typed_rename = rename_information("typed.txt", 0, false);
    assert_eq!(
        fs.zw_rename_file(
            f.handle,
            FileRenameRoot::SourceParent,
            &typed_rename[20..],
            false,
        ),
        STATUS_SUCCESS
    );
    assert!(fs.query_attributes(r"\??\C:\profiles\nested.txt").is_none());
    assert_eq!(
        fs.query_attributes(r"\??\C:\profiles\typed.txt")
            .unwrap()
            .end_of_file,
        4
    );

    let collision = fs.zw_create_file(
        r"\??\C:\profiles\collision.txt",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(collision.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_write_file(collision.handle, None, b"collision"),
        (STATUS_SUCCESS, 9)
    );
    assert_eq!(
        fs.zw_set_information_file(
            f.handle,
            FILE_RENAME_INFORMATION,
            &rename_information("collision.txt", dir.handle, false),
        ),
        STATUS_OBJECT_NAME_COLLISION
    );
    assert_eq!(
        fs.file_bytes(r"\??\C:\profiles\collision.txt"),
        Some(&b"collision"[..])
    );
    assert_eq!(
        fs.zw_set_information_file(
            f.handle,
            FILE_RENAME_INFORMATION,
            &rename_information(r"\??\D:\elsewhere.txt", 0, false),
        ),
        STATUS_NOT_SAME_DEVICE
    );
    assert_eq!(
        fs.file_bytes(r"\??\C:\profiles\typed.txt"),
        Some(&b"0123"[..])
    );
    assert!(fs.query_attributes(r"\??\D:\elsewhere.txt").is_none());
    assert_eq!(
        fs.zw_set_information_file(
            f.handle,
            FILE_RENAME_INFORMATION,
            &rename_information("collision.txt", dir.handle, true),
        ),
        STATUS_SUCCESS
    );
    assert_eq!(
        fs.file_bytes(r"\??\C:\profiles\collision.txt"),
        Some(&b"0123"[..])
    );
    assert_eq!(
        fs.zw_set_information_file(
            f.handle,
            FILE_LINK_INFORMATION,
            &rename_information("alias.txt", dir.handle, false),
        ),
        STATUS_SUCCESS
    );
    assert_eq!(
        fs.file_bytes(r"\??\C:\profiles\alias.txt"),
        Some(&b"0123"[..])
    );
    assert_eq!(
        fs.zw_query_standard_information(f.handle)
            .unwrap()
            .number_of_links,
        2
    );
    // FileDispositionInformation deletes at close.
    assert_eq!(
        fs.zw_set_information_file(f.handle, FILE_DISPOSITION_INFORMATION, &[1u8]),
        STATUS_SUCCESS
    );
    fs.zw_close(f.handle);
    assert!(fs
        .query_attributes(r"\??\C:\profiles\collision.txt")
        .is_none());
    assert_eq!(
        fs.file_bytes(r"\??\C:\profiles\alias.txt"),
        Some(&b"0123"[..])
    );
    // The directory itself survived, and is still a directory.
    let d = fs.query_attributes(r"\??\C:\profiles").unwrap();
    assert!(d.is_directory && d.attributes & FILE_ATTRIBUTE_DIRECTORY != 0);
}

#[test]
fn writable_volume_hardlinks_share_nodes_and_retain_exact_entries() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.initialize_timestamps(100));
    assert!(fs.provision_directory(r"\??\C:\links"));
    let source = fs.zw_create_file(
        r"\??\C:\links\source.txt",
        FILE_WRITE_DATA,
        0,
        FILE_SHARE_WRITE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(source.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_write_file(source.handle, None, b"source"),
        (STATUS_SUCCESS, 6)
    );
    let dir = fs.zw_create_file(
        r"\??\C:\links",
        FILE_READ_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(dir.status, STATUS_SUCCESS);
    let alias_name = rename_information("alias.txt", dir.handle, false);
    assert_eq!(
        fs.zw_link_file(
            source.handle,
            FileRenameRoot::Directory(dir.handle),
            &alias_name[20..],
            false,
        ),
        STATUS_SUCCESS
    );

    let alias = fs.zw_create_file(
        r"\??\C:\links\alias.txt",
        FILE_WRITE_DATA,
        0,
        FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(alias.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_query_opened_name(source.handle).as_deref(),
        Some(r"\links\source.txt")
    );
    assert_eq!(
        fs.zw_query_opened_name(alias.handle).as_deref(),
        Some(r"\links\alias.txt")
    );
    let source_metadata = fs.zw_query_metadata(source.handle).unwrap();
    let alias_metadata = fs.zw_query_metadata(alias.handle).unwrap();
    assert_eq!(source_metadata.file_id, alias_metadata.file_id);
    assert_eq!(source_metadata.creation_time, 100);
    fs.set_current_time_100ns(200);
    assert_eq!(
        fs.zw_query_standard_information(alias.handle)
            .unwrap()
            .number_of_links,
        2
    );
    assert_eq!(
        fs.zw_write_file(alias.handle, Some(0), b"shared"),
        (STATUS_SUCCESS, 6)
    );
    assert_eq!(
        fs.file_bytes(r"\??\C:\links\source.txt"),
        Some(&b"shared"[..])
    );
    let written_metadata = fs.zw_query_metadata(alias.handle).unwrap();
    assert_eq!(written_metadata.creation_time, 100);
    assert_eq!(written_metadata.last_write_time, 200);
    assert_eq!(written_metadata.change_time, 200);

    let renamed = rename_information("renamed.txt", 0, false);
    assert_eq!(
        fs.zw_rename_file(
            alias.handle,
            FileRenameRoot::SourceParent,
            &renamed[20..],
            false,
        ),
        STATUS_SUCCESS
    );
    assert!(fs.query_attributes(r"\??\C:\links\alias.txt").is_none());
    assert!(fs.query_attributes(r"\??\C:\links\source.txt").is_some());
    assert!(fs.query_attributes(r"\??\C:\links\renamed.txt").is_some());
    assert_eq!(
        fs.zw_query_opened_name(alias.handle).as_deref(),
        Some(r"\links\renamed.txt")
    );

    assert_eq!(
        fs.zw_set_information_file(source.handle, FILE_DISPOSITION_INFORMATION, &[1]),
        STATUS_SUCCESS
    );
    assert_eq!(fs.zw_close(source.handle), STATUS_SUCCESS);
    assert!(fs.query_attributes(r"\??\C:\links\source.txt").is_none());
    assert_eq!(
        fs.zw_query_standard_information(alias.handle)
            .unwrap()
            .number_of_links,
        1
    );

    let displaced = fs.zw_create_file(
        r"\??\C:\links\target.txt",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(displaced.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_write_file(displaced.handle, None, b"old"),
        (STATUS_SUCCESS, 3)
    );
    let target = rename_information("target.txt", dir.handle, true);
    assert_eq!(
        fs.zw_link_file(
            alias.handle,
            FileRenameRoot::Directory(dir.handle),
            &target[20..],
            true,
        ),
        STATUS_SUCCESS
    );
    assert_eq!(
        fs.file_bytes(r"\??\C:\links\target.txt"),
        Some(&b"shared"[..])
    );
    assert_eq!(
        fs.zw_read_file(displaced.handle, Some(0), 8),
        (STATUS_SUCCESS, b"old".to_vec())
    );
    assert_eq!(
        fs.zw_query_opened_name(displaced.handle).as_deref(),
        Some(r"\links\target.txt")
    );
    assert_eq!(fs.zw_close(displaced.handle), STATUS_SUCCESS);
    assert_eq!(
        fs.zw_query_standard_information(alias.handle)
            .unwrap()
            .number_of_links,
        2
    );
    assert_eq!(
        fs.zw_link_file(
            dir.handle,
            FileRenameRoot::Directory(dir.handle),
            &target[20..],
            true,
        ),
        STATUS_INVALID_PARAMETER
    );

    let snapshot = fs.export_volume_snapshot().unwrap();
    assert_eq!(MemFs::snapshot_info(&snapshot).unwrap().version, 6);
    let mut restored = FileSystem::from_volume_snapshot(&snapshot).unwrap();
    assert!(!restored.initialize_timestamps(300));
    let restored_alias = restored.zw_create_file(
        r"\??\C:\links\renamed.txt",
        FILE_WRITE_DATA,
        0,
        FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    let restored_target = restored.zw_create_file(
        r"\??\C:\links\target.txt",
        FILE_WRITE_DATA,
        0,
        FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(restored_alias.status, STATUS_SUCCESS);
    assert_eq!(restored_target.status, STATUS_SUCCESS);
    let restored_alias_metadata = restored.zw_query_metadata(restored_alias.handle).unwrap();
    let restored_target_metadata = restored.zw_query_metadata(restored_target.handle).unwrap();
    assert_eq!(restored_alias_metadata.file_id, written_metadata.file_id);
    assert_eq!(restored_target_metadata.file_id, written_metadata.file_id);
    assert_eq!(restored_alias_metadata.creation_time, 100);
    assert_eq!(restored_alias_metadata.last_write_time, 200);
    assert_eq!(
        restored
            .zw_query_standard_information(restored_alias.handle)
            .unwrap()
            .number_of_links,
        2
    );
    assert_eq!(
        restored.zw_write_file(restored_target.handle, Some(0), b"again!"),
        (STATUS_SUCCESS, 6)
    );
    assert_eq!(
        restored.file_bytes(r"\??\C:\links\renamed.txt"),
        Some(&b"again!"[..])
    );
}

#[test]
fn file_allocation_information_is_distinct_from_end_of_file_and_persists() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\allocation"));
    let file = fs.zw_create_file(
        r"\??\C:\allocation\state.bin",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(file.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_write_file(file.handle, None, &[0x5A; 5000]),
        (STATUS_SUCCESS, 5000)
    );
    assert_eq!(
        fs.zw_query_metadata(file.handle).unwrap().allocation_size,
        8192
    );

    assert_eq!(
        fs.zw_set_information_file(
            file.handle,
            FILE_ALLOCATION_INFORMATION,
            &16384u64.to_le_bytes(),
        ),
        STATUS_SUCCESS
    );
    let preallocated = fs.zw_query_metadata(file.handle).unwrap();
    assert_eq!(preallocated.end_of_file, 5000);
    assert_eq!(preallocated.allocation_size, 16384);

    let snapshot = fs.export_volume_snapshot().unwrap();
    assert_eq!(MemFs::snapshot_info(&snapshot).unwrap().version, 6);
    let mut restored = FileSystem::from_volume_snapshot(&snapshot).unwrap();
    let reopened = restored.zw_create_file(
        r"\??\C:\allocation\state.bin",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    let persisted = restored.zw_query_metadata(reopened.handle).unwrap();
    assert_eq!(persisted.end_of_file, 5000);
    assert_eq!(persisted.allocation_size, 16384);

    assert_eq!(
        restored.zw_set_information_file(
            reopened.handle,
            FILE_ALLOCATION_INFORMATION,
            &4096u64.to_le_bytes(),
        ),
        STATUS_SUCCESS
    );
    let truncated = restored.zw_query_metadata(reopened.handle).unwrap();
    assert_eq!(truncated.end_of_file, 4096);
    assert_eq!(truncated.allocation_size, 4096);

    assert_eq!(
        restored.zw_set_information_file(
            reopened.handle,
            FILE_END_OF_FILE_INFORMATION,
            &2000u64.to_le_bytes(),
        ),
        STATUS_SUCCESS
    );
    let shrunk_eof = restored.zw_query_metadata(reopened.handle).unwrap();
    assert_eq!(shrunk_eof.end_of_file, 2000);
    assert_eq!(shrunk_eof.allocation_size, 4096);

    assert_eq!(
        restored.zw_set_information_file(
            reopened.handle,
            FILE_END_OF_FILE_INFORMATION,
            &6000u64.to_le_bytes(),
        ),
        STATUS_SUCCESS
    );
    let grown = restored.zw_query_metadata(reopened.handle).unwrap();
    assert_eq!(grown.end_of_file, 6000);
    assert_eq!(grown.allocation_size, 8192);
    for class in [FILE_ALLOCATION_INFORMATION, FILE_END_OF_FILE_INFORMATION] {
        assert_eq!(
            restored.zw_set_information_file(reopened.handle, class, &u64::MAX.to_le_bytes()),
            STATUS_INVALID_PARAMETER
        );
    }
    assert_eq!(restored.zw_query_metadata(reopened.handle).unwrap(), grown);
}

#[test]
fn valid_data_length_is_privileged_monotonic_node_state_and_persists() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\vdl"));
    let file = fs.zw_create_file(
        r"\??\C:\vdl\state.bin",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(file.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_write_file(file.handle, Some(0), &[0x5a; 100]),
        (STATUS_SUCCESS, 100)
    );
    assert_eq!(
        fs.zw_set_information_file(
            file.handle,
            FILE_END_OF_FILE_INFORMATION,
            &200u64.to_le_bytes(),
        ),
        STATUS_SUCCESS
    );
    let grown = fs.zw_query_metadata(file.handle).unwrap();
    assert_eq!(grown.end_of_file, 200);
    assert_eq!(grown.valid_data_length, 100);

    // FastFAT captures SeManageVolumePrivilege into the CCB during create. Merely holding
    // FILE_WRITE_DATA is insufficient for an explicit VDL change.
    assert_eq!(
        fs.zw_set_information_file(
            file.handle,
            FILE_VALID_DATA_LENGTH_INFORMATION,
            &150u64.to_le_bytes(),
        ),
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        fs.capture_open_privileges(
            file.handle,
            FileOpenPrivileges {
                manage_volume: true,
            },
        ),
        STATUS_SUCCESS
    );
    assert_eq!(
        fs.zw_set_information_file(
            file.handle,
            FILE_VALID_DATA_LENGTH_INFORMATION,
            &150u64.to_le_bytes(),
        ),
        STATUS_SUCCESS
    );
    for invalid in [149u64, 201, u64::MAX] {
        assert_eq!(
            fs.zw_set_information_file(
                file.handle,
                FILE_VALID_DATA_LENGTH_INFORMATION,
                &invalid.to_le_bytes(),
            ),
            STATUS_INVALID_PARAMETER
        );
    }

    let snapshot = fs.export_volume_snapshot().unwrap();
    assert_eq!(MemFs::snapshot_info(&snapshot).unwrap().version, 6);
    let mut restored = FileSystem::from_volume_snapshot(&snapshot).unwrap();
    let reopened = restored.zw_create_file(
        r"\??\C:\vdl\state.bin",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    let persisted = restored.zw_query_metadata(reopened.handle).unwrap();
    assert_eq!(persisted.end_of_file, 200);
    assert_eq!(persisted.valid_data_length, 150);

    assert_eq!(
        restored.zw_set_information_file(
            reopened.handle,
            FILE_END_OF_FILE_INFORMATION,
            &120u64.to_le_bytes(),
        ),
        STATUS_SUCCESS
    );
    assert_eq!(
        restored
            .zw_query_metadata(reopened.handle)
            .unwrap()
            .valid_data_length,
        120
    );
    assert_eq!(
        restored.zw_write_file(reopened.handle, Some(180), b"write"),
        (STATUS_SUCCESS, 5)
    );
    let written = restored.zw_query_metadata(reopened.handle).unwrap();
    assert_eq!(written.end_of_file, 185);
    assert_eq!(written.valid_data_length, 185);
}

#[test]
fn short_names_are_entry_owned_collision_checked_enumerated_and_persisted() {
    fn short_name_information(name: &str) -> alloc::vec::Vec<u8> {
        let units: alloc::vec::Vec<u16> = name.encode_utf16().collect();
        let mut information = alloc::vec![0u8; (4 + units.len() * 2).max(8)];
        information[..4].copy_from_slice(&((units.len() * 2) as u32).to_le_bytes());
        for (index, unit) in units.iter().copied().enumerate() {
            information[4 + index * 2..6 + index * 2].copy_from_slice(&unit.to_le_bytes());
        }
        information
    }

    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\aliases"));
    let long = fs.zw_create_file(
        r"\??\C:\aliases\Long Document.txt",
        FILE_WRITE_DATA,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(long.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_set_information_file(
            long.handle,
            FILE_SHORT_NAME_INFORMATION,
            &short_name_information("LONGDO~1.TXT"),
        ),
        STATUS_SUCCESS
    );
    assert_eq!(
        fs.zw_query_short_name(long.handle).unwrap().units(),
        &"LONGDO~1.TXT"
            .encode_utf16()
            .collect::<alloc::vec::Vec<_>>()
    );

    let by_alias = fs.zw_create_file(
        r"\??\C:\aliases\longdo~1.txt",
        FILE_READ_DATA,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(by_alias.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_query_metadata(by_alias.handle).unwrap().file_id,
        fs.zw_query_metadata(long.handle).unwrap().file_id
    );

    let other = fs.zw_create_file(
        r"\??\C:\aliases\other.txt",
        FILE_WRITE_DATA,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(other.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_set_information_file(
            other.handle,
            FILE_SHORT_NAME_INFORMATION,
            &short_name_information("longdo~1.txt"),
        ),
        STATUS_OBJECT_NAME_COLLISION
    );
    assert_eq!(
        fs.zw_set_information_file(
            other.handle,
            FILE_SHORT_NAME_INFORMATION,
            &short_name_information("Long Document.txt"),
        ),
        STATUS_INFO_LENGTH_MISMATCH
    );
    assert_eq!(
        fs.zw_set_information_file(
            other.handle,
            FILE_SHORT_NAME_INFORMATION,
            &short_name_information("BAD NAME.TXT"),
        ),
        STATUS_INVALID_PARAMETER
    );

    let directory = fs.zw_create_file(
        r"\??\C:\aliases",
        FILE_READ_DATA,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE,
    );
    let pattern: alloc::vec::Vec<u16> = "LONGDO~1.TXT".encode_utf16().collect();
    let mut encoded = [0u8; 256];
    let result = fs.zw_query_directory_file(
        directory.handle,
        FILE_BOTH_DIRECTORY_INFORMATION,
        true,
        Some(&pattern),
        true,
        &mut encoded,
    );
    assert_eq!(result.status, STATUS_SUCCESS);
    assert_eq!(encoded[68], 24);
    let enumerated_short: alloc::vec::Vec<u16> = encoded[70..94]
        .chunks_exact(2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .collect();
    assert_eq!(enumerated_short, pattern);

    let link_name = rename_information("Second Link.txt", directory.handle, false);
    assert_eq!(
        fs.zw_link_file(
            long.handle,
            FileRenameRoot::Directory(directory.handle),
            &link_name[20..],
            false,
        ),
        STATUS_SUCCESS
    );
    let second_link = fs.zw_create_file(
        r"\??\C:\aliases\Second Link.txt",
        FILE_WRITE_DATA,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(second_link.status, STATUS_SUCCESS);
    assert!(fs
        .zw_query_short_name(second_link.handle)
        .unwrap()
        .units()
        .is_empty());
    assert_eq!(
        fs.zw_set_information_file(
            second_link.handle,
            FILE_SHORT_NAME_INFORMATION,
            &short_name_information("LONGDO~2.TXT"),
        ),
        STATUS_SUCCESS
    );
    assert_eq!(
        fs.zw_query_short_name(long.handle).unwrap().units(),
        pattern
    );

    let snapshot = fs.export_volume_snapshot().unwrap();
    assert_eq!(MemFs::snapshot_info(&snapshot).unwrap().version, 6);
    let mut restored = FileSystem::from_volume_snapshot(&snapshot).unwrap();
    let restored_alias = restored.zw_create_file(
        r"\??\C:\aliases\LONGDO~1.TXT",
        FILE_WRITE_DATA,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(restored_alias.status, STATUS_SUCCESS);
    let restored_second_alias = restored.zw_create_file(
        r"\??\C:\aliases\LONGDO~2.TXT",
        FILE_READ_DATA,
        0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(restored_second_alias.status, STATUS_SUCCESS);
    assert_eq!(
        restored
            .zw_query_metadata(restored_second_alias.handle)
            .unwrap()
            .file_id,
        restored
            .zw_query_metadata(restored_alias.handle)
            .unwrap()
            .file_id
    );
    assert_eq!(
        restored
            .zw_query_short_name(restored_alias.handle)
            .unwrap()
            .units(),
        pattern
    );
    assert_eq!(
        restored.zw_set_information_file(
            restored_alias.handle,
            FILE_SHORT_NAME_INFORMATION,
            &short_name_information(""),
        ),
        STATUS_SUCCESS
    );
    assert!(restored
        .zw_query_short_name(restored_alias.handle)
        .unwrap()
        .units()
        .is_empty());
    assert_eq!(
        restored
            .zw_create_file(
                r"\??\C:\aliases\LONGDO~1.TXT",
                FILE_READ_DATA,
                0,
                0,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE,
            )
            .status,
        STATUS_OBJECT_NAME_NOT_FOUND
    );
}

#[test]
fn memfs_snapshot_v6_reader_accepts_version_five_without_short_name_storage() {
    fn checksum(bytes: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for &byte in bytes {
            crc ^= byte as u32;
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    (crc >> 1) ^ 0x82F6_3B78
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    let mut payload = alloc::vec![0u8; 77];
    payload[0] = 1;
    payload[1..5].copy_from_slice(&FILE_ATTRIBUTE_DIRECTORY.to_le_bytes());
    let mut snapshot = alloc::vec![0u8; 32];
    snapshot[0..8].copy_from_slice(b"USNTFS\0\x01");
    snapshot[8..10].copy_from_slice(&32u16.to_le_bytes());
    snapshot[10..12].copy_from_slice(&5u16.to_le_bytes());
    snapshot[12..16].copy_from_slice(&1u32.to_le_bytes());
    snapshot[16..24].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    snapshot[24..28].copy_from_slice(&checksum(&payload).to_le_bytes());
    let header_crc = checksum(&snapshot[..28]);
    snapshot[28..32].copy_from_slice(&header_crc.to_le_bytes());
    snapshot.extend_from_slice(&payload);

    let fs = FileSystem::from_volume_snapshot(&snapshot).unwrap();
    assert_eq!(
        MemFs::snapshot_info(&fs.export_volume_snapshot().unwrap())
            .unwrap()
            .version,
        6
    );
}

#[test]
fn writable_volume_disposition_ex_controls_delete_pending() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\profiles"));

    let f = fs.zw_create_file(
        r"\??\C:\profiles\scratch.tmp",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(f.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_write_file(f.handle, None, b"scratch"),
        (STATUS_SUCCESS, 7)
    );
    assert_eq!(
        fs.zw_set_information_file(
            f.handle,
            FILE_DISPOSITION_INFORMATION_EX,
            &disposition_ex(FILE_DISPOSITION_DELETE | FILE_DISPOSITION_ON_CLOSE),
        ),
        STATUS_SUCCESS
    );
    assert_eq!(
        fs.zw_set_information_file(
            f.handle,
            FILE_DISPOSITION_INFORMATION_EX,
            &disposition_ex(FILE_DISPOSITION_ON_CLOSE),
        ),
        STATUS_SUCCESS
    );
    fs.zw_close(f.handle);
    assert!(fs
        .query_attributes(r"\??\C:\profiles\scratch.tmp")
        .is_some());

    let f = fs.zw_create_file(
        r"\??\C:\profiles\readonly.tmp",
        FILE_WRITE_DATA,
        FILE_ATTRIBUTE_READONLY,
        0,
        FILE_CREATE,
        FILE_NON_DIRECTORY_FILE,
    );
    assert_eq!(f.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_set_information_file(
            f.handle,
            FILE_DISPOSITION_INFORMATION_EX,
            &disposition_ex(FILE_DISPOSITION_DELETE),
        ),
        STATUS_CANNOT_DELETE
    );
    assert_eq!(
        fs.zw_set_information_file(
            f.handle,
            FILE_DISPOSITION_INFORMATION_EX,
            &disposition_ex(
                FILE_DISPOSITION_DELETE
                    | FILE_DISPOSITION_POSIX_SEMANTICS
                    | FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
            ),
        ),
        STATUS_SUCCESS
    );
    fs.zw_close(f.handle);
    assert!(fs
        .query_attributes(r"\??\C:\profiles\readonly.tmp")
        .is_none());
}

#[test]
fn writable_volume_disposition_rejects_invalid_and_nonempty_directory_delete() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(r"\??\C:\profiles\dir\child.txt", b"child"));
    let dir = fs.zw_create_file(
        r"\??\C:\profiles\dir",
        FILE_WRITE_DATA,
        0,
        0,
        FILE_OPEN,
        FILE_DIRECTORY_FILE,
    );
    assert_eq!(dir.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_set_information_file(
            dir.handle,
            FILE_DISPOSITION_INFORMATION_EX,
            &disposition_ex(FILE_DISPOSITION_DELETE),
        ),
        STATUS_DIRECTORY_NOT_EMPTY
    );
    assert_eq!(
        fs.zw_set_information_file(
            dir.handle,
            FILE_DISPOSITION_INFORMATION_EX,
            &disposition_ex(0x8000_0000),
        ),
        STATUS_INVALID_PARAMETER
    );
    assert_eq!(
        fs.zw_set_information_file(dir.handle, FILE_DISPOSITION_INFORMATION_EX, &[1, 0, 0]),
        STATUS_INFO_LENGTH_MISMATCH
    );
    fs.zw_close(dir.handle);
    assert!(fs.query_attributes(r"\??\C:\profiles\dir").is_some());
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
    let info = fs
        .query_attributes(r"\??\C:\profiles\Default User\ntuser.dat")
        .unwrap();
    assert!(!info.is_directory);
    assert_eq!(info.end_of_file, HIVE.len() as u64);
    // (3) It borrows back in place, byte-identical.
    assert_eq!(
        fs.file_bytes(r"\??\C:\profiles\Default User\ntuser.dat"),
        Some(HIVE)
    );
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
    let r = fs.zw_query_directory_file(
        dir.handle,
        FILE_DIRECTORY_INFORMATION,
        false,
        None,
        true,
        &mut out,
    );
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

#[test]
fn owned_provisioning_installs_large_file_without_copying_into_blob_store() {
    let mut fs = FileSystem::new(MemFs::new());
    let mut hive_image = alloc::vec::Vec::new();
    hive_image.resize(130_682, 0x5a);
    hive_image[..4].copy_from_slice(b"UNTH");

    assert!(fs
        .provision_file_owned(
            r"\??\C:\profiles\Default User\ntuser.dat",
            hive_image.clone()
        )
        .is_ok());
    assert_eq!(
        fs.query_attributes(r"\??\C:\profiles\Default User\ntuser.dat")
            .unwrap()
            .end_of_file,
        130_682
    );
    assert_eq!(
        fs.file_bytes(r"\??\C:\profiles\Default User\ntuser.dat"),
        Some(hive_image.as_slice())
    );
    assert_eq!(fs.unique_data_blobs(), 0);

    let returned = fs
        .provision_file_owned(r"\??\D:\outside.dat", hive_image)
        .expect_err("unmounted volume returns owned buffer");
    assert_eq!(returned.len(), 130_682);
}

/// Provisioning REPLACES an existing file's bytes exactly (no append, no stale tail), refuses a
/// path that names a directory, and refuses a path off this volume. `file_bytes` misses honestly.
#[test]
fn provisioning_replaces_bytes_and_refuses_non_files() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(r"\??\C:\profiles\Default User\ntuser.dat", b"0123456789"));
    assert!(fs.provision_file(r"\??\C:\profiles\Default User\ntuser.dat", b"abc"));
    assert_eq!(
        fs.file_bytes(r"\??\C:\profiles\Default User\ntuser.dat"),
        Some(&b"abc"[..])
    );
    assert_eq!(
        fs.query_attributes(r"\??\C:\profiles\Default User\ntuser.dat")
            .unwrap()
            .end_of_file,
        3
    );
    // A directory is not a file.
    assert!(!fs.provision_file(r"\??\C:\profiles\Default User", b"x"));
    assert_eq!(fs.file_bytes(r"\??\C:\profiles\Default User"), None);
    // A path that never resolved is an honest miss.
    assert_eq!(fs.file_bytes(r"\??\C:\profiles\nope.dat"), None);
}

#[test]
fn installed_file_import_preserves_state_before_normal_open() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory_relative(b"reactos\\system32"));
    let source = FileMetadata {
        creation_time: 11,
        last_access_time: 22,
        last_write_time: 33,
        change_time: 44,
        allocation_size: 4096,
        end_of_file: 7,
        valid_data_length: 7,
        file_id: 0x1234_5678,
        attributes: FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE,
        reparse_tag: 0,
        number_of_links: 1,
        delete_pending: false,
        is_directory: false,
    };
    assert_eq!(
        fs.import_file_relative(
            b"reactos\\system32\\installed.dat",
            source,
            b"payload".to_vec(),
        ),
        Ok(true)
    );
    let imported = fs
        .query_metadata_relative(b"reactos\\system32\\installed.dat")
        .unwrap();
    assert_eq!(imported.creation_time, 11);
    assert_eq!(imported.last_access_time, 22);
    assert_eq!(imported.last_write_time, 33);
    assert_eq!(imported.change_time, 44);
    assert_eq!(
        imported.attributes,
        FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE
    );
    assert_ne!(imported.file_id, 0);
    assert_ne!(imported.file_id, source.file_id);
    assert_eq!(
        fs.file_bytes_relative(b"reactos\\system32\\installed.dat"),
        Some(&b"payload"[..])
    );

    let opened = fs.zw_create_file_relative(
        b"reactos\\system32\\installed.dat",
        FILE_READ_DATA | FILE_WRITE_DATA | SYNCHRONIZE,
        0,
        0,
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
    );
    assert_eq!(opened.status, STATUS_SUCCESS);
    assert_eq!(opened.information, FILE_OPENED);
    assert_eq!(
        fs.zw_read_file(opened.handle, Some(0), 7),
        (STATUS_SUCCESS, b"payload".to_vec())
    );
}

#[test]
fn installed_file_import_is_fail_closed_and_never_replaces_the_writable_winner() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory_relative(b"reactos"));
    let metadata = FileMetadata {
        end_of_file: 3,
        attributes: FILE_ATTRIBUTE_ARCHIVE,
        number_of_links: 1,
        ..FileMetadata::default()
    };
    assert_eq!(
        fs.import_file_relative(b"reactos\\state.dat", metadata, b"fat".to_vec()),
        Ok(true)
    );
    assert_eq!(
        fs.import_file_relative(b"reactos\\state.dat", metadata, b"new".to_vec()),
        Ok(false)
    );
    assert_eq!(
        fs.file_bytes_relative(b"reactos\\state.dat"),
        Some(&b"fat"[..])
    );

    let invalid = FileMetadata {
        end_of_file: 4,
        ..metadata
    };
    assert_eq!(
        fs.import_file_relative(b"reactos\\bad.dat", invalid, b"bad".to_vec()),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(fs.file_bytes_relative(b"reactos\\bad.dat"), None);
    assert_eq!(
        fs.import_file_relative(b"missing\\bad.dat", metadata, b"bad".to_vec()),
        Err(STATUS_OBJECT_PATH_NOT_FOUND)
    );
    assert_eq!(fs.file_bytes_relative(b"missing\\bad.dat"), None);
}

#[test]
fn installed_file_open_policy_has_one_owner_for_every_disposition() {
    assert_eq!(
        installed_file_open_action(FILE_READ_DATA, FILE_OPEN, 0),
        Ok(InstalledFileOpenAction::ReadOnly)
    );
    assert_eq!(
        installed_file_open_action(FILE_READ_DATA, FILE_OPEN_IF, 0),
        Ok(InstalledFileOpenAction::ReadOnly)
    );
    for access in [FILE_WRITE_DATA, FILE_APPEND_DATA, 0x0001_0000, 0x0200_0000] {
        assert_eq!(
            installed_file_open_action(access, FILE_OPEN, 0),
            Ok(InstalledFileOpenAction::CopyContents)
        );
    }
    assert_eq!(
        installed_file_open_action(FILE_READ_DATA, FILE_OPEN, FILE_DELETE_ON_CLOSE),
        Ok(InstalledFileOpenAction::CopyContents)
    );
    for disposition in [FILE_OVERWRITE, FILE_OVERWRITE_IF, FILE_SUPERSEDE] {
        assert_eq!(
            installed_file_open_action(FILE_WRITE_DATA, disposition, 0),
            Ok(InstalledFileOpenAction::CopyMetadata)
        );
    }
    assert_eq!(
        installed_file_open_action(FILE_READ_DATA, FILE_CREATE, 0),
        Ok(InstalledFileOpenAction::NameCollision)
    );
    assert_eq!(
        installed_file_open_action(FILE_READ_DATA, 6, 0),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        installed_file_open_action(FILE_READ_DATA, FILE_OPEN, FILE_DIRECTORY_FILE),
        Err(STATUS_NOT_A_DIRECTORY)
    );
}

#[test]
fn provisioned_file_extend_reads_zeroes_and_materializes_on_write() {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_file(r"\??\C:\profiles\AppEvent.Evt", b"evt"));
    let f = fs.zw_create_file(
        r"\??\C:\profiles\AppEvent.Evt",
        FILE_READ_DATA | FILE_WRITE_DATA,
        0,
        0,
        FILE_OPEN,
        0,
    );
    assert_eq!(f.status, STATUS_SUCCESS);
    assert_eq!(
        fs.zw_set_information_file(f.handle, FILE_END_OF_FILE_INFORMATION, &8u64.to_le_bytes()),
        STATUS_SUCCESS
    );
    assert_eq!(
        fs.zw_query_standard_information(f.handle)
            .unwrap()
            .end_of_file,
        8
    );
    let (status, bytes) = fs.zw_read_file(f.handle, Some(0), 8);
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(&bytes, b"evt\0\0\0\0\0");

    assert_eq!(
        fs.zw_write_file(f.handle, Some(5), b"xy"),
        (STATUS_SUCCESS, 2)
    );
    let (status, bytes) = fs.zw_read_file(f.handle, Some(0), 8);
    assert_eq!(status, STATUS_SUCCESS);
    assert_eq!(&bytes, b"evt\0\0xy\0");
}
