use super::*;
use crate::snapshot_test_device::CachedDisk;

fn reference_crc32c(bytes: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

#[test]
fn snapshot_crc_matches_castagnoli_golden_vectors() {
    assert_eq!(crc32c(b""), 0);
    assert_eq!(crc32c(b"123456789"), 0xe306_9283);
    assert_eq!(crc32c(&[0; 32]), 0x8a91_36aa);
    assert_eq!(crc32c(&[0xff; 32]), 0x62a8_ab43);
}

#[test]
fn snapshot_crc_matches_bitwise_reference_across_fragment_boundaries() {
    for length in [0, 1, 7, 31, 255, 512, 4097, 65537] {
        let bytes: Vec<u8> = (0..length)
            .map(|index| ((index * 73 + index / 11) & 0xff) as u8)
            .collect();
        let expected = reference_crc32c(&bytes);
        assert_eq!(crc32c(&bytes), expected);
        for chunk in [1, 3, 9, 127, 512, 2048] {
            let mut incremental = Crc32c::new();
            incremental.update(&[]);
            for bytes in bytes.chunks(chunk) {
                incremental.update(bytes);
                incremental.update(&[]);
            }
            assert_eq!(
                incremental.finish(),
                expected,
                "length={length} chunk={chunk}"
            );
        }
    }
}

#[derive(Default)]
struct ReferencePayload(Vec<u8>);

impl SnapshotPayloadSink for ReferencePayload {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}

fn reference_snapshot(volume: &MemFs) -> Vec<u8> {
    let mut payload = ReferencePayload::default();
    let records = volume.write_snapshot_payload_to_sink(&mut payload).unwrap();
    let mut header = [0u8; MEMFS_SNAPSHOT_HEADER_LEN];
    header[..8].copy_from_slice(&MEMFS_SNAPSHOT_MAGIC);
    header[8..10].copy_from_slice(&(MEMFS_SNAPSHOT_HEADER_LEN as u16).to_le_bytes());
    header[10..12].copy_from_slice(&MEMFS_SNAPSHOT_VERSION.to_le_bytes());
    header[12..16].copy_from_slice(&records.to_le_bytes());
    header[16..24].copy_from_slice(&(payload.0.len() as u64).to_le_bytes());
    header[24..28].copy_from_slice(&reference_crc32c(&payload.0).to_le_bytes());
    let header_crc = reference_crc32c(&header[..28]);
    header[28..32].copy_from_slice(&header_crc.to_le_bytes());
    let mut image = header.to_vec();
    image.extend_from_slice(&payload.0);
    image
}

#[test]
fn fragmented_snapshot_updates_preserve_encoded_bytes_and_durable_payload() {
    const PATH: &str = r"\??\C:\Config\Hive.LOG";
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\Config"));
    assert!(fs.provision_file(PATH, b"initial"));
    let mut disk = CachedDisk::new();
    let store = SnapshotBlockStore::new(0, disk.sector_count());
    for (index, length) in [1, 7, 31, 64, 127, 257, 11, 33].into_iter().enumerate() {
        let bytes = alloc::vec![index as u8; length];
        assert_eq!(
            fs.append_file_by_path(PATH, &bytes),
            (STATUS_SUCCESS, length)
        );
        let expected = reference_snapshot(&fs.volume);
        assert_eq!(fs.export_volume_snapshot().unwrap(), expected);
        let (generation, length) = fs.commit_volume_snapshot(&store, &mut disk).unwrap();
        assert_eq!(generation, index as u64 + 1);
        assert_eq!(length, expected.len());
        disk.power_cut();
        let stored = store.read_latest(&mut disk).unwrap().unwrap();
        assert_eq!(stored.generation, generation);
        assert_eq!(stored.payload, expected);
        let restored = MemFs::from_snapshot(&stored.payload).unwrap();
        assert_eq!(restored.to_snapshot().unwrap(), expected);
    }
}
