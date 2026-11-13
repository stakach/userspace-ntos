use nt_fs::{FatPathGeometry, FatPathLookup, FatPathProgress, FatPathRequestKind,
    InstalledMetadataSectorCache, STATUS_DATA_ERROR};

const LFN_OFFSETS: [usize; 13] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
const GEOMETRY: FatPathGeometry = FatPathGeometry {
    fat_start_sector: 1, data_start_sector: 100, total_sectors: 200, sectors_per_cluster: 1,
};

fn deleted_sector() -> [u8; 512] { [0xe5; 512] }

fn short_entry(name: &[u8; 11], cluster: u16, size: u32) -> [u8; 32] {
    let mut entry = [0; 32];
    entry[..11].copy_from_slice(name);
    entry[11] = 0x20;
    entry[26..28].copy_from_slice(&cluster.to_le_bytes());
    entry[28..32].copy_from_slice(&size.to_le_bytes());
    entry
}

fn long_entry(short: &[u8; 11], name: &str) -> [u8; 32] {
    let mut entry = [0xff; 32];
    entry[0] = 0x41;
    entry[11] = 0x0f;
    entry[12] = 0;
    entry[13] = short.iter().fold(0u8, |sum, byte| sum.rotate_right(1).wrapping_add(*byte));
    entry[26..28].copy_from_slice(&0u16.to_le_bytes());
    let name: Vec<_> = name.encode_utf16().collect();
    assert!(name.len() <= 13);
    for (index, offset) in LFN_OFFSETS.into_iter().enumerate() {
        let unit = name.get(index).copied().unwrap_or(if index == name.len() { 0 } else { 0xffff });
        entry[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
    }
    entry
}

fn fixture(sector: u32) -> [u8; 512] {
    match sector {
        100 => deleted_sector(),
        101 => {
            let mut bytes = deleted_sector();
            bytes[..32].copy_from_slice(&short_entry(b"FIRST   TXT", 8, 1234));
            bytes
        }
        102 => {
            let alias = *b"LONGNA~1TXT";
            let mut bytes = deleted_sector();
            bytes[..32].copy_from_slice(&long_entry(&alias, "Long name.txt"));
            bytes[32..64].copy_from_slice(&short_entry(&alias, 9, 5678));
            bytes[64] = 0;
            bytes
        }
        _ => panic!("unexpected Directory sector {sector}"),
    }
}

fn lookup(
    cache: &mut InstalledMetadataSectorCache<u64, 3>, generation: u64, name: &[u8],
    physical: &mut Vec<u32>,
) -> Option<(u32, u64, u64, Vec<u16>, Vec<u16>)> {
    let mut lookup = FatPathLookup::new(GEOMETRY, 2, name).unwrap();
    loop {
        let request = lookup.request().unwrap();
        let bytes = match request.kind {
            FatPathRequestKind::Directory => cache.read_or_fetch(generation, request.sector, |sector, bytes| {
                physical.push(sector);
                *bytes = fixture(sector);
                Ok::<(), u32>(())
            }).unwrap(),
            FatPathRequestKind::Fat => {
                let mut fat = [0; 512];
                fat[8..12].copy_from_slice(&3u32.to_le_bytes());
                fat[12..16].copy_from_slice(&4u32.to_le_bytes());
                fat[16..20].copy_from_slice(&0x0fff_ffffu32.to_le_bytes());
                fat
            }
        };
        match lookup.feed(request, &bytes).unwrap() {
            FatPathProgress::Pending => {}
            FatPathProgress::NotFound => return None,
            FatPathProgress::Found => {
                let record = lookup.take_found().unwrap();
                let metadata = record.metadata();
                return Some((record.first_cluster, metadata.end_of_file, metadata.file_id,
                    record.entry.name().to_vec(), record.entry.short_name().to_vec()));
            }
        }
    }
}

#[test]
fn repeated_multicluster_lookup_preserves_lfn_alias_metadata_and_distinct_sector_budget() {
    let mut cache = InstalledMetadataSectorCache::<u64, 3>::new();
    let mut physical = Vec::new();
    assert_eq!(lookup(&mut cache, 7, b"missing.txt", &mut physical), None);
    assert_eq!(physical, [100, 101, 102]);
    for name in [b"FIRST.TXT".as_slice(), b"Long name.txt", b"LONGNA~1.TXT", b"missing.txt"] {
        let before = physical.len();
        let result = lookup(&mut cache, 7, name, &mut physical);
        assert_eq!(physical.len(), before, "warm lookup must use copied Directory sectors");
        if name == b"missing.txt" { assert_eq!(result, None); continue; }
        let (cluster, size, file_id, long, short) = result.unwrap();
        if name == b"FIRST.TXT" {
            assert_eq!((cluster, size), (8, 1234));
        } else {
            assert_eq!((cluster, size), (9, 5678));
            assert_eq!(long, "Long name.txt".encode_utf16().collect::<Vec<_>>());
            assert_eq!(short, "LONGNA~1.TXT".encode_utf16().collect::<Vec<_>>());
        }
        assert_eq!(file_id >> 32, 2);
    }
}

#[test]
fn generation_write_uncertainty_failure_and_eviction_fence_copied_sectors() {
    let mut cache = InstalledMetadataSectorCache::<u64, 2>::new();
    let mut physical = 0;
    for sector in [100, 101, 102] {
        cache.read_or_fetch(7, sector, |_, bytes| {
            physical += 1; bytes.fill(sector as u8); Ok::<(), u32>(())
        }).unwrap();
    }
    assert_eq!(physical, 3);
    assert!(cache.lookup(7, 100).is_none(), "oldest sector is evicted");
    assert_eq!(cache.lookup(7, 101).unwrap()[0], 101);
    assert!(cache.lookup(8, 101).is_none(), "mount generation changes identity");
    cache.invalidate(); // Before any possible installed write, including uncertain results.
    assert!(cache.lookup(7, 101).is_none());
    assert_eq!(cache.read_or_fetch(7, 101, |_, bytes| {
        physical += 1; bytes.fill(0xaa); Err::<(), _>(STATUS_DATA_ERROR)
    }).map(|_| ()), Err(STATUS_DATA_ERROR));
    assert!(cache.lookup(7, 101).is_none(), "failed fetch must not publish DMA bytes");
    assert_eq!(cache.read_or_fetch(7, 101, |_, bytes| {
        physical += 1; bytes.fill(0xbb); Ok::<(), u32>(())
    }).unwrap()[0], 0xbb);
    assert_eq!(physical, 5);

    let mut disabled = InstalledMetadataSectorCache::<u64, 0>::new();
    for value in [1, 2] {
        assert_eq!(disabled.read_or_fetch(7, 101, |_, bytes| {
            bytes.fill(value); Ok::<(), u32>(())
        }).unwrap()[0], value);
    }
    assert!(disabled.lookup(7, 101).is_none());
}
