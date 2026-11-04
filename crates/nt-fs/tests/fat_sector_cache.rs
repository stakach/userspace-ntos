use nt_fs::{FatPathGeometry, FatPathLookup, FatPathProgress, FatPathRequestKind, FatSectorCache, STATUS_DATA_ERROR};

#[test]
fn adjacent_directory_links_share_one_physical_fat_sector_without_changing_lookup() {
    let geometry = FatPathGeometry {
        fat_start_sector: 1,
        data_start_sector: 100,
        total_sectors: 200,
        sectors_per_cluster: 1,
    };
    let mut cache = FatSectorCache::new();
    let mut lookup = FatPathLookup::new(geometry, 2, b"FOUND.TXT").unwrap();
    let mut link_requests = 0;
    let mut physical_link_fetches = 0;
    loop {
        let request = lookup.request().unwrap();
        let mut bytes = [0u8; 512];
        match request.kind {
            FatPathRequestKind::Directory if request.sector < 102 => bytes.fill(0xe5),
            FatPathRequestKind::Directory => {
                bytes[..11].copy_from_slice(b"FOUND   TXT");
                bytes[11] = 0x20;
                bytes[26..28].copy_from_slice(&8u16.to_le_bytes());
                bytes[28..32].copy_from_slice(&1234u32.to_le_bytes());
            }
            FatPathRequestKind::Fat => {
                link_requests += 1;
                bytes.copy_from_slice(cache.read_sector(7, request.sector, |_, sector| {
                    physical_link_fetches += 1;
                    sector[8..12].copy_from_slice(&3u32.to_le_bytes());
                    sector[12..16].copy_from_slice(&4u32.to_le_bytes());
                    Ok(())
                }).unwrap());
            }
        }
        match lookup.feed(request, &bytes).unwrap() {
            FatPathProgress::Pending => {}
            FatPathProgress::Found => break,
            FatPathProgress::NotFound => panic!("expected the third directory cluster"),
        }
    }
    let found = lookup.take_found().unwrap();
    assert_eq!((found.first_cluster, found.metadata().end_of_file), (8, 1234));
    assert_eq!(link_requests, 2);
    assert_eq!(physical_link_fetches, 1);
    assert_eq!(cache.read_entry(7, 1, 12, |_, _| panic!("same sector")), Ok(4));
}

#[test]
fn raw_sector_view_fences_remount_write_and_failed_fetch() {
    let mut cache = FatSectorCache::new();
    let mut fetches = 0;
    for (generation, value) in [(7, 3u32), (8, 4u32)] {
        let sector = cache.read_sector(generation, 1, |_, bytes| {
            fetches += 1;
            bytes[8..12].copy_from_slice(&value.to_le_bytes());
            Ok(())
        }).unwrap();
        assert_eq!(u32::from_le_bytes(sector[8..12].try_into().unwrap()), value);
    }
    assert_eq!(fetches, 2);
    cache.invalidate(); // The Executive does this before a possibly uncertain FAT write.
    assert!(cache.read_sector(8, 1, |_, _| {
        fetches += 1;
        Err(STATUS_DATA_ERROR)
    }).is_err());
    let refreshed = cache.read_sector(8, 1, |_, bytes| {
        fetches += 1;
        bytes[8..12].copy_from_slice(&5u32.to_le_bytes());
        Ok(())
    }).unwrap();
    assert_eq!(u32::from_le_bytes(refreshed[8..12].try_into().unwrap()), 5);
    assert_eq!(fetches, 4);
}

#[test]
fn cached_fat_sector_survives_unrelated_dma_payloads() {
    let mut cache = FatSectorCache::new();
    let mut fetches = 0;
    let first = cache.read_entry(7, 42, 12, |_, sector| {
        fetches += 1;
        sector[12..16].copy_from_slice(&123u32.to_le_bytes());
        Ok(())
    });
    assert_eq!(first, Ok(123));

    let mut dma_payload = [0u8; 2_048];
    dma_payload.fill(0xaa);
    assert_eq!(dma_payload[512], 0xaa);
    let again = cache.read_entry(7, 42, 12, |_, _| {
        fetches += 1;
        Ok(())
    });
    assert_eq!(again, Ok(123));
    assert_eq!(fetches, 1);
}

#[test]
fn remount_identity_and_invalidation_require_fresh_sector_reads() {
    let mut cache = FatSectorCache::new();
    let mut fetches = 0;
    for (volume, value) in [(7, 123u32), (8, 456u32)] {
        assert_eq!(
            cache.read_entry(volume, 42, 12, |_, sector| {
                fetches += 1;
                sector[12..16].copy_from_slice(&value.to_le_bytes());
                Ok(())
            }),
            Ok(value)
        );
    }
    cache.invalidate();
    assert_eq!(
        cache.read_entry(8, 42, 12, |_, _| {
            fetches += 1;
            Err(STATUS_DATA_ERROR)
        }),
        Err(STATUS_DATA_ERROR)
    );
    assert_eq!(
        cache.read_entry(8, 42, 12, |_, sector| {
            fetches += 1;
            sector[12..16].copy_from_slice(&789u32.to_le_bytes());
            Ok(())
        }),
        Ok(789)
    );
    assert_eq!(fetches, 4);
}

#[test]
fn invalid_entry_offset_is_rejected_without_io() {
    let mut cache = FatSectorCache::new();
    assert_eq!(
        cache.read_entry(7, 42, 510, |_, _| panic!("out-of-sector read")),
        Err(STATUS_DATA_ERROR)
    );
}
