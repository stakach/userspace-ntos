use nt_fs::{FatSectorCache, STATUS_DATA_ERROR};

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
