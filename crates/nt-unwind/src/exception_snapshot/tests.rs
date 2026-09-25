use super::*;
use alloc::vec;

const BASE: u64 = 0x180_0000_0000;
const OPTIONAL: usize = 0x98;
const SECTION: usize = OPTIONAL + 240;

fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn mapped_pe() -> alloc::vec::Vec<u8> {
    let mut bytes = vec![0u8; 0x2000];
    put16(&mut bytes, 0, 0x5a4d);
    put32(&mut bytes, 0x3c, 0x80);
    put32(&mut bytes, 0x80, 0x4550);
    put16(&mut bytes, 0x84, 0x8664);
    put16(&mut bytes, 0x86, 1);
    put16(&mut bytes, 0x94, 240);
    put16(&mut bytes, 0x96, 2);
    put16(&mut bytes, OPTIONAL, 0x20b);
    put32(&mut bytes, OPTIONAL + 16, 0x1000);
    put64(&mut bytes, OPTIONAL + 24, 0x140_0000_0000);
    put32(&mut bytes, OPTIONAL + 32, 0x1000);
    put32(&mut bytes, OPTIONAL + 36, 0x200);
    put32(&mut bytes, OPTIONAL + 56, 0x2000);
    put32(&mut bytes, OPTIONAL + 60, 0x400);
    put32(&mut bytes, OPTIONAL + 108, 16);
    bytes[SECTION..SECTION + 8].copy_from_slice(b".text\0\0\0");
    put32(&mut bytes, SECTION + 8, 0x200);
    put32(&mut bytes, SECTION + 12, 0x1000);
    put32(&mut bytes, SECTION + 16, 0x200);
    put32(&mut bytes, SECTION + 20, 0xff_0000);
    put32(&mut bytes, SECTION + 36, 0x6000_0020);
    bytes[0x1000..0x1200].fill(0x90);
    bytes
}

fn encode_two(first: &[u8], second: &[u8]) -> alloc::vec::Vec<u8> {
    let images = [
        SnapshotImage {
            base: BASE,
            bytes: first,
        },
        SnapshotImage {
            base: BASE + 0x10000,
            bytes: second,
        },
    ];
    let mut output = vec![0; encoded_len(&images).unwrap()];
    assert_eq!(encode(&images, &mut output).unwrap(), output.len());
    output
}

fn parse_error(bytes: &[u8]) -> SnapshotError {
    let mut slots = [None, None];
    match SealedExceptionCatalog::parse(bytes, &mut slots) {
        Ok(_) => panic!("unexpectedly admitted malformed snapshot"),
        Err(error) => error,
    }
}

fn view_error(bytes: &[u8]) -> SnapshotError {
    match SealedExceptionView::parse(bytes) {
        Ok(_) => panic!("unexpectedly admitted malformed snapshot view"),
        Err(error) => error,
    }
}

fn scoped_pe() -> alloc::vec::Vec<u8> {
    let mut bytes = mapped_pe();
    put32(&mut bytes, 0x1100, 1);
    put32(&mut bytes, 0x1104, 0x1000);
    put32(&mut bytes, 0x1108, 0x1080);
    put32(&mut bytes, 0x110c, 1);
    put32(&mut bytes, 0x1110, 0x1080);
    bytes
}

#[test]
fn roundtrip_two_images_uses_exact_bases_and_no_allocating_parser() {
    let first = mapped_pe();
    let second = mapped_pe();
    let encoded = encode_two(&first, &second);
    let mut slots = [None, None, None];
    let catalog = SealedExceptionCatalog::parse(&encoded, &mut slots).unwrap();
    assert_eq!(catalog.image_count(), 2);
    assert_eq!(
        catalog.lookup_exception_function(BASE + 0x1000),
        Ok(ExceptionFunction::Leaf)
    );
    assert_eq!(
        catalog.lookup_exception_function(BASE + 0x11000),
        Ok(ExceptionFunction::Leaf)
    );
    assert_eq!(catalog.read_u8(BASE + 0x10000, 0x1000), Some(0x90));
    assert_eq!(catalog.read_u8(BASE, 0x1000), Some(0x90));
    assert_eq!(catalog.read_u8(BASE + 1, 0x1000), None);
    assert_eq!(
        catalog.lookup_exception_function(BASE + 0x2000),
        Err(ExceptionImageError::UnknownImage)
    );
    assert_eq!(
        catalog.read_c_scope_table(BASE + 1, BASE + 0x1000).err(),
        Some(ScopeTableError::UnknownImage)
    );
}

#[test]
fn sealed_view_matches_slot_catalog_across_images_and_gap() {
    let first = mapped_pe();
    let second = scoped_pe();
    let encoded = encode_two(&first, &second);
    let mut slots = [None, None];
    let catalog = SealedExceptionCatalog::parse(&encoded, &mut slots).unwrap();
    let view = SealedExceptionView::parse(&encoded).unwrap();
    assert_eq!(view.image_count(), catalog.image_count());
    for pc in [
        BASE + 0x1000,
        BASE + 0x11ff,
        BASE + 0x2000,
        BASE + 0x9000,
        BASE + 0x11000,
        BASE + 0x111ff,
    ] {
        assert_eq!(
            view.lookup_exception_function(pc),
            catalog.lookup_exception_function(pc)
        );
    }
    for base in [BASE, BASE + 1, BASE + 0x10000] {
        assert_eq!(view.read_u8(base, 0x1000), catalog.read_u8(base, 0x1000));
    }
    let second_base = BASE + 0x10000;
    assert_eq!(
        view.read_c_scope_table(second_base, second_base + 0x1100)
            .unwrap()
            .collect::<alloc::vec::Vec<_>>(),
        catalog
            .read_c_scope_table(second_base, second_base + 0x1100)
            .unwrap()
            .collect::<alloc::vec::Vec<_>>(),
    );
    assert!(view.validate_collision_scope(second_base, second_base + 0x1100, 1));
    assert!(!view.validate_collision_scope(second_base, second_base + 0x1100, 2));
    assert!(!view.validate_collision_scope(second_base + 1, second_base + 0x1100, 0));
    assert!(matches!(
        view.read_c_scope_table(second_base + 1, second_base + 0x1100),
        Err(ScopeTableError::UnknownImage),
    ));
}

#[test]
fn sealed_view_and_slot_catalog_reject_same_malformed_envelopes() {
    let first = mapped_pe();
    let second = mapped_pe();
    let encoded = encode_two(&first, &second);
    let mut cases = alloc::vec::Vec::new();
    let mut wrong_magic = encoded.clone();
    wrong_magic[0] ^= 1;
    cases.push(wrong_magic);
    let mut slack = encoded.clone();
    slack.push(0);
    cases.push(slack);
    let mut gap = encoded.clone();
    put_u64(
        &mut gap,
        HEADER_SIZE + 8,
        (HEADER_SIZE + 2 * DESCRIPTOR_SIZE + 1) as u64,
    );
    cases.push(gap);
    let mut overlap = encoded.clone();
    put_u64(&mut overlap, HEADER_SIZE + DESCRIPTOR_SIZE, BASE + 0x1000);
    cases.push(overlap);
    let mut invalid_pe = encoded.clone();
    invalid_pe[HEADER_SIZE + 2 * DESCRIPTOR_SIZE] = 0;
    cases.push(invalid_pe);
    for bytes in cases {
        assert_eq!(view_error(&bytes), parse_error(&bytes));
    }
}

#[test]
fn encoding_rejects_unadmitted_unsorted_and_overlapping_images() {
    let good = mapped_pe();
    let mut bad = mapped_pe();
    bad[0] = 0;
    assert!(matches!(
        encoded_len(&[SnapshotImage {
            base: BASE,
            bytes: &bad
        }]),
        Err(SnapshotError::ImageAdmission(_))
    ));
    assert_eq!(encoded_len(&[]), Err(SnapshotError::EmptyCatalog));
    let unordered = [
        SnapshotImage {
            base: BASE + 0x10000,
            bytes: &good,
        },
        SnapshotImage {
            base: BASE,
            bytes: &good,
        },
    ];
    assert_eq!(encoded_len(&unordered), Err(SnapshotError::ImageOrder));
    let overlapping = [
        SnapshotImage {
            base: BASE,
            bytes: &good,
        },
        SnapshotImage {
            base: BASE + 0x1000,
            bytes: &good,
        },
    ];
    assert_eq!(encoded_len(&overlapping), Err(SnapshotError::ImageOverlap));
    let one = [SnapshotImage {
        base: BASE,
        bytes: &good,
    }];
    let mut too_small = vec![0; encoded_len(&one).unwrap() - 1];
    assert_eq!(
        encode(&one, &mut too_small),
        Err(SnapshotError::InsufficientSpace)
    );
}

#[test]
fn parser_rejects_wrong_version_extent_slack_and_capacity() {
    let first = mapped_pe();
    let second = mapped_pe();
    let encoded = encode_two(&first, &second);
    assert!(matches!(
        SealedExceptionCatalog::parse(&encoded, &mut [None]),
        Err(SnapshotError::InsufficientImageSlots)
    ));
    let mut altered = encoded.clone();
    altered[0] ^= 1;
    assert_eq!(parse_error(&altered), SnapshotError::InvalidHeader);
    let mut altered = encoded.clone();
    put16(&mut altered, 8, 2);
    assert_eq!(parse_error(&altered), SnapshotError::UnsupportedVersion);
    let mut altered = encoded.clone();
    put16(&mut altered, 10, 25);
    assert_eq!(parse_error(&altered), SnapshotError::InvalidHeader);
    let mut altered = encoded.clone();
    altered.push(0);
    assert_eq!(parse_error(&altered), SnapshotError::InvalidHeader);
    assert_eq!(
        parse_error(&encoded[..encoded.len() - 1]),
        SnapshotError::InvalidHeader
    );
}

#[test]
fn parser_rejects_descriptor_gaps_overlap_and_bad_embedded_pe() {
    let first = mapped_pe();
    let second = mapped_pe();
    let encoded = encode_two(&first, &second);
    for (field, value) in [
        (
            HEADER_SIZE + 8,
            (HEADER_SIZE + 2 * DESCRIPTOR_SIZE + 1) as u64,
        ),
        (HEADER_SIZE + 16, (first.len() - 1) as u64),
        (
            HEADER_SIZE + DESCRIPTOR_SIZE + 8,
            (HEADER_SIZE + 2 * DESCRIPTOR_SIZE) as u64,
        ),
        (HEADER_SIZE + DESCRIPTOR_SIZE + 16, u64::MAX),
    ] {
        let mut altered = encoded.clone();
        put_u64(&mut altered, field, value);
        let _ = parse_error(&altered);
    }
    let mut altered = encoded.clone();
    put_u64(&mut altered, HEADER_SIZE + DESCRIPTOR_SIZE, BASE + 0x1000);
    assert_eq!(parse_error(&altered), SnapshotError::ImageOverlap);
    let mut altered = encoded.clone();
    put_u64(&mut altered, HEADER_SIZE + DESCRIPTOR_SIZE, BASE);
    assert_eq!(parse_error(&altered), SnapshotError::ImageOrder);
    let mut altered = encoded.clone();
    altered[HEADER_SIZE + 2 * DESCRIPTOR_SIZE] = 0;
    assert!(matches!(
        parse_error(&altered),
        SnapshotError::ImageAdmission(_)
    ));
}

#[test]
fn descriptor_mutations_never_create_an_unvalidated_catalog() {
    let image = mapped_pe();
    let input = [SnapshotImage {
        base: BASE,
        bytes: &image,
    }];
    let mut encoded = vec![0; encoded_len(&input).unwrap()];
    encode(&input, &mut encoded).unwrap();
    for byte in 0..HEADER_SIZE + DESCRIPTOR_SIZE {
        for bit in 0..8 {
            let mut altered = encoded.clone();
            altered[byte] ^= 1 << bit;
            let mut slots = [None];
            if let Ok(catalog) = SealedExceptionCatalog::parse(&altered, &mut slots) {
                // Some mutations may remain valid (for example a different disjoint load base),
                // but every successful parse must still admit a real executable image.
                assert_eq!(catalog.image_count(), 1);
                assert!(catalog.images[0].is_some());
            }
        }
    }
}
