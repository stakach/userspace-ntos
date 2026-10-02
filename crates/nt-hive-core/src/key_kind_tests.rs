use crate::*;
use nt_config_store::codec::crc32c;

fn checksums(image: &mut [u8]) {
    let payload = crc32c(&image[68..]);
    image[60..64].copy_from_slice(&payload.to_le_bytes());
    let header = crc32c(&image[..64]);
    image[64..68].copy_from_slice(&header.to_le_bytes());
}

#[test]
fn key_kind_survives_image_subtree_and_additive_overlay() {
    let mut hive = Hive::new(HiveKind::System);
    let ordinary = hive.create_key("Ordinary");
    let link = hive.create_key("Link");
    assert_eq!(hive.key_kind(ordinary), Some(KeyKind::Ordinary));
    assert!(hive.set_key_kind(link, KeyKind::SymbolicLink));
    let image = encode_image(&hive);
    assert_eq!(u16::from_le_bytes(image[10..12].try_into().unwrap()), 3);
    let restored = decode_image(&image).unwrap();
    assert_eq!(restored.key_kind(restored.open_key("Link").unwrap()), Some(KeyKind::SymbolicLink));
    assert_eq!(restored.key_kind(restored.open_key("Ordinary").unwrap()), Some(KeyKind::Ordinary));
    let subtree = decode_image(&try_encode_subtree_image(&hive, link).unwrap()).unwrap();
    assert_eq!(subtree.key_kind(subtree.root()), Some(KeyKind::SymbolicLink));
    let composed = compose_hive_overlay(&Hive::new(HiveKind::System), &hive).unwrap();
    assert_eq!(composed.key_kind(composed.open_key("Link").unwrap()), Some(KeyKind::SymbolicLink));
    let mut overlay = Hive::new(HiveKind::System);
    overlay.create_key("Link");
    assert_eq!(compose_hive_overlay(&hive, &overlay).unwrap().key_kind(link), Some(KeyKind::SymbolicLink));
}

#[test]
fn overlay_cannot_change_existing_ordinary_key_into_link() {
    let mut base = Hive::new(HiveKind::System);
    base.create_key("Same");
    let mut overlay = Hive::new(HiveKind::System);
    let link = overlay.create_key("Same");
    overlay.set_key_kind(link, KeyKind::SymbolicLink);
    assert!(matches!(compose_hive_overlay(&base, &overlay), Err(HiveOverlayError::InvalidSource)));
}

#[test]
fn schema_two_zero_flags_are_ordinary_and_nonzero_flags_fail_closed() {
    let hive = Hive::new(HiveKind::System);
    let mut image = encode_image(&hive);
    image[10..12].copy_from_slice(&2u16.to_le_bytes());
    checksums(&mut image);
    let restored = decode_image(&image).unwrap();
    assert_eq!(restored.key_kind(restored.root()), Some(KeyKind::Ordinary));
    let mut legacy_one = image.clone();
    legacy_one[10..12].copy_from_slice(&1u16.to_le_bytes());
    // Schema one predates the security-descriptor presence byte.
    legacy_one.remove(68 + 2 + 8 + 8 + 4 + 4 + 1);
    let payload_len = (legacy_one.len() - 68) as u64;
    legacy_one[52..60].copy_from_slice(&payload_len.to_le_bytes());
    checksums(&mut legacy_one);
    let restored = decode_image(&legacy_one).unwrap();
    assert_eq!(restored.key_kind(restored.root()), Some(KeyKind::Ordinary));
    // First root record has an empty name: type/id/parent/name length, then key flags.
    let flags = 68 + 2 + 8 + 8 + 4;
    image[flags..flags + 4].copy_from_slice(&1u32.to_le_bytes());
    checksums(&mut image);
    assert!(matches!(decode_image(&image), Err(HiveDecodeError::UnsupportedSchema)));
    assert!(matches!(image_root_subkey_count_if_valid(&image), Err(HiveDecodeError::UnsupportedSchema)));
    image[10..12].copy_from_slice(&3u16.to_le_bytes());
    image[flags..flags + 4].copy_from_slice(&2u32.to_le_bytes());
    checksums(&mut image);
    assert!(matches!(decode_image(&image), Err(HiveDecodeError::UnsupportedSchema)));
}
