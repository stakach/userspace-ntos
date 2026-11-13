use nt_compat_exports::crt::{compare_wide_z, rfind_wide_z, sort_opaque_elements};
use std::cmp::Ordering;

#[test]
fn wide_compare_requires_terminators_and_stops_before_trailing_storage() {
    assert_eq!(compare_wide_z(&[b'A' as u16, 0, 9], &[b'A' as u16, 0, 8]), Some(Ordering::Equal));
    assert_eq!(compare_wide_z(&[b'A' as u16, 0], &[b'B' as u16, 0]), Some(Ordering::Less));
    assert_eq!(compare_wide_z(&[b'B' as u16, 0], &[b'A' as u16, 0]), Some(Ordering::Greater));
    assert_eq!(compare_wide_z(&[b'A' as u16], &[b'A' as u16, 0]), None);
}

#[test]
fn wide_reverse_find_includes_terminator_only_when_requested() {
    let text = [b'A' as u16, b'B' as u16, b'A' as u16, 0, b'A' as u16];
    assert_eq!(rfind_wide_z(&text, b'A' as u16), Some(2));
    assert_eq!(rfind_wide_z(&text, 0), Some(3));
    assert_eq!(rfind_wide_z(&text, b'C' as u16), None);
    assert_eq!(rfind_wide_z(&text[..3], b'A' as u16), None);
}

#[test]
fn opaque_sort_orders_whole_records_without_touching_adjacent_bytes() {
    let mut storage = [0xA5, 3, 30, 31, 1, 10, 11, 2, 20, 21, 0x5A];
    assert!(sort_opaque_elements(&mut storage[1..10], 3, |a, b| a[0].cmp(&b[0])));
    assert_eq!(storage, [0xA5, 1, 10, 11, 2, 20, 21, 3, 30, 31, 0x5A]);
}

#[test]
fn opaque_sort_rejects_invalid_geometry_before_mutation() {
    let mut bytes = [3, 2, 1, 0xEE];
    assert!(!sort_opaque_elements(&mut bytes, 0, |_, _| Ordering::Equal));
    assert!(!sort_opaque_elements(&mut bytes, 3, |_, _| Ordering::Equal));
    assert_eq!(bytes, [3, 2, 1, 0xEE]);
    assert!(sort_opaque_elements(&mut bytes[..0], 1, |_, _| Ordering::Equal));
}
