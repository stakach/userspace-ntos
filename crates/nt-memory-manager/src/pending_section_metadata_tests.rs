use super::*;
use crate::SectionMountIds;
use alloc::string::String;

fn mount() -> SectionMountId {
    SectionMountIds::new().allocate().unwrap()
}

fn standard() -> [u8; 24] {
    let mut bytes = [0; 24];
    bytes[8..16].copy_from_slice(&4096i64.to_le_bytes());
    bytes
}

fn internal() -> [u8; 8] {
    77u64.to_le_bytes()
}

fn query(bytes: &[u8]) -> CompletedFileQuery<'_> {
    CompletedFileQuery {
        status: 0,
        information: bytes.len() as u64,
        output: bytes,
    }
}

#[test]
fn inline_queries_retire_without_fabricated_irp_keys() {
    let mut pending = PendingSectionMetadataQueries::<String, u64>::new();
    let id = pending.reserve(mount(), String::from("capture")).unwrap();
    assert_eq!(
        pending.next_query(id),
        Some(FILE_STANDARD_INFORMATION_CLASS)
    );
    assert!(pending.complete_inline(id, query(&standard())));
    assert_eq!(
        pending.next_query(id),
        Some(FILE_INTERNAL_INFORMATION_CLASS)
    );
    assert!(pending.complete_inline(id, query(&internal())));
    let (owner, result) = pending.take_terminal(id).unwrap();
    assert_eq!(owner, "capture");
    assert_eq!(result.unwrap().end_of_file, 4096);
    assert!(pending.take_terminal(id).is_none());
}

#[test]
fn pending_queries_copy_exact_prefix_before_each_backend_ack() {
    let mut pending = PendingSectionMetadataQueries::<String, u64>::new();
    let id = pending
        .reserve(mount(), String::from("file reference"))
        .unwrap();
    assert!(pending.bind_pending(id, 41));
    assert!(!pending.terminal(id, 42, 0, 24));
    assert!(!pending.terminal(id, 41, STATUS_PENDING, 24));
    assert!(pending.terminal(id, 41, 0, 24));
    let bytes = standard();
    assert!(!pending.append(id, 42, 0, &bytes[..8]));
    assert!(pending.append(id, 41, 0, &bytes[..8]));
    assert!(!pending.append(id, 41, 0, &bytes[8..]));
    assert!(!pending.acknowledge_backend(id, 41));
    assert_eq!(pending.next_query(id), None);
    assert!(pending.append(id, 41, 8, &bytes[8..]));
    assert!(pending.acknowledge_backend(id, 41));
    assert_eq!(
        pending.next_query(id),
        Some(FILE_INTERNAL_INFORMATION_CLASS)
    );
    assert!(pending.bind_pending(id, 42));
    assert!(pending.terminal(id, 42, 0, 8));
    assert!(pending.append(id, 42, 0, &internal()));
    assert!(pending.take_terminal(id).is_none());
    assert!(!pending.acknowledge_backend(id, 41));
    assert!(pending.acknowledge_backend(id, 42));
    let (owner, result) = pending.take_terminal(id).unwrap();
    assert_eq!(owner, "file reference");
    assert_eq!(result.unwrap().file.file_id, 77);
}

#[test]
fn short_or_failed_terminal_retains_capture_until_ack() {
    let mut pending = PendingSectionMetadataQueries::<String, u64>::new();
    let id = pending.reserve(mount(), String::from("short")).unwrap();
    assert!(pending.bind_pending(id, 7));
    assert!(pending.terminal(id, 7, 0, 23));
    assert!(pending.take_terminal(id).is_none());
    assert!(pending.acknowledge_backend(id, 7));
    let (owner, result) = pending.take_terminal(id).unwrap();
    assert_eq!(owner, "short");
    assert_eq!(result, Err(STATUS_IO_DEVICE_ERROR));

    let id = pending.reserve(mount(), String::from("failure")).unwrap();
    assert!(pending.bind_pending(id, 8));
    assert!(pending.terminal(id, 8, 0xc000_0185, 0));
    assert!(pending.acknowledge_backend(id, 8));
    let (owner, result) = pending.take_terminal(id).unwrap();
    assert_eq!(owner, "failure");
    assert_eq!(result, Err(0xc000_0185));
}

#[test]
fn stale_and_foreign_ids_cannot_advance_or_release_reused_slots() {
    let mut first = PendingSectionMetadataQueries::<String, u64>::new();
    let mut other = PendingSectionMetadataQueries::<String, u64>::new();
    let old = first.reserve(mount(), String::from("old")).unwrap();
    assert_eq!(first.cancel_reserved(old).unwrap(), "old");
    let current = first.reserve(mount(), String::from("current")).unwrap();
    assert_ne!(old, current);
    assert_eq!(first.next_query(old), None);
    assert!(!first.bind_pending(old, 9));
    assert_eq!(other.next_query(current), None);
    let foreign = other.reserve(mount(), String::from("foreign")).unwrap();
    assert!(!first.bind_pending(foreign, 9));
    assert!(first.bind_pending(current, 9));
    assert!(other.bind_pending(foreign, 9));
    assert_eq!(other.next_query(foreign), None);
    assert!(first.cancel_reserved(current).is_none());
}

#[test]
fn invalid_internal_identity_fails_only_after_exact_ack() {
    let mut pending = PendingSectionMetadataQueries::<String, u64>::new();
    let id = pending.reserve(mount(), String::from("zero id")).unwrap();
    assert!(pending.complete_inline(id, query(&standard())));
    assert!(pending.bind_pending(id, 50));
    assert!(pending.terminal(id, 50, 0, 8));
    assert!(pending.append(id, 50, 0, &[0; 8]));
    assert!(pending.take_terminal(id).is_none());
    assert!(pending.acknowledge_backend(id, 50));
    let (owner, result) = pending.take_terminal(id).unwrap();
    assert_eq!(owner, "zero id");
    assert_eq!(result, Err(0xc000_003e));
}

#[test]
fn negative_eof_stops_before_the_internal_query() {
    let mut pending = PendingSectionMetadataQueries::<String, u64>::new();
    let id = pending
        .reserve(mount(), String::from("negative EOF"))
        .unwrap();
    let mut bytes = standard();
    bytes[8..16].copy_from_slice(&(-1i64).to_le_bytes());
    assert!(pending.bind_pending(id, 61));
    assert!(pending.terminal(id, 61, 0, 24));
    assert!(pending.append(id, 61, 0, &bytes));
    assert!(pending.acknowledge_backend(id, 61));
    assert_eq!(pending.next_query(id), None);
    let (owner, result) = pending.take_terminal(id).unwrap();
    assert_eq!(owner, "negative EOF");
    assert_eq!(result, Err(0xc000_003e));
}

#[test]
fn one_active_irp_key_cannot_own_two_queries() {
    let mut pending = PendingSectionMetadataQueries::<String, u64>::new();
    let first = pending.reserve(mount(), String::from("first")).unwrap();
    let second = pending.reserve(mount(), String::from("second")).unwrap();
    assert!(pending.bind_pending(first, 91));
    assert!(!pending.bind_pending(second, 91));
    assert_eq!(
        pending.next_query(second),
        Some(FILE_STANDARD_INFORMATION_CLASS)
    );
    assert!(pending.terminal(first, 91, 0xc000_0185, 0));
    assert!(!pending.bind_pending(second, 91));
    assert!(pending.acknowledge_backend(first, 91));
    assert!(pending.bind_pending(second, 91));
}
