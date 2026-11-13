use super::*;
use alloc::string::String;
use alloc::vec;

#[test]
fn pending_windows_require_exact_copy_and_ack_before_advancing() {
    let mut read = RoutedImageRead::<_, u64, _>::new((17, 29), 10, 6, String::from("file owner"))
        .unwrap();
    assert_eq!(read.source(), (17, 29));
    assert_eq!(read.enter_window(), Some(ImageReadWindow { offset: 0, length: 6 }));
    assert_eq!(read.enter_window(), None);
    assert!(read.bind_pending(41));
    assert_eq!(read.pending_key(), Some(41));
    assert!(!read.terminal(42, 0, 6));
    assert!(!read.terminal(41, STATUS_PENDING, 6));
    assert!(read.terminal(41, 0, 6));
    assert_eq!(read.copy_position(), Some((41, 0, 6)));
    assert!(!read.copy_fragment(41, 1, b"abc"));
    assert!(read.copy_fragment(41, 0, b"abc"));
    assert_eq!(read.copy_position(), Some((41, 3, 3)));
    assert!(read.copy_fragment(41, 3, b"def"));
    assert_eq!(read.acknowledgment_key(), Some(41));
    assert_eq!(read.enter_window(), None);
    assert!(!read.acknowledge(42));
    assert!(read.acknowledge(41));
    assert_eq!(read.enter_window(), Some(ImageReadWindow { offset: 6, length: 4 }));
    assert!(read.complete_inline(0, 4, b"ghij"));
    let (owner, result) = read.into_terminal().ok().unwrap();
    assert_eq!(owner, "file owner");
    assert_eq!(result.unwrap(), b"abcdefghij");
}

#[test]
fn process_sized_snapshot_advances_only_after_each_pending_window_ack() {
    const EXTENT: usize = 197_632;
    let mut read = RoutedImageRead::<_, u64, _>::new(
        (17, 29), EXTENT as u64, MAX_IMAGE_READ_WINDOW,
        String::from("exact Section and File owner"),
    ).unwrap();
    let mut offset = 0;
    let mut key = 100;
    while offset < EXTENT {
        let window = read.enter_window().unwrap();
        assert_eq!(window.offset, offset as u64);
        assert_eq!(window.length, (EXTENT - offset).min(MAX_IMAGE_READ_WINDOW));
        assert!(read.bind_pending(key));
        assert!(read.terminal(key, 0, window.length as u64));
        let bytes = vec![(key & 0xff) as u8; window.length];
        assert!(read.copy_fragment(key, 0, &bytes));
        assert_eq!(read.acknowledgment_key(), Some(key));
        assert!(read.enter_window().is_none(), "next window waits for provider ACK");
        read = read.into_terminal().err().expect("source owner cannot publish before ACK");
        assert!(!read.acknowledge(key + 1), "wrong IRP cannot release the captured source");
        assert!(read.acknowledge(key));
        offset += window.length;
        key += 1;
    }
    assert_eq!(key, 107, "197632 bytes require seven bounded reads");
    let (owner, bytes) = read.into_terminal().ok().unwrap();
    assert_eq!(owner, "exact Section and File owner");
    let bytes = bytes.unwrap();
    assert_eq!(bytes.len(), EXTENT);
    assert_eq!(&bytes[..MAX_IMAGE_READ_WINDOW], &[100u8; MAX_IMAGE_READ_WINDOW]);
    assert_eq!(&bytes[6 * MAX_IMAGE_READ_WINDOW..], &[106u8; 1024]);
}

#[test]
fn short_pending_success_is_terminal_only_after_ack() {
    let mut read = RoutedImageRead::<_, u64, _>::new(17, 4, 4, 99u32).unwrap();
    assert_eq!(read.enter_window(), Some(ImageReadWindow { offset: 0, length: 4 }));
    assert!(read.bind_pending(7));
    assert!(read.terminal(7, 0, 3));
    assert_eq!(read.terminal_result(), None);
    assert_eq!(read.enter_window(), None);
    assert!(read.acknowledge(7));
    let (owner, result) = read.into_terminal().ok().unwrap();
    assert_eq!(owner, 99);
    assert_eq!(result, Err(STATUS_IO_DEVICE_ERROR));
}

#[test]
fn failed_copy_preserves_backend_ack_barrier() {
    let mut read = RoutedImageRead::<_, u64, _>::new(17, 4, 4, ()).unwrap();
    read.enter_window().unwrap();
    assert!(read.bind_pending(7));
    assert!(read.terminal(7, 0, 4));
    assert!(read.copy_fragment(7, 0, b"ab"));
    assert!(read.fail_copy(7, 0xc000_0185));
    assert_eq!(read.terminal_result(), None);
    assert!(read.acknowledge(7));
    assert_eq!(read.into_terminal().ok().unwrap().1, Err(0xc000_0185));
}

#[test]
fn uncertain_dispatch_cannot_be_replayed_or_published() {
    let mut read = RoutedImageRead::<_, u64, _>::new(17, 4, 4, ()).unwrap();
    read.enter_window().unwrap();
    read.quarantine();
    assert_eq!(read.enter_window(), None);
    assert!(!read.bind_pending(7));
    assert_eq!(read.terminal_result(), None);
    assert!(read.into_terminal().is_err());
}

#[test]
fn invalid_window_does_not_consume_captured_owner() {
    assert_eq!(RoutedImageRead::<_, u64, _>::new(17, 4, 0, 99u32).err(), Some(99));
    assert_eq!(
        RoutedImageRead::<_, u64, _>::new(17, 4, MAX_IMAGE_READ_WINDOW + 1, 99u32).err(),
        Some(99)
    );
    assert_eq!(
        RoutedImageRead::<_, u64, _>::new_at(17, u64::MAX - 1, 4, 4, 99u32).err(),
        Some(99)
    );
}

#[test]
fn page_source_window_keeps_absolute_file_offset() {
    let mut read = RoutedImageRead::<_, u64, _>::new_at(17, 0x31_000, 4, 4, ()).unwrap();
    assert_eq!(read.enter_window(), Some(ImageReadWindow { offset: 0x31_000, length: 4 }));
    assert!(read.complete_inline(0, 4, b"page"));
    assert_eq!(read.into_terminal().ok().unwrap().1.unwrap(), b"page");
}

#[test]
fn unused_capture_can_be_retired_but_entered_dispatch_cannot() {
    let read = RoutedImageRead::<_, u64, _>::new(17, 4, 4, 99u32).unwrap();
    assert_eq!(read.abort_ready().ok(), Some(99));
    let mut entered = RoutedImageRead::<_, u64, _>::new(17, 4, 4, 88u32).unwrap();
    entered.enter_window().unwrap();
    assert!(entered.abort_ready().is_err());
}

#[test]
fn syscall_output_page_waits_for_exact_provider_ack_before_writing_or_replying() {
    let mut output_page = [0xa5; 4];
    let mut replied = false;
    let mut read = RoutedImageRead::<_, u64, _>::new_at(
        (17, 29), 0x31_000, 4, 4, String::from("captured File and Section"),
    )
    .unwrap();
    assert_eq!(read.enter_window(), Some(ImageReadWindow { offset: 0x31_000, length: 4 }));
    assert!(read.bind_pending(41));
    assert!(read.terminal(41, 0, 4));
    assert!(read.copy_fragment(41, 0, b"data"));
    // Completing the provider IRP is not an acknowledgement and must not release the
    // source capture or permit the syscall output page to be written.
    assert_eq!(read.acknowledgment_key(), Some(41));
    assert_eq!(read.terminal_result(), None);
    assert_eq!(output_page, [0xa5; 4]);
    assert!(!replied);
    read = read.into_terminal().err().unwrap();
    assert!(!read.acknowledge(42));
    assert_eq!(read.owner(), "captured File and Section");
    assert_eq!(output_page, [0xa5; 4]);
    assert!(!replied);

    assert!(read.acknowledge(41));
    let (owner, bytes) = read.into_terminal().ok().unwrap();
    assert_eq!(owner, "captured File and Section");
    output_page.copy_from_slice(&bytes.unwrap());
    replied = true;
    assert_eq!(&output_page, b"data");
    assert!(replied);
}
