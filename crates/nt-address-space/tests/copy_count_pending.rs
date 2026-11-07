use nt_address_space::copy::VmCopyCountProbe;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Caller {
    process_generation: u64,
    thread_generation: u64,
    reply: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Source {
    section_generation: u64,
    lease_generation: u64,
}

#[test]
fn split_count_probe_retains_capture_across_pending_before_one_shot_self_write() {
    let caller = Caller { process_generation: 3, thread_generation: 5, reply: 7 };
    let stale_caller = Caller { thread_generation: 4, ..caller };
    let source = Source { section_generation: 11, lease_generation: 13 };
    let stale_source = Source { lease_generation: 12, ..source };
    let mut probe = VmCopyCountProbe::<Caller, Source, u64>::new(caller, 0x1ffc);

    assert_eq!(probe.next_capture(caller), Some((0x1ffc, 4)));
    assert!(probe.capture_bytes(caller, 0x1ffc, &[0x21, 0x43, 0x65, 0x87]));
    assert_eq!(probe.enter_write(caller), None,
        "the first page cannot be self-written before the second is captured");
    assert_eq!(probe.next_capture(caller), Some((0x2000, 4)));
    assert!(probe.begin_pending(caller, 0x2000, source, 17));
    assert_eq!(probe.next_capture(caller), None);
    assert_eq!(probe.enter_write(caller), None);
    assert!(!probe.capture_bytes(caller, 0x2000, &[0; 4]));
    assert!(!probe.acknowledge_pending(stale_caller, 0x2000, source, 17));
    assert!(!probe.acknowledge_pending(caller, 0x2000, stale_source, 17));
    assert!(!probe.acknowledge_pending(caller, 0x2000, source, 18));
    assert!(!probe.resume_pending(caller, 0x2000, source, 17));
    assert!(probe.acknowledge_pending(caller, 0x2000, source, 17));
    assert!(probe.resume_pending(caller, 0x2000, source, 17));
    assert_eq!(probe.next_capture(caller), Some((0x2000, 4)));
    assert!(probe.capture_bytes(caller, 0x2000, &[0x09, 0xab, 0xcd, 0xef]));
    assert_eq!(probe.next_capture(caller), None);

    // No probe write may enter before all eight original bytes have been captured.
    assert_eq!(probe.next_write(caller), Some((0x1ffc, 4)));
    assert_eq!(probe.enter_write(caller), Some((0x1ffc, &[0x21, 0x43, 0x65, 0x87][..])));
    assert_eq!(probe.enter_write(caller), None,
        "an uncertain self-write must never be entered twice");
    assert!(!probe.write_completed(stale_caller, 0x1ffc));
    assert!(probe.write_completed(caller, 0x1ffc));
    assert!(!probe.write_completed(caller, 0x1ffc));
    assert_eq!(probe.next_write(caller), Some((0x2000, 4)));
    assert_eq!(probe.enter_write(caller), Some((0x2000, &[0x09, 0xab, 0xcd, 0xef][..])));
    assert_eq!(probe.enter_write(caller), None);
    assert!(probe.write_completed(caller, 0x2000));
    assert!(probe.published(caller));
    assert!(!probe.published(stale_caller));
}

#[test]
fn failed_count_pagein_keeps_exact_terminal_error_and_never_writes() {
    let caller = Caller { process_generation: 3, thread_generation: 5, reply: 7 };
    let source = Source { section_generation: 11, lease_generation: 13 };
    let mut probe = VmCopyCountProbe::<Caller, Source, u64>::new(caller, 0x1ffc);
    assert!(probe.capture_bytes(caller, 0x1ffc, &[1, 2, 3, 4]));
    assert!(probe.begin_pending(caller, 0x2000, source, 17));
    assert!(!probe.fail_pending(caller, 0x2000, source, 17, 0xc000_0005));
    assert!(probe.acknowledge_pending(caller, 0x2000, source, 17));
    assert!(probe.fail_pending(caller, 0x2000, source, 17, 0xc000_0005));
    assert_eq!(probe.failure(caller), Some(0xc000_0005));
    assert_eq!(probe.enter_write(caller), None);
    assert_eq!(probe.next_capture(caller), None);
}

#[test]
fn inline_count_capture_error_is_terminal_before_any_self_write() {
    let caller = Caller { process_generation: 3, thread_generation: 5, reply: 7 };
    let mut probe = VmCopyCountProbe::<Caller, Source, u64>::new(caller, 0x1ffc);
    assert!(probe.capture_bytes(caller, 0x1ffc, &[1, 2, 3, 4]));
    assert!(probe.fail(caller, 0xc000_0005));
    assert!(!probe.fail(caller, 0xc000_0005));
    assert_eq!(probe.next_capture(caller), None);
    assert_eq!(probe.enter_write(caller), None);
    assert_eq!(probe.failure(caller), Some(0xc000_0005));
}

#[test]
fn definitive_second_count_probe_write_failure_preserves_first_page_once() {
    let caller = Caller { process_generation: 3, thread_generation: 5, reply: 7 };
    let mut probe = VmCopyCountProbe::<Caller, Source, u64>::new(caller, 0x1ffc);
    assert!(probe.capture_bytes(caller, 0x1ffc, &[1, 2, 3, 4]));
    assert!(probe.capture_bytes(caller, 0x2000, &[5, 6, 7, 8]));
    assert_eq!(probe.next_write(caller), Some((0x1ffc, 4)));
    assert!(probe.enter_write(caller).is_some());
    assert!(!probe.fail_before_write(caller, 0xc000_0005));
    assert!(probe.write_completed(caller, 0x1ffc));
    assert_eq!(probe.next_write(caller), Some((0x2000, 4)));
    assert!(probe.fail_before_write(caller, 0xc000_0005));
    assert_eq!(probe.next_write(caller), None);
    assert_eq!(probe.failure(caller), Some(0xc000_0005));
    assert!(!probe.published(caller));
}
