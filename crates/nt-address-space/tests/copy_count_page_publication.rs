use nt_address_space::copy::{CopyResult, VmCopyContinuation};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Caller {
    process_generation: u64,
    thread_generation: u64,
    reply: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Target {
    process_generation: u64,
    address_space_generation: u64,
}

#[test]
fn count_output_crosses_page_once_before_original_reply() {
    let caller = Caller { process_generation: 3, thread_generation: 5, reply: 7 };
    let stale_caller = Caller { thread_generation: 4, ..caller };
    let target = Target { process_generation: 11, address_space_generation: 13 };
    let stale_target = Target { address_space_generation: 12, ..target };
    let mut copy = VmCopyContinuation::<Caller, Target, u64, u64>::new(
        caller, target, 0x4000, 0x6000, 0x123, 0x1ffd,
    );

    // Complete the copy with the same 256-byte chunks as the native copy loop.
    assert!(copy.stage_source(caller, target, 0, &[0xa5; 256]));
    assert!(copy.enter_probe_page(caller, target, 0x6000));
    assert!(copy.probe_page_completed(caller, target, 0x6000));
    assert!(copy.enter_copy_write(caller, target, 0));
    assert!(copy.commit_copied(caller, target, 0, 256));
    assert!(copy.stage_source(caller, target, 256, &[0x5a; 0x23]));
    assert!(copy.enter_copy_write(caller, target, 256));
    assert!(copy.commit_copied(caller, target, 256, 0x23));
    assert!(copy.finish(caller, target, 0));

    let count_bytes = 0x123u64.to_le_bytes();
    assert_eq!(copy.next_output_chunk(stale_caller, target), None);
    assert_eq!(copy.next_output_chunk(caller, stale_target), None);
    assert_eq!(copy.next_output_chunk(caller, target), Some((0x1ffd, &count_bytes[..3])));
    assert!(!copy.output_page_completed(caller, target, 0x1ffd));
    assert!(!copy.enter_output_page(stale_caller, target, 0x1ffd));
    assert!(!copy.enter_output_page(caller, stale_target, 0x1ffd));
    assert!(!copy.enter_output_page(caller, target, 0x2000));
    assert!(copy.enter_output_page(caller, target, 0x1ffd));
    assert!(!copy.enter_output_page(caller, target, 0x1ffd),
        "an uncertain first-page write must not be replayed");
    assert_eq!(copy.next_output_chunk(caller, target), None,
        "an entered write cannot be submitted again before confirmation");
    assert!(!copy.output_page_completed(stale_caller, target, 0x1ffd));
    assert!(copy.output_page_completed(caller, target, 0x1ffd));
    assert!(!copy.output_published(caller, target),
        "the second page still owns the remaining SIZE_T bytes");

    assert_eq!(copy.next_output_chunk(caller, target), Some((0x2000, &count_bytes[3..])));
    assert!(copy.enter_output_page(caller, target, 0x2000));
    assert!(!copy.enter_output_page(caller, target, 0x2000));
    assert!(!copy.enter_reply(caller, target).is_some());
    assert!(copy.output_page_completed(caller, target, 0x2000));
    assert!(copy.output_published(caller, target));
    assert_eq!(copy.enter_reply(caller, target), Some((caller, CopyResult {
        status: 0,
        transferred: 0x123,
    })));
    assert_eq!(copy.enter_reply(caller, target), None);
}

#[test]
fn null_count_pointer_has_no_write_and_still_replies_once() {
    let caller = Caller { process_generation: 1, thread_generation: 2, reply: 3 };
    let target = Target { process_generation: 4, address_space_generation: 5 };
    let mut copy = VmCopyContinuation::<Caller, Target, u64, u64>::new(
        caller, target, 0x4000, 0x6000, 0, 0,
    );
    assert!(copy.finish(caller, target, 0));
    assert_eq!(copy.next_output_chunk(caller, target), None);
    assert!(!copy.enter_output_page(caller, target, 0));
    assert!(!copy.skip_null_output(Caller { reply: 9, ..caller }, target));
    assert!(copy.skip_null_output(caller, target));
    assert!(!copy.skip_null_output(caller, target));
    assert_eq!(copy.enter_reply(caller, target), Some((caller, CopyResult {
        status: 0,
        transferred: 0,
    })));
    assert_eq!(copy.enter_reply(caller, target), None);
}

#[test]
fn definitive_second_count_page_failure_keeps_original_copy_result() {
    let caller = Caller { process_generation: 1, thread_generation: 2, reply: 3 };
    let target = Target { process_generation: 4, address_space_generation: 5 };
    let mut copy = VmCopyContinuation::<Caller, Target, u64, u64>::new(
        caller, target, 0x4000, 0x6000, 0, 0x1ffd,
    );
    assert!(copy.finish(caller, target, 0));
    assert!(copy.enter_output_page(caller, target, 0x1ffd));
    assert!(!copy.output_failed(caller, target),
        "an entered count write cannot be treated as a proven no-write failure");
    assert!(copy.output_page_completed(caller, target, 0x1ffd));
    assert!(copy.output_failed(caller, target));
    assert!(!copy.output_failed(caller, target));
    assert_eq!(copy.enter_reply(caller, target), Some((caller, CopyResult {
        status: 0,
        transferred: 0,
    })));
}
