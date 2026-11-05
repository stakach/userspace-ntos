use nt_address_space::copy::{CopyResult, VmCopyContinuation, STATUS_PARTIAL_COPY};

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Source {
    section_generation: u64,
    view_generation: u64,
    lease_generation: u64,
}

#[test]
fn foreign_copy_retains_reply_progress_and_exact_pending_page_owner() {
    let caller = Caller {
        process_generation: 3,
        thread_generation: 7,
        reply: 11,
    };
    let stale_caller = Caller {
        thread_generation: 6,
        ..caller
    };
    let target = Target {
        process_generation: 13,
        address_space_generation: 17,
    };
    let stale_target = Target {
        address_space_generation: 16,
        ..target
    };
    let section = Source {
        section_generation: 19,
        view_generation: 23,
        lease_generation: 29,
    };
    let stale_section = Source {
        lease_generation: 28,
        ..section
    };
    let count_pointer = 0x8ff8;
    let mut copy = VmCopyContinuation::<Caller, Target, Source, u64>::new(
        caller,
        target,
        0x1ff0,
        0x4ff0,
        0x30,
        count_pointer,
    );

    // The first page is already resident. The copy must retain its exact prefix before
    // page-in of the second page, including the caller's output and original Reply.
    assert_eq!(copy.next_offset(caller, target), Some(0));
    assert!(copy.stage_source(caller, target, 0, &[0xa5; 0x10]));
    assert!(copy.enter_probe_page(caller, target, 0x4ff0));
    assert!(copy.probe_page_completed(caller, target, 0x4ff0));
    assert!(copy.enter_probe_page(caller, target, 0x5000));
    assert!(copy.probe_page_completed(caller, target, 0x5000));
    assert!(copy.commit_copied(caller, target, 0, 0x10));
    assert_eq!(copy.next_offset(caller, target), Some(0x10));
    assert!(!copy.commit_copied(caller, target, 0, 0x10));
    assert!(copy.begin_pending(caller, target, 0x10, section, 31));
    assert_eq!(copy.next_offset(caller, target), None);
    assert!(!copy.begin_pending(caller, target, 0x10, section, 31),
        "an entered provider read must never be replayed");
    assert!(!copy.acknowledge_pending(stale_caller, target, 0x10, section, 31));
    assert!(!copy.acknowledge_pending(caller, stale_target, 0x10, section, 31));
    assert!(!copy.acknowledge_pending(caller, target, 0x10, stale_section, 31));
    assert!(!copy.acknowledge_pending(caller, target, 0x10, section, 32));
    assert!(!copy.resume_pending(caller, target, 0x10, section, 31),
        "provider Pending is not a terminal completion");
    assert!(copy.acknowledge_pending(caller, target, 0x10, section, 31));
    assert!(!copy.acknowledge_pending(caller, target, 0x10, section, 31));
    assert!(copy.resume_pending(caller, target, 0x10, section, 31));
    assert_eq!(copy.next_offset(caller, target), Some(0x10));
    assert!(copy.stage_source(caller, target, 0x10, &[0x5a; 0x20]));
    assert!(copy.commit_copied(caller, target, 0x10, 0x20));
    assert!(copy.finish(caller, target, 0));
    assert_eq!(copy.output_to_publish(caller, target), Some((count_pointer, 0x30)));
    assert!(copy.enter_reply(caller, target).is_none(),
        "the count output must be published before replying");
    assert!(copy.enter_output(caller, target));
    assert!(!copy.enter_output(caller, target),
        "an uncertain count write must not be replayed");
    assert!(copy.output_published(caller, target));
    assert_eq!(copy.enter_reply(caller, target), Some((caller, CopyResult {
        status: 0,
        transferred: 0x30,
    })));
    assert_eq!(copy.enter_reply(caller, target), None,
        "an uncertain Reply send must not be repeated");
}

#[test]
fn terminal_page_error_publishes_only_completed_prefix_once() {
    let caller = Caller { process_generation: 1, thread_generation: 2, reply: 3 };
    let target = Target { process_generation: 4, address_space_generation: 5 };
    let section = Source { section_generation: 6, view_generation: 7, lease_generation: 8 };
    let mut copy = VmCopyContinuation::<Caller, Target, Source, u64>::new(
        caller, target, 0x1ff0, 0x4ff0, 0x30, 0x8ff8,
    );
    assert!(copy.stage_source(caller, target, 0, &[0xa5; 0x10]));
    assert!(copy.enter_probe_page(caller, target, 0x4ff0));
    assert!(copy.probe_page_completed(caller, target, 0x4ff0));
    assert!(copy.enter_probe_page(caller, target, 0x5000));
    assert!(copy.probe_page_completed(caller, target, 0x5000));
    assert!(copy.commit_copied(caller, target, 0, 0x10));
    assert!(copy.begin_pending(caller, target, 0x10, section, 9));
    assert!(copy.acknowledge_pending(caller, target, 0x10, section, 9));
    assert!(copy.fail_pending(caller, target, 0x10, section, 9, STATUS_PARTIAL_COPY));
    assert_eq!(copy.output_to_publish(caller, target), Some((0x8ff8, 0x10)));
    assert!(copy.enter_output(caller, target));
    assert!(copy.output_published(caller, target));
    assert_eq!(copy.enter_reply(caller, target), Some((caller, CopyResult {
        status: STATUS_PARTIAL_COPY,
        transferred: 0x10,
    })));
    assert!(!copy.fail_pending(caller, target, 0x10, section, 9, STATUS_PARTIAL_COPY));
}

#[test]
fn inline_copy_error_retains_completed_prefix_without_replaying_probe() {
    let caller = Caller { process_generation: 1, thread_generation: 2, reply: 3 };
    let target = Target { process_generation: 4, address_space_generation: 5 };
    let mut copy = VmCopyContinuation::<Caller, Target, Source, u64>::new(
        caller, target, 0x1ff0, 0x4ff0, 0x30, 0x8ff8,
    );
    assert!(copy.stage_source(caller, target, 0, &[0xa5; 0x10]));
    assert!(copy.enter_probe_page(caller, target, 0x4ff0));
    assert!(!copy.fail(caller, target, STATUS_PARTIAL_COPY),
        "an entered probe has an uncertain self-write until completion");
    assert!(copy.probe_page_completed(caller, target, 0x4ff0));
    assert!(copy.enter_probe_page(caller, target, 0x5000));
    assert!(copy.probe_page_completed(caller, target, 0x5000));
    assert!(copy.commit_copied(caller, target, 0, 0x10));
    assert!(copy.fail(caller, target, STATUS_PARTIAL_COPY));
    assert!(!copy.fail(caller, target, STATUS_PARTIAL_COPY));
    assert_eq!(copy.output_to_publish(caller, target), Some((0x8ff8, 0x10)));
}
