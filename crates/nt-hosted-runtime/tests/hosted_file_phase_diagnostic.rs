use nt_hosted_runtime::{FilePhaseIdentity, HostedFilePhaseDiagnostic, LocalFilePhaseMarks,
    NpfsDispatchMarks, NpfsCallbackDiagnostic, NpfsCallbackIdentity, NpfsMajor,
    NpfsPoolRetireMarks};

const FILE: u64 = (3u64 << 40) | 0x42;
const IRP_GEN_1: u64 = (1u64 << 40) | 0x17;
const IRP_GEN_2: u64 = (2u64 << 40) | 0x17;

fn identity(irp_id: u64) -> FilePhaseIdentity {
    FilePhaseIdentity { pid: 208, process_generation: 8, file_id: FILE, irp_id }
}

#[test]
fn local_phase_accounting_partitions_one_hosted_file_call_without_losing_time() {
    let mut diagnostic = HostedFilePhaseDiagnostic::<2>::new();
    let phases = diagnostic.record_call(identity(IRP_GEN_1), LocalFilePhaseMarks {
        entered: 10,
        captured: 13,
        acquired: 19,
        terminal: 55,
        dispatched: 48,
    }).expect("valid ordered phases");

    assert_eq!(phases.capture, 3);
    assert_eq!(phases.acquire, 6);
    assert_eq!(phases.dispatch, 29);
    assert_eq!(phases.tail, 7);
    assert_eq!(phases.total, 45);
    assert_eq!(phases.capture + phases.acquire + phases.dispatch + phases.tail, phases.total);
    assert_eq!(diagnostic.counts().calls, 1);
    assert!(diagnostic.record_call(identity(IRP_GEN_1), LocalFilePhaseMarks {
        entered: 10, captured: 13, acquired: 19, dispatched: 18, terminal: 55,
    }).is_none());
    assert_eq!(diagnostic.counts().invalid_phase_order, 1);
}

#[test]
fn independent_pump_and_handler_counters_do_not_claim_same_call_pairing() {
    let mut diagnostic = HostedFilePhaseDiagnostic::<1>::new();
    diagnostic.record_component_pump(21);
    diagnostic.record_npfs_handler(8);
    diagnostic.record_component_pump(13);
    let counts = diagnostic.counts();
    assert_eq!((counts.pump_calls, counts.pump_ticks), (2, 34));
    assert_eq!((counts.handler_calls, counts.handler_ticks), (1, 8));
    assert_eq!(counts.calls, 0);
}

#[test]
fn pending_completion_requires_exact_canonical_irp_generation() {
    let mut diagnostic = HostedFilePhaseDiagnostic::<1>::new();
    assert!(diagnostic.begin_pending_read(identity(IRP_GEN_1), 100));
    assert!(!diagnostic.begin_pending_read(identity(IRP_GEN_1), 101));
    assert_eq!(diagnostic.complete_pending_read(identity(IRP_GEN_2), 140), None);
    assert_eq!(diagnostic.complete_pending_read(FilePhaseIdentity {
        process_generation: 9, ..identity(IRP_GEN_1)
    }, 140), None);
    assert_eq!(diagnostic.complete_pending_read(identity(IRP_GEN_1), 150), Some(50));
    assert_eq!(diagnostic.complete_pending_read(identity(IRP_GEN_1), 160), None);
    assert!(diagnostic.begin_pending_read(identity(IRP_GEN_2), 170));
    assert_eq!(diagnostic.complete_pending_read(identity(IRP_GEN_2), 200), Some(30));
    let counts = diagnostic.counts();
    assert_eq!((counts.pending_completed, counts.pending_untracked, counts.pending_rejected), (2, 1, 3));
}

#[test]
fn full_pending_table_reports_lost_measurements() {
    let mut diagnostic = HostedFilePhaseDiagnostic::<1>::new();
    assert!(diagnostic.begin_pending_read(identity(IRP_GEN_1), 100));
    assert!(!diagnostic.begin_pending_read(identity(IRP_GEN_2), 101));
    assert_eq!(diagnostic.counts().pending_untracked, 1);
    assert_eq!(diagnostic.complete_pending_read(identity(IRP_GEN_1), 120), Some(20));
}

#[test]
fn npfs_dispatch_partitions_source_preparation_handler_and_terminal_work() {
    let mut diagnostic = HostedFilePhaseDiagnostic::<1>::new();
    let phases = diagnostic.record_npfs_dispatch(NpfsDispatchMarks {
        entered: 100, handler_entered: 108, handler_returned: 113, terminal: 121,
    }).expect("ordered NPFS dispatch");
    assert_eq!((phases.pre_handler, phases.handler, phases.post_handler, phases.total),
        (8, 5, 8, 21));
    assert_eq!(phases.pre_handler + phases.handler + phases.post_handler, phases.total);
    assert!(diagnostic.record_npfs_dispatch(NpfsDispatchMarks {
        entered: 100, handler_entered: 108, handler_returned: 107, terminal: 121,
    }).is_none());
    let counts = diagnostic.counts();
    assert_eq!((counts.npfs_calls, counts.npfs_pre_ticks, counts.npfs_handler_ticks,
        counts.npfs_post_ticks, counts.invalid_phase_order), (1, 8, 5, 8, 1));
}

#[test]
fn npfs_pool_retirement_partitions_ownership_check_and_service_without_wraparound() {
    let phases = NpfsPoolRetireMarks {
        entered: 100, ownership_checked: 108, retirement_returned: 127,
    }.durations().expect("ordered pool retirement");
    assert_eq!((phases.ownership_check, phases.retirement_service, phases.total), (8, 19, 27));
    assert_eq!(phases.ownership_check + phases.retirement_service, phases.total);
    assert!(NpfsPoolRetireMarks {
        entered: 100, ownership_checked: 99, retirement_returned: 127,
    }.durations().is_none());
    assert!(NpfsPoolRetireMarks {
        entered: 100, ownership_checked: 108, retirement_returned: 107,
    }.durations().is_none());
}

#[test]
fn pending_publication_to_guest_wake_requires_exact_generation_and_order() {
    let mut diagnostic = HostedFilePhaseDiagnostic::<1>::new();
    assert!(diagnostic.begin_pending_read(identity(IRP_GEN_1), 100));
    assert!(!diagnostic.mark_pending_publication(identity(IRP_GEN_2), 130));
    assert!(!diagnostic.mark_pending_publication(identity(IRP_GEN_1), 99));
    assert!(diagnostic.mark_pending_publication(identity(IRP_GEN_1), 130));
    assert!(!diagnostic.mark_pending_publication(identity(IRP_GEN_1), 131));
    assert_eq!(diagnostic.complete_pending_read(identity(IRP_GEN_2), 150), None);
    assert_eq!(diagnostic.complete_pending_read(identity(IRP_GEN_1), 150), Some(50));
    let counts = diagnostic.counts();
    assert_eq!((counts.pending_wait_ticks, counts.pending_delivery_ticks,
        counts.pending_published, counts.pending_publication_rejected), (30, 20, 1, 3));
    assert_eq!(counts.pending_wait_ticks + counts.pending_delivery_ticks, counts.pending_ticks);
    assert!(diagnostic.begin_pending_read(identity(IRP_GEN_2), 160));
    assert_eq!(diagnostic.complete_pending_read(identity(IRP_GEN_2), 180), Some(20));
    assert_eq!(diagnostic.counts().pending_unpublished, 1,
        "an unobserved publication must not masquerade as zero delivery latency");
}

#[test]
fn pending_terminal_outcomes_pair_once_and_report_bounded_overflow() {
    let mut diagnostic = HostedFilePhaseDiagnostic::<1>::new();
    assert!(diagnostic.begin_pending_read(identity(IRP_GEN_1), 100));
    assert!(!diagnostic.begin_pending_read(identity(IRP_GEN_2), 101));
    assert!(!diagnostic.record_pending_terminal(identity(IRP_GEN_2), 120, 0, 8));
    assert!(diagnostic.mark_pending_publication(identity(IRP_GEN_1), 130));
    assert!(diagnostic.record_pending_terminal(identity(IRP_GEN_1), 130, 0, 4));
    assert!(!diagnostic.record_pending_terminal(identity(IRP_GEN_1), 131, 0, 999));
    assert_eq!(diagnostic.complete_pending_read(identity(IRP_GEN_1), 150), Some(50));
    assert_eq!(diagnostic.complete_pending_read(identity(IRP_GEN_1), 151), None);

    assert!(diagnostic.begin_pending_read(identity(IRP_GEN_2), 160));
    assert!(diagnostic.mark_pending_publication(identity(IRP_GEN_2), 170));
    assert!(diagnostic.record_pending_terminal(identity(IRP_GEN_2), 170, 0xc0000001, 0));
    assert_eq!(diagnostic.complete_pending_read(identity(IRP_GEN_2), 180), Some(20));

    assert!(diagnostic.begin_pending_read(identity(IRP_GEN_1), 190));
    assert!(diagnostic.mark_pending_publication(identity(IRP_GEN_1), 200));
    assert!(diagnostic.record_pending_terminal(identity(IRP_GEN_1), 200, 0, 0));
    assert_eq!(diagnostic.complete_pending_read(identity(IRP_GEN_1), 210), Some(20));

    assert!(diagnostic.begin_pending_read(identity(IRP_GEN_2), 220));
    assert!(diagnostic.mark_pending_publication(identity(IRP_GEN_2), 230));
    assert!(diagnostic.record_pending_terminal(identity(IRP_GEN_2), 230, 0x8000_0005, 8));
    assert_eq!(diagnostic.complete_pending_read(identity(IRP_GEN_2), 240), Some(20));

    assert!(diagnostic.begin_pending_read(identity(IRP_GEN_1), 250));
    assert!(diagnostic.mark_pending_publication(identity(IRP_GEN_1), 260));
    assert!(diagnostic.record_pending_terminal(identity(IRP_GEN_1), 260, 0x8000_0016, 8));
    assert_eq!(diagnostic.complete_pending_read(identity(IRP_GEN_1), 270), Some(20));

    let counts = diagnostic.counts();
    assert_eq!(counts.pending_overflow, 1);
    assert_eq!(counts.pending_terminal_recorded, 5);
    assert_eq!(counts.pending_terminal_rejected, 2);
    assert_eq!(counts.pending_terminal_success, 2);
    assert_eq!(counts.pending_terminal_warning, 2);
    assert_eq!(counts.pending_terminal_error, 1);
    assert_eq!(counts.pending_terminal_copy_eligible_bytes, 12);
    assert_eq!(counts.pending_terminal_no_copy, 2);
    assert_eq!(counts.pending_terminal_zero_bytes, 1);
    assert_eq!(counts.pending_completed_with_terminal, 5);
    assert_eq!(counts.pending_completed_without_terminal, 0);
}

#[test]
fn npfs_callback_cost_is_split_by_major_and_nested_completion_owner() {
    let mut diagnostic = NpfsCallbackDiagnostic::new();
    let read = NpfsCallbackIdentity { canonical_irp_id: IRP_GEN_1, major: NpfsMajor::Read };
    let write = NpfsCallbackIdentity { canonical_irp_id: IRP_GEN_2, major: NpfsMajor::Write };

    assert!(diagnostic.enter(read, 100));
    assert!(!diagnostic.nested_completion(write, 0x1000, 5),
        "an unrelated dispatch generation cannot borrow read callback time");
    assert!(diagnostic.nested_completion(read, 0x1000, 5));
    assert!(diagnostic.returned(read, 125));
    assert!(diagnostic.enter(write, 130));
    assert!(diagnostic.nested_completion(write, 0x2000, 3));
    assert!(diagnostic.nested_completion(write, 0x3000, 4));
    assert!(diagnostic.returned(write, 150));
    let counts = diagnostic.counts();
    assert_eq!((counts.read_calls, counts.read_ticks, counts.read_completion_calls,
        counts.read_completion_ticks), (1, 25, 1, 5));
    assert_eq!((counts.write_calls, counts.write_ticks, counts.write_completion_calls,
        counts.write_completion_ticks), (1, 20, 2, 7));
    assert_eq!(counts.owner_mismatches, 1);
}

#[test]
fn npfs_callback_rejects_stale_generation_and_invalid_completion_target() {
    let mut diagnostic = NpfsCallbackDiagnostic::new();
    let active = NpfsCallbackIdentity { canonical_irp_id: IRP_GEN_1, major: NpfsMajor::Write };
    let stale = NpfsCallbackIdentity { canonical_irp_id: IRP_GEN_2, major: NpfsMajor::Write };
    assert!(diagnostic.enter(active, 200));
    assert!(!diagnostic.nested_completion(active, 0, 7));
    assert!(!diagnostic.returned(stale, 210));
    assert!(diagnostic.nested_completion(active, 0x1234, 4));
    assert!(diagnostic.returned(active, 220));
    assert_eq!(diagnostic.counts().write_completion_ticks, 4);
    assert_eq!(diagnostic.counts().owner_mismatches, 2);
}

#[test]
fn npfs_pool_retirement_cost_requires_exact_active_callback_generation() {
    let mut diagnostic = NpfsCallbackDiagnostic::new();
    let read = NpfsCallbackIdentity { canonical_irp_id: IRP_GEN_1, major: NpfsMajor::Read };
    let stale = NpfsCallbackIdentity { canonical_irp_id: IRP_GEN_2, major: NpfsMajor::Read };
    let write = NpfsCallbackIdentity { canonical_irp_id: IRP_GEN_2, major: NpfsMajor::Write };
    assert!(diagnostic.enter(read, 100));
    assert!(!diagnostic.nested_pool_retirement(stale, 0x1000, 8));
    assert!(!diagnostic.nested_pool_retirement(read, 0, 8));
    assert!(diagnostic.nested_pool_retirement(read, 0x1000, 7));
    assert!(diagnostic.returned(read, 120));
    assert!(diagnostic.enter(write, 130));
    assert!(diagnostic.nested_pool_retirement(write, 0x2000, 11));
    assert!(diagnostic.returned(write, 150));
    let counts = diagnostic.counts();
    assert_eq!((counts.read_pool_retire_calls, counts.read_pool_retire_ticks), (1, 7));
    assert_eq!((counts.write_pool_retire_calls, counts.write_pool_retire_ticks), (1, 11));
    assert_eq!(counts.owner_mismatches, 2);
}

#[test]
fn npfs_quota_allocation_cost_requires_exact_active_callback_generation() {
    let mut diagnostic = NpfsCallbackDiagnostic::new();
    let read = NpfsCallbackIdentity { canonical_irp_id: IRP_GEN_1, major: NpfsMajor::Read };
    let stale = NpfsCallbackIdentity { canonical_irp_id: IRP_GEN_2, major: NpfsMajor::Read };
    let write = NpfsCallbackIdentity { canonical_irp_id: IRP_GEN_2, major: NpfsMajor::Write };
    assert!(diagnostic.enter(read, 100));
    assert!(!diagnostic.nested_quota_allocation(stale, 0x1000, 8));
    assert!(!diagnostic.nested_quota_allocation(read, 0, 8));
    assert!(diagnostic.nested_quota_allocation(read, 0x1000, 7));
    assert!(diagnostic.returned(read, 120));
    assert!(diagnostic.enter(write, 130));
    assert!(diagnostic.nested_quota_allocation(write, 0x2000, 11));
    assert!(diagnostic.returned(write, 150));
    let counts = diagnostic.counts();
    assert_eq!((counts.read_quota_alloc_calls, counts.read_quota_alloc_ticks), (1, 7));
    assert_eq!((counts.write_quota_alloc_calls, counts.write_quota_alloc_ticks), (1, 11));
    assert_eq!(counts.owner_mismatches, 2);
}
