use super::*;

const FILE: u64 = 11;
const IRP: u64 = 12;
const TID: u64 = 13;
const ERROR: u32 = 0xc000_009a;

fn request() -> PendingFileIo {
    PendingFileIo {
        file_id: FILE,
        irp_id: IRP,
        major: nt_io_abi::major::IRP_MJ_READ,
        tid: TID,
        busy: Some(test_busy(FILE, TID)),
        event_obj_idx: u64::MAX,
        reply_cap: 77,
        reply_required: true,
        ..PendingFileIo::default()
    }
}

fn parked() -> (PendingFileIoTable, usize) {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(request()).unwrap();
    (table, slot)
}

fn retire(table: &mut PendingFileIoTable, slot: usize) {
    assert_eq!(table.claim_reply_cap_exact(slot, IRP), Some(Some(77)));
    table.mark_reply_published_exact(slot, IRP).unwrap();
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    table.finish_exact(slot, IRP).unwrap();
}

#[test]
fn release_and_wake_receipts_gate_reply_ack_and_retirement() {
    let (mut table, slot) = parked();
    assert!(table
        .mark_delivery_exact(slot, IRP, IO_DELIVERY_FILE_LOCK_RELEASED)
        .is_none());
    assert!(table.claim_reply_cap_exact(slot, IRP).is_none());
    assert!(table.mark_backend_acked_exact(slot, IRP).is_none());
    let mut release = table.begin_busy_release_exact(slot, IRP).unwrap();
    assert!(table.begin_busy_release_exact(slot, IRP).is_err());
    assert_eq!(release.owner(), request().busy.unwrap().owner());
    assert!(
        table.record_busy_release(&mut release, Ok(2)).unwrap() & IO_DELIVERY_FILE_LOCK_RELEASED
            != 0
    );
    assert!(table.record_busy_release(&mut release, Ok(2)).is_err());
    assert!(table.begin_busy_release_exact(slot, IRP).is_err());
    assert!(table.claim_reply_cap_exact(slot, IRP).is_none());
    assert!(table.mark_backend_acked_exact(slot, IRP).is_none());
    assert!(table.finish_exact(slot, IRP).is_none());
    let mut wake = table.begin_busy_wake_exact(slot, IRP).unwrap();
    assert_eq!(wake.waiters(), 2);
    assert!(table.next_busy_wake_after(None).is_none());
    assert!(table.begin_busy_wake_exact(slot, IRP).is_err());
    table.record_busy_wake(&mut wake, Ok(())).unwrap();
    assert!(table.record_busy_wake(&mut wake, Ok(())).is_err());
    assert!(table.get(slot).unwrap().busy.unwrap().is_settled());
    retire(&mut table, slot);
    assert!(table.is_empty());
}

#[test]
fn definite_release_rejection_preserves_owner_for_exact_retry() {
    let (mut table, slot) = parked();
    let mut attempt = table.begin_busy_release_exact(slot, IRP).unwrap();
    assert_eq!(table.record_busy_release(&mut attempt, Err(ERROR)), Ok(0));
    assert_eq!(
        table.get(slot).unwrap().busy.unwrap().phase(),
        PendingFileBusyPhase::ReleaseReady {
            last_error: Some(ERROR)
        }
    );
    assert!(table.get(slot).unwrap().busy.unwrap().release_pending());
    assert!(table.next_busy_wake_after(None).is_none());
    assert!(table.claim_reply_cap_exact(slot, IRP).is_none());
    assert!(table.record_busy_release(&mut attempt, Ok(0)).is_err());
    settle_test_busy(&mut table, slot, IRP);
    retire(&mut table, slot);
}

#[test]
fn wake_failure_retries_only_wake_not_release() {
    let (mut table, slot) = parked();
    let mut release = table.begin_busy_release_exact(slot, IRP).unwrap();
    table.record_busy_release(&mut release, Ok(1)).unwrap();
    let mut wake = table.begin_busy_wake_exact(slot, IRP).unwrap();
    table.record_busy_wake(&mut wake, Err(ERROR)).unwrap();
    let pending = table.get(slot).unwrap();
    assert!(!pending.busy.unwrap().release_pending());
    assert_eq!(
        pending.busy.unwrap().phase(),
        PendingFileBusyPhase::WakeReady {
            waiters: 1,
            last_error: Some(ERROR)
        }
    );
    assert_ne!(pending.delivery_state & IO_DELIVERY_FILE_LOCK_RELEASED, 0);
    assert!(table.begin_busy_release_exact(slot, IRP).is_err());
    assert_eq!(table.next_busy_wake_after(None).unwrap().0, slot);
    assert!(table.claim_reply_cap_exact(slot, IRP).is_none());
    let mut retry = table.begin_busy_wake_exact(slot, IRP).unwrap();
    assert!(table.record_busy_wake(&mut wake, Ok(())).is_err());
    table.record_busy_wake(&mut retry, Ok(())).unwrap();
    retire(&mut table, slot);
}

#[test]
fn dropped_release_attempt_is_not_permission_to_replay_or_drop_owner() {
    let (mut table, slot) = parked();
    drop(table.begin_busy_release_exact(slot, IRP).unwrap());
    assert!(table.begin_busy_release_exact(slot, IRP).is_err());
    assert!(table.begin_busy_wake_exact(slot, IRP).is_err());
    assert!(!table.reset());
    assert_eq!(
        table.take_thread_with(TID, |_| panic!("live Busy escaped")),
        0
    );
    assert_eq!(table.abandon_thread_transfers_with(TID, |_| {}), 1);
    assert!(table.get(slot).unwrap().consumer_abandoned);
    assert!(table.finish_exact(slot, IRP).is_none());
}

#[test]
fn abandoned_consumer_does_not_invalidate_entered_release_or_wake() {
    let (mut table, slot) = parked();
    let mut release = table.begin_busy_release_exact(slot, IRP).unwrap();
    assert_eq!(table.abandon_thread_transfers_with(TID, |_| {}), 1);
    table.record_busy_release(&mut release, Ok(0)).unwrap();
    let mut wake = table.begin_busy_wake_exact(slot, IRP).unwrap();
    assert_eq!(table.abandon_thread_transfers_with(TID, |_| {}), 0);
    table.record_busy_wake(&mut wake, Ok(())).unwrap();
    assert!(table.completion_surfaces_settled_exact(slot, IRP));
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    assert!(table.finish_exact(slot, IRP).unwrap().consumer_abandoned);
}

#[test]
fn dropped_wake_attempt_stays_retained_with_release_committed() {
    let (mut table, slot) = parked();
    let mut release = table.begin_busy_release_exact(slot, IRP).unwrap();
    table.record_busy_release(&mut release, Ok(0)).unwrap();
    drop(table.begin_busy_wake_exact(slot, IRP).unwrap());
    assert!(table.next_busy_wake_after(None).is_none());
    assert!(table.begin_busy_wake_exact(slot, IRP).is_err());
    assert!(table.begin_busy_release_exact(slot, IRP).is_err());
    assert!(table.claim_reply_cap_exact(slot, IRP).is_none());
    assert!(!table.reset());
    assert_eq!(table.take_thread_with(TID, |_| panic!("wake escaped")), 0);
}

#[test]
fn attempts_are_exact_across_tables_slots_and_identical_irp_reuse() {
    let (mut first, slot) = parked();
    let (mut second, other_slot) = parked();
    assert_eq!(slot, other_slot);
    let mut release = first.begin_busy_release_exact(slot, IRP).unwrap();
    let mut other_release = second.begin_busy_release_exact(other_slot, IRP).unwrap();
    assert_eq!(
        second.record_busy_release(&mut release, Ok(0)),
        Err(PendingFileBusyError::WrongIdentity)
    );
    first.record_busy_release(&mut release, Ok(0)).unwrap();
    second
        .record_busy_release(&mut other_release, Ok(0))
        .unwrap();
    let mut wake = first.begin_busy_wake_exact(slot, IRP).unwrap();
    let mut other_wake = second.begin_busy_wake_exact(other_slot, IRP).unwrap();
    assert_eq!(
        second.record_busy_wake(&mut wake, Ok(())),
        Err(PendingFileBusyError::WrongIdentity)
    );
    first.record_busy_wake(&mut wake, Ok(())).unwrap();
    second.record_busy_wake(&mut other_wake, Ok(())).unwrap();
    retire(&mut first, slot);
    assert!(first.reset());
    assert_eq!(first.park(request()), Some(slot));
    assert_eq!(
        first.record_busy_release(&mut release, Ok(0)),
        Err(PendingFileBusyError::WrongIdentity)
    );
    assert_eq!(
        first.record_busy_wake(&mut wake, Ok(())),
        Err(PendingFileBusyError::WrongIdentity)
    );
    settle_test_busy(&mut first, slot, IRP);
    retire(&mut first, slot);
    retire(&mut second, other_slot);
}

#[test]
fn published_observation_cannot_be_reparked_as_fresh_busy_owner() {
    let (table, slot) = parked();
    let copied = table.get(slot).unwrap();
    let mut other = PendingFileIoTable::new();
    assert!(other.park(copied).is_none());
    let reservation = other.reserve().unwrap();
    assert_eq!(
        other.park_reserved(reservation, copied),
        Err(PendingFileIoParkError::InvalidRecord)
    );
    assert!(other.cancel_reservation(reservation));
}

#[test]
fn admission_rejects_wrong_file_domain_tid_mode_and_local_variants() {
    let owners = [
        FileIoBusyOwner {
            key: FileIoWaitKey::Hosted(FILE + 1),
            tid: TID,
            mode: FileIoMode::SynchronousAlertable,
        },
        FileIoBusyOwner {
            key: FileIoWaitKey::LocalOverlay(FILE),
            tid: TID,
            mode: FileIoMode::SynchronousAlertable,
        },
        FileIoBusyOwner {
            key: FileIoWaitKey::Hosted(FILE),
            tid: TID + 1,
            mode: FileIoMode::SynchronousAlertable,
        },
        FileIoBusyOwner {
            key: FileIoWaitKey::Hosted(FILE),
            tid: 0,
            mode: FileIoMode::SynchronousAlertable,
        },
        FileIoBusyOwner {
            key: FileIoWaitKey::Hosted(FILE),
            tid: u64::MAX,
            mode: FileIoMode::SynchronousAlertable,
        },
        FileIoBusyOwner {
            key: FileIoWaitKey::Hosted(FILE),
            tid: TID,
            mode: FileIoMode::Asynchronous,
        },
    ];
    for owner in owners {
        let mut pending = request();
        pending.busy = Some(PendingFileBusy::new(owner));
        assert!(PendingFileIoTable::new().park(pending).is_none());
    }
    let mut notify = request();
    notify.major = nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL;
    notify.iosb_va = 0x1000;
    notify.operation = PendingFileIoOperation::LocalDirectoryNotify(PendingLocalDirectoryNotify {
        notify_id: 1,
        status: 0x103,
        information: 0,
        alertable: true,
    });
    assert!(PendingFileIoTable::new().park(notify).is_none());
    let mut lock = notify;
    lock.major = nt_io_abi::major::IRP_MJ_LOCK_CONTROL;
    lock.operation = PendingFileIoOperation::LocalByteLock(PendingLocalByteLock {
        wait_id: 1,
        status: 0x103,
        alertable: true,
    });
    assert!(PendingFileIoTable::new().park(lock).is_none());
    lock.busy = None;
    assert!(PendingFileIoTable::new().park(lock).is_some());
    notify.busy = None;
    assert!(PendingFileIoTable::new().park(notify).is_some());
}

#[test]
fn release_requires_every_pre_reply_surface_but_accepts_terminal_iosb_fault() {
    let mut table = PendingFileIoTable::new();
    let mut pending = request();
    pending.output_va = 0x2000;
    pending.output_len = 8;
    pending.iosb_va = 0x1000;
    pending.signal_file = true;
    pending.event_obj_idx = 5;
    let slot = table.park(pending).unwrap();
    assert_eq!(
        table.begin_busy_release_exact(slot, IRP).unwrap_err(),
        PendingFileBusyError::UnsettledSurfaces
    );
    table.advance_output_exact(slot, IRP, 8, 8).unwrap();
    table.mark_iosb_faulted_exact(slot, IRP, 0x1000).unwrap();
    table
        .mark_delivery_exact(slot, IRP, IO_DELIVERY_FILE_PUBLISHED)
        .unwrap();
    assert_eq!(
        table.begin_busy_release_exact(slot, IRP).unwrap_err(),
        PendingFileBusyError::UnsettledSurfaces
    );
    table
        .mark_delivery_exact(slot, IRP, IO_DELIVERY_EVENT_PUBLISHED)
        .unwrap();
    settle_test_busy(&mut table, slot, IRP);
    retire(&mut table, slot);
}

#[test]
fn wake_scan_is_bounded_and_skips_entered_attempts_on_reentry() {
    let (mut table, first) = parked();
    let mut another = request();
    another.irp_id += 1;
    let second = table.park(another).unwrap();
    for (slot, irp) in [(first, IRP), (second, IRP + 1)] {
        let mut release = table.begin_busy_release_exact(slot, irp).unwrap();
        table.record_busy_release(&mut release, Ok(0)).unwrap();
    }
    assert_eq!(table.next_busy_wake_after(None).unwrap().0, first);
    let mut first_wake = table.begin_busy_wake_exact(first, IRP).unwrap();
    assert_eq!(table.next_busy_wake_after(None).unwrap().0, second);
    table.record_busy_wake(&mut first_wake, Err(ERROR)).unwrap();
    assert_eq!(table.next_busy_wake_after(Some(first)).unwrap().0, second);
    assert!(table.next_busy_wake_after(Some(second)).is_none());
}

#[test]
fn release_exhaustion_and_wrong_irp_do_not_enter_mechanism() {
    let (mut table, slot) = parked();
    assert_eq!(
        table.begin_busy_release_exact(slot, IRP + 1).unwrap_err(),
        PendingFileBusyError::WrongIdentity
    );
    table.slots[slot]
        .as_mut()
        .unwrap()
        .busy
        .as_mut()
        .unwrap()
        .next_attempt = u64::MAX;
    let before = table.get(slot);
    assert_eq!(
        table.begin_busy_release_exact(slot, IRP).unwrap_err(),
        PendingFileBusyError::Exhausted
    );
    assert_eq!(table.get(slot), before);
}

#[test]
fn reset_does_not_discard_ordinary_owner_or_pre_dispatch_reservation() {
    let mut table = PendingFileIoTable::new();
    let mut pending = request();
    pending.busy = None;
    let slot = table.park(pending).unwrap();
    assert!(!table.reset());
    assert_eq!(table.get(slot), Some(pending));
    assert_eq!(table.take_thread_with(TID, |_| {}), 1);
    let reservation = table.reserve().unwrap();
    assert!(!table.reset());
    assert!(table.cancel_reservation(reservation));
    assert!(table.reset());
}

#[test]
fn retarget_cannot_change_the_identity_of_an_entered_release() {
    let mut table = PendingFileIoTable::new();
    let mut pending = request();
    pending.major = nt_io_abi::major::IRP_MJ_CREATE;
    pending.iosb_va = 0x1000;
    pending.operation = PendingFileIoOperation::SetFileName(PendingSetFileNameOperation {
        transaction_id: 31,
        target_file_id: FILE + 1,
    });
    let slot = table.park(pending).unwrap();
    // Abandonment removes user destinations but keeps the source File's Busy owner.
    assert_eq!(table.abandon_thread_transfers_with(TID, |_| {}), 1);
    let mut release = table.begin_busy_release_exact(slot, IRP).unwrap();
    assert!(table
        .retarget_set_file_name_irp_exact(slot, IRP, IRP + 1)
        .is_none());
    table.record_busy_release(&mut release, Err(ERROR)).unwrap();
    assert!(table
        .retarget_set_file_name_irp_exact(slot, IRP, IRP + 1)
        .is_none());
    settle_test_busy(&mut table, slot, IRP);
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    assert!(table.finish_exact(slot, IRP).is_some());
}

#[test]
fn apc_interruption_requires_captured_alertable_mode_and_unstarted_release() {
    let mut table = PendingFileIoTable::new();
    let mut pending = request();
    pending.busy = Some(PendingFileBusy::new(FileIoBusyOwner {
        mode: FileIoMode::SynchronousNonAlertable,
        ..pending.busy.unwrap().owner()
    }));
    let slot = table.park(pending).unwrap();
    assert!(table.user_apc_interrupt_candidate(TID).is_none());
    assert!(table
        .mark_user_apc_interrupt_requested_exact(slot, IRP, FILE, TID)
        .is_none());

    let (mut alertable, slot) = parked();
    assert!(alertable.user_apc_interrupt_candidate(TID).is_some());
    let mut release = alertable.begin_busy_release_exact(slot, IRP).unwrap();
    assert!(alertable.user_apc_interrupt_candidate(TID).is_none());
    assert!(alertable
        .mark_user_apc_interrupt_requested_exact(slot, IRP, FILE, TID)
        .is_none());
    alertable
        .record_busy_release(&mut release, Err(ERROR))
        .unwrap();
    assert!(alertable.user_apc_interrupt_candidate(TID).is_none());
}
