//! Real wait-table/Event-registry composition; native effect outcomes are explicit fixture inputs.
use nt_io_manager::*;
use nt_kernel_exec::{EventLeaseKind, EventObjectError, EventObjectOwner, EventObjectRegistry};

fn fixture() -> (SynchronousFileWaitTable, EventObjectRegistry, SynchronousFileWaiter, usize) {
    let mut events = EventObjectRegistry::new();
    let id = events.create(EventObjectOwner::new(42, 3), 101).unwrap();
    let lease = events.acquire_wait(id, EventLeaseKind::Operation).unwrap();
    let event = FileTransferEvent { id, lease, native_identity: 101 };
    let mut waiter = super::waiter(super::hosted(10), 20);
    waiter.transfer_parameters = Some(FileTransferParameters {
        arguments: [0x101, 0x202, 0x303, 0x404, 0x505, 0x606, 0x707, 0x808, 0x909],
        byte_offset: Some(37), key: 0x12345678,
    });
    waiter.transfer_event = Some(event);
    let mut queue = SynchronousFileWaitTable::new();
    let slot = queue.park(waiter).unwrap();
    assert_eq!(events.request_delete(id), Ok(None));
    (queue, events, waiter, slot)
}

fn assert_event_retained(events: &EventObjectRegistry, original: SynchronousFileWaiter) {
    let event = original.transfer_event.unwrap();
    assert_eq!(events.event_for_lease(event.lease, EventLeaseKind::Operation), Ok(event.id));
    let snapshot = events.snapshot(event.id).unwrap();
    assert!(snapshot.delete_pending);
    assert_eq!(snapshot.operation_leases, 1);
    assert_eq!(events.live_lease_count(), 1, "waiter copies create no additional Event authority");
}

#[test]
fn transfer_values_and_event_survive_rejected_retry_and_exact_adoption() {
    let (mut queue, mut events, original, slot) = fixture();
    assert!(queue.promote_exact(slot, original.key(), original.tid + 1).is_none());
    queue.promote_exact(slot, original.key(), original.tid).unwrap();
    let identity = queue.retry_identity(slot, original.key(), original.tid).unwrap();
    let mut refused = queue.begin_retry(identity).unwrap();
    assert_eq!(refused.waiter().transfer_parameters.unwrap().arguments,
        [0x101, 0x202, 0x303, 0x404, 0x505, 0x606, 0x707, 0x808, 0x909]);
    assert_eq!(refused.waiter().transfer_parameters, original.transfer_parameters);
    assert_eq!(refused.waiter().transfer_event, original.transfer_event);
    queue.record_retry(&mut refused, SynchronousFileRetryOutcome::NotEntered(13)).unwrap();
    assert_event_retained(&events, original);
    let mut acknowledged = queue.begin_retry(identity).unwrap();
    queue.record_retry(&mut acknowledged, SynchronousFileRetryOutcome::Acknowledged).unwrap();
    assert!(!queue.finish_retry(identity, Err(13)).unwrap());
    assert_event_retained(&events, original);
    assert!(queue.finish_retry(identity, Ok(())).unwrap());
    assert!(queue.begin_ingress(original.pi, original.tid, original.badge + 1,
        original.service_number).is_err());
    assert_event_retained(&events, original);
    let mut ingress = queue.begin_ingress(original.pi, original.tid, original.badge,
        original.service_number).unwrap().unwrap();
    let mut attempt = queue.begin_adoption(&mut ingress).unwrap();
    assert_eq!(attempt.waiter().transfer_parameters, original.transfer_parameters);
    assert_eq!(attempt.waiter().transfer_event, original.transfer_event);
    let owner = queue.record_adoption(&mut attempt, Ok(())).unwrap().unwrap();
    assert!(queue.record_adoption(&mut attempt, Ok(())).is_err());
    assert!(queue.is_empty());
    let captured = owner.waiter();
    assert_eq!(captured.transfer_parameters.unwrap().arguments,
        [0x101, 0x202, 0x303, 0x404, 0x505, 0x606, 0x707, 0x808, 0x909],
        "adoption preserves the original register and tail arguments, not retry transport values");
    assert_eq!(captured.transfer_parameters, original.transfer_parameters);
    assert_eq!(captured.transfer_event, original.transfer_event);
    assert_event_retained(&events, original);
    let event = captured.transfer_event.unwrap();
    assert_eq!(events.release_wait(event.lease, EventLeaseKind::ProviderWait), Err(EventObjectError::WrongLeaseKind));
    assert_event_retained(&events, original);
    assert_eq!(events.release_wait(event.lease, EventLeaseKind::Operation).unwrap().unwrap().id, event.id);
    assert_eq!(events.release_wait(event.lease, EventLeaseKind::Operation), Err(EventObjectError::StaleLease));
    assert_eq!(events.snapshot(event.id), Err(EventObjectError::StaleObject));
}

#[test]
fn uncertain_retry_keeps_exact_transfer_owner_and_event_pinned() {
    let (mut queue, events, original, slot) = fixture();
    queue.promote_exact(slot, original.key(), original.tid).unwrap();
    let identity = queue.retry_identity(slot, original.key(), original.tid).unwrap();
    let mut attempt = queue.begin_retry(identity).unwrap();
    queue.record_retry(&mut attempt, SynchronousFileRetryOutcome::Indeterminate(13)).unwrap();
    assert!(queue.begin_retry(identity).is_err());
    assert!(queue.finish_retry(identity, Ok(())).is_err());
    assert!(queue.take_exact(slot, original.key(), original.tid).is_none());
    assert!(queue.begin_ingress(original.pi, original.tid, original.badge,
        original.service_number).is_err());
    assert!(!queue.is_empty());
    assert_event_retained(&events, original);
}

#[test]
fn exact_cancel_returns_event_owner_only_once_after_all_effect_receipts() {
    let (mut queue, mut events, original, slot) = fixture();
    let wait = queue.wait_identity(slot, original.key(), original.tid).unwrap();
    let cancel = queue.request_cancellation(wait).unwrap();
    assert!(queue.finish_cancellation(cancel).is_none());
    assert_event_retained(&events, original);
    // These are reported effect outcomes, not synthetic native completion claims.
    for receipt in [
        SynchronousFileCancelReceipt::HostedPolicy { waiters: 0 },
        SynchronousFileCancelReceipt::Wake,
        SynchronousFileCancelReceipt::HostedReference(nt_io_completion::FileReferenceRelease {
            device_id: super::DEVICE, ..Default::default()
        }),
        SynchronousFileCancelReceipt::ReplyRevoked,
        SynchronousFileCancelReceipt::ReplyCapRetired,
    ] {
        let mut attempt = queue.begin_cancellation(cancel).unwrap();
        queue.record_cancellation(&mut attempt,
            SynchronousFileCancelOutcome::Completed(receipt)).unwrap();
        assert_event_retained(&events, original);
    }
    let retired = queue.finish_cancellation(cancel).unwrap();
    assert_eq!(retired.transfer_parameters, original.transfer_parameters);
    assert_eq!(retired.transfer_event, original.transfer_event);
    assert!(queue.finish_cancellation(cancel).is_none());
    let event = retired.transfer_event.unwrap();
    assert_eq!(events.release_wait(event.lease, EventLeaseKind::Operation).unwrap().unwrap().id, event.id);
    assert_eq!(events.release_wait(event.lease, EventLeaseKind::Operation), Err(EventObjectError::StaleLease));
    assert!(queue.is_empty());
}

#[test]
fn pending_transfer_keeps_event_through_abandonment_and_exact_retirement() {
    let (_, mut events, original, _) = fixture();
    let event = original.transfer_event.unwrap();
    let request = PendingFileIo {
        route: PendingFileRoute::Hosted(10), irp_id: 91,
        major: nt_io_abi::major::IRP_MJ_WRITE,
        tid: original.tid, transfer_event: Some(event), event_obj_idx: event.native_identity,
        ..PendingFileIo::default()
    };
    let mut pending = PendingFileIoTable::new();
    let slot = pending.park(request).unwrap();
    let identity = pending.identity(slot).unwrap();
    let mut foreign_table = PendingFileIoTable::new();
    let foreign_slot = foreign_table.park(PendingFileIo { transfer_event: None, ..request }).unwrap();
    let foreign = foreign_table.identity(foreign_slot).unwrap();
    assert_eq!(pending.finish_owner_exact(foreign, 91), None);
    assert_eq!(pending.get_exact(identity).unwrap().transfer_event, Some(event));
    assert_event_retained(&events, original);
    pending.abandon_transfer_owner_exact(identity, 91).unwrap();
    assert_eq!(pending.finish_owner_exact(identity, 91), None);
    assert_event_retained(&events, original);
    pending.mark_backend_acked_exact(slot, 91).unwrap();
    let retired = pending.finish_owner_exact(identity, 91).unwrap();
    assert_eq!(retired.transfer_event, Some(event));
    assert_eq!(pending.finish_owner_exact(identity, 91), None);
    assert_eq!(events.release_wait(event.lease, EventLeaseKind::Operation).unwrap().unwrap().id, event.id);
    let reused = pending.park(PendingFileIo { transfer_event: None, ..request }).unwrap();
    assert_eq!(reused, slot);
    assert_eq!(pending.get_exact(identity), None);
    assert_eq!(events.release_wait(event.lease, EventLeaseKind::Operation), Err(EventObjectError::StaleLease));
}
