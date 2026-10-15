use nt_io_completion::{FileCompletionTable, FileIoMode, FileReferenceRelease};
use nt_io_manager::*;

fn request(irp_id: u64) -> PendingFileIo {
    PendingFileIo {
        route: PendingFileRoute::Hosted(72),
        irp_id,
        tid: 73,
        major: nt_io_abi::major::IRP_MJ_SET_INFORMATION,
        operation: PendingFileIoOperation::OwnedInline(PendingOwnedInline {
            status: 0,
            information: 0,
        }),
        event_obj_idx: u64::MAX,
        completion_port_suppressed: true,
        ..PendingFileIo::default()
    }
}

#[test]
fn consumed_hosted_reference_is_retained_before_followup_and_never_released_twice() {
    let mut files = FileCompletionTable::<1>::new();
    files.insert_file_with_mode(72, 75, FileIoMode::Asynchronous).unwrap();
    files.retain_file(72).unwrap();
    let mut table = PendingFileIoTable::new();
    let slot = table.park(request(71)).unwrap();
    let identity = table.identity(slot).unwrap();
    assert!(table.mark_owned_reference_released_exact(slot, 71).is_none());
    assert!(table.record_owned_reference_release_exact(identity, 71,
        FileReferenceRelease::default()).is_none(), "cannot retire before delivery/ACK");
    table.mark_backend_acked_exact(slot, 71).unwrap();
    let release = files.release_file(72).unwrap();
    assert_eq!(table.record_owned_reference_release_exact(identity, 71, release), Some(()));
    assert_eq!(table.owned_reference_release_exact(identity, 71), Some(release));
    assert!(table.finish_owner_exact(identity, 71).is_none());
    // A definite followup refusal does not consume this receipt or return to decrementing File.
    assert_eq!(table.owned_reference_release_exact(identity, 71), Some(release));
    assert!(table.record_owned_reference_release_exact(identity, 71, release).is_none());
    table.mark_owned_reference_released_exact(slot, 71).unwrap();
    assert_eq!(table.finish_owner_exact(identity, 71).unwrap().owned_terminal_result(), Some((0, 0)));
    assert!(table.owned_reference_release_exact(identity, 71).is_none());
    assert!(files.release_handle(72).unwrap().cleanup_required,
        "only the original handle reference remains after one owned-inline release");
}

#[test]
fn reference_receipts_require_exact_table_generation_irp_and_survive_abandonment() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(request(71)).unwrap();
    let old = table.identity(slot).unwrap();
    table.mark_backend_acked_exact(slot, 71).unwrap();
    let mut foreign = PendingFileIoTable::new();
    let foreign_slot = foreign.park(request(71)).unwrap();
    let foreign_identity = foreign.identity(foreign_slot).unwrap();
    let release = FileReferenceRelease { port_id: Some(81), ..FileReferenceRelease::default() };
    assert!(table.record_owned_reference_release_exact(foreign_identity, 71, release).is_none());
    assert!(table.record_owned_reference_release_exact(old, 72, release).is_none());
    assert_eq!(table.record_owned_reference_release_exact(old, 71, release), Some(()));
    table.abandon_thread_transfers_with(73, |_| {});
    assert!(table.get_exact(old).unwrap().consumer_abandoned);
    assert_eq!(table.owned_reference_release_exact(old, 71), Some(release));
    assert!(table.finish_owner_exact(old, 71).is_none());
    table.mark_owned_reference_released_exact(slot, 71).unwrap();
    table.finish_owner_exact(old, 71).unwrap();
    let reused = table.park(request(71)).unwrap();
    let current = table.identity(reused).unwrap();
    assert_eq!(slot, reused);
    assert_ne!(old, current);
    table.mark_backend_acked_exact(reused, 71).unwrap();
    assert!(table.record_owned_reference_release_exact(old, 71, release).is_none());
    assert!(table.owned_reference_release_exact(current, 71).is_none());
    assert_eq!(table.record_owned_reference_release_exact(current, 71, release), Some(()));
}
