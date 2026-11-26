use super::*;

const FILE: u64 = 19;
const TID: u64 = 23;
const IOSB: u64 = 0x2000;
const REPLY: u64 = 41;

fn park_basic(table: &mut PendingFileIoTable) -> (PendingFileIoIdentity, u64) {
    let reservation = table.reserve().unwrap();
    let id = table.local_operation_id(reservation).unwrap();
    let row = PendingFileIo {
        route: PendingFileRoute::Local(LocalFileObject::Overlay(FILE)),
        irp_id: id,
        major: nt_io_abi::major::IRP_MJ_SET_INFORMATION,
        operation: PendingFileIoOperation::OwnedBasicPreflight(PendingOwnedBasicPreflight::new(7)),
        tid: TID,
        busy: Some(PendingFileBusy::new(FileIoBusyOwner {
            key: crate::FileIoWaitKey::LocalOverlay(FILE),
            tid: TID,
            mode: nt_io_completion::FileIoMode::SynchronousNonAlertable,
        })),
        iosb_va: IOSB,
        reply_cap: REPLY,
        reply_required: true,
        completion_port_suppressed: true,
        event_obj_idx: u64::MAX,
        ..PendingFileIo::default()
    };
    let slot = table.park_reserved(reservation, row).unwrap();
    (table.identity(slot).unwrap(), id)
}

fn assert_uncommitted(table: &mut PendingFileIoTable, owner: PendingFileIoIdentity, id: u64) {
    let row = table.get_exact(owner).unwrap();
    assert_eq!(row.owned_terminal_result(), None);
    assert_eq!(row.iosb_va, IOSB);
    assert_eq!(row.reply_cap, REPLY);
    assert_eq!(row.delivery_state, 0);
    assert_eq!(
        table.mark_delivery_exact(owner.slot, id, IO_DELIVERY_IOSB_PUBLISHED),
        None
    );
    assert_eq!(table.claim_reply_cap_exact(owner.slot, id), None);
    assert_eq!(table.mark_backend_acked_exact(owner.slot, id), None);
    assert_eq!(table.finish_exact(owner.slot, id), None);
}

#[test]
fn exact_local_basic_set_survives_busy_baseline_without_early_delivery() {
    let mut table = PendingFileIoTable::new();
    let (owner, id) = park_basic(&mut table);
    assert_uncommitted(&mut table, owner, id);

    let mut first = table.begin_owned_basic_baseline_exact(owner, id).unwrap();
    assert_uncommitted(&mut table, owner, id);
    assert_eq!(table.record_owned_basic_baseline_busy(&mut first), Some(()));
    assert_uncommitted(&mut table, owner, id);

    let mut second = table.begin_owned_basic_baseline_exact(owner, id).unwrap();
    assert_ne!(first, second);
    assert_eq!(
        table.record_owned_basic_baseline_published(&mut first, 7),
        None
    );
    assert_eq!(
        table.record_owned_basic_baseline_published(&mut second, 6),
        None
    );
    assert_uncommitted(&mut table, owner, id);
    assert_eq!(
        table.record_owned_basic_baseline_published(&mut second, 7),
        Some(())
    );
    assert_uncommitted(&mut table, owner, id);
    assert_eq!(table.cancel_unentered_owned_basic_exact(owner, id), None);
    assert_uncommitted(&mut table, owner, id);
    assert_eq!(table.begin_owned_basic_baseline_exact(owner, id), None);
}

#[test]
fn basic_baseline_ticket_refuses_crossed_owner_and_retains_uncertain_effect() {
    let mut table = PendingFileIoTable::new();
    let (owner, id) = park_basic(&mut table);
    let mut ticket = table.begin_owned_basic_baseline_exact(owner, id).unwrap();
    let mut peer = PendingFileIoTable::new();
    let (peer_owner, peer_id) = park_basic(&mut peer);
    assert_eq!(
        peer.record_owned_basic_baseline_published(&mut ticket, 7),
        None
    );
    assert_eq!(
        table.begin_owned_basic_baseline_exact(peer_owner, peer_id),
        None
    );
    let crossed_generation = PendingFileIoIdentity {
        generation: owner.generation().checked_add(1).unwrap(),
        ..owner
    };
    assert_eq!(
        table.begin_owned_basic_baseline_exact(crossed_generation, id),
        None
    );

    // A detached consumer loses delivery surfaces, while the entered baseline owner remains.
    assert!(table.abandon_transfer_exact(owner.slot, id).is_some());
    assert_eq!(
        table.record_owned_basic_baseline_uncertain(&mut ticket),
        Some(())
    );
    assert_eq!(table.cancel_unentered_owned_basic_exact(owner, id), None);
    assert_eq!(table.begin_owned_basic_baseline_exact(owner, id), None);
    assert_eq!(table.record_owned_basic_baseline_busy(&mut ticket), None);
    assert_eq!(
        table.record_owned_basic_baseline_published(&mut ticket, 7),
        None
    );
    let retained = table.get_exact(owner).unwrap();
    assert!(retained.consumer_abandoned);
    assert!(retained.operation.is_owned_work_uncommitted());
    assert_eq!(retained.delivery_state, 0);
    assert_eq!(table.finish_exact(owner.slot, id), None);
}

#[test]
fn cancelled_consumer_before_baseline_entry_cannot_start_effect() {
    let mut table = PendingFileIoTable::new();
    let (owner, id) = park_basic(&mut table);
    assert!(table.abandon_transfer_exact(owner.slot, id).is_some());
    assert_eq!(table.begin_owned_basic_baseline_exact(owner, id), None);
    assert_eq!(
        table.get_exact(owner).unwrap().owned_terminal_result(),
        None
    );
    assert_eq!(
        table.cancel_unentered_owned_basic_exact(owner, id),
        Some(())
    );
    assert_eq!(
        table.get_exact(owner).unwrap().owned_terminal_result(),
        Some((nt_status::NtStatus::CANCELLED.raw() as u32, 0))
    );
}
