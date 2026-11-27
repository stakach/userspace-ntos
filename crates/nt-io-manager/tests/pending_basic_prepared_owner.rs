use std::cell::Cell;
use std::rc::Rc;

use nt_fs::{FileSystem, MemFs, FILE_CREATE, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, STATUS_SUCCESS,
    SYNCHRONIZE};
use nt_io_manager::{FileIoBusyOwner, FileIoWaitKey, LocalFileObject,
    PendingBasicPreparedAdmissionError, PendingBasicPreparedOwner, PendingBasicPreparedTable,
    PendingFileBusy, PendingFileIo, PendingFileIoIdentity, PendingFileIoOperation,
    PendingFileIoParkError, PendingFileIoReservation, PendingFileIoTable, PendingFileRoute,
    PendingOwnedBasicPreflight, PendingOwnedInline};

struct FileReference(Rc<Cell<usize>>);

impl Drop for FileReference {
    fn drop(&mut self) { self.0.set(self.0.get() + 1); }
}

fn prepared() -> (FileSystem, u64, [u8; 40]) {
    let mut fs = FileSystem::new(MemFs::new());
    assert!(fs.provision_directory(r"\??\C:\Dir"));
    let opened = fs.zw_create_file(r"\??\C:\Dir\file.txt", FILE_WRITE_DATA | SYNCHRONIZE,
        0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE,
        FILE_NON_DIRECTORY_FILE);
    assert_eq!(opened.status, STATUS_SUCCESS);
    let mut input = [0u8; 40];
    input[16..24].copy_from_slice(&777u64.to_le_bytes());
    (fs, opened.handle, input)
}

#[test]
fn prepared_owner_keeps_one_stable_file_id_across_handles_and_apply() {
    let (mut fs, first_handle, input) = prepared();
    let second = fs.zw_create_file(r"\??\C:\Dir\file.txt", FILE_WRITE_DATA | SYNCHRONIZE,
        0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN,
        FILE_NON_DIRECTORY_FILE);
    assert_eq!(second.status, STATUS_SUCCESS);
    assert_ne!(first_handle, second.handle);
    let drops = Rc::new(Cell::new(0));
    let mut first = PendingBasicPreparedOwner::prepare(&fs, first_handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let second = PendingBasicPreparedOwner::prepare(&fs, second.handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let stable = fs.query_file_object_information(first_handle).unwrap().metadata.file_id;
    assert_eq!(first.stable_file_id(), stable);
    assert_eq!(second.stable_file_id(), stable);
    assert_eq!(first.apply_snapshot_once(&mut fs).0, STATUS_SUCCESS);
    assert_eq!(first.stable_file_id(), stable);
}

fn basic_row(irp_id: u64) -> PendingFileIo {
    PendingFileIo {
        route: PendingFileRoute::Local(LocalFileObject::Overlay(19)),
        irp_id,
        major: nt_io_abi::major::IRP_MJ_SET_INFORMATION,
        operation: PendingFileIoOperation::OwnedBasicPreflight(PendingOwnedBasicPreflight::new(1)),
        busy: Some(PendingFileBusy::new(FileIoBusyOwner {
            key: FileIoWaitKey::LocalOverlay(19), tid: 23,
            mode: nt_io_completion::FileIoMode::SynchronousNonAlertable,
        })),
        tid: 23,
        iosb_va: 0x2000,
        reply_cap: 41,
        reply_required: true,
        signal_file: true,
        completion_port_suppressed: true,
        event_obj_idx: u64::MAX,
        ..PendingFileIo::default()
    }
}

fn admit_row(table: &mut PendingFileIoTable,
    owners: &mut PendingBasicPreparedTable<FileReference>,
    owner: PendingBasicPreparedOwner<FileReference>,
) -> (PendingFileIoIdentity, u64, PendingFileIoReservation) {
    let reservation = table.reserve().unwrap();
    let irp_id = table.local_operation_id(reservation).unwrap();
    let identity = owners.admit_reserved_exact(table, reservation, basic_row(irp_id), owner)
        .ok().unwrap();
    (identity, irp_id, reservation)
}

#[test]
fn prepared_owner_claims_only_the_exact_pending_row_without_early_delivery() {
    let (fs, handle, input) = prepared();
    let mut pending = PendingFileIoTable::new();
    let drops = Rc::new(Cell::new(0));
    let mut owners = PendingBasicPreparedTable::new();
    let before = fs.query_file_object_information(handle).unwrap().metadata;
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let (identity, irp_id, _) = admit_row(&mut pending, &mut owners, owner);

    let (other_fs, other_handle, other_input) = prepared();
    let mut other_owners = PendingBasicPreparedTable::new();
    let other_owner = PendingBasicPreparedOwner::prepare(&other_fs, other_handle, other_input,
        FileReference(Rc::new(Cell::new(0)))).ok().unwrap();
    let (crossed_row, crossed_irp, _) = admit_row(&mut pending, &mut other_owners, other_owner);
    assert!(owners.claim_exact(&pending, crossed_row, crossed_irp).is_none());
    assert!(owners.claim_exact(&pending, identity, crossed_irp).is_none());
    let claim = owners.claim_exact(&pending, identity, irp_id).unwrap();
    assert!(owners.claim_exact(&pending, identity, irp_id).is_none());
    assert_eq!(owners.claimed_exact(&pending, &claim).unwrap().input(), &input);
    assert_eq!(drops.get(), 0);
    let row = pending.get_exact(identity).unwrap();
    assert_eq!(row.iosb_va, 0x2000);
    assert_eq!(row.reply_cap, 41);
    assert_eq!(row.owned_terminal_result(), None);

    owners.mark_uncertain_exact(&pending, &claim).unwrap();
    assert!(owners.cancel_unentered_exact(&mut pending, identity, irp_id).is_none());
    drop(claim);
    assert_eq!(owners.len(), 1, "a lost claim cannot retire uncertain native ownership");
    assert_eq!(drops.get(), 0);
    assert_eq!(fs.query_file_object_information(handle).unwrap().metadata, before);
    let row = pending.get_exact(identity).unwrap();
    assert_eq!(row.owned_terminal_result(), None);
    assert_eq!((row.iosb_va, row.reply_cap, row.delivery_state), (0x2000, 41, 0));
}

#[test]
fn pre_entry_cancellation_returns_the_file_and_keeps_delivery_owned_by_the_row() {
    let (fs, handle, input) = prepared();
    let mut pending = PendingFileIoTable::new();
    let drops = Rc::new(Cell::new(0));
    let mut owners = PendingBasicPreparedTable::new();
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let (identity, irp_id, _) = admit_row(&mut pending, &mut owners, owner);
    assert!(pending.abandon_transfer_exact(identity.slot(), irp_id).is_some());
    assert!(owners.claim_exact(&pending, identity, irp_id).is_none());
    let owner = owners.cancel_unentered_exact(&mut pending, identity, irp_id).unwrap();
    assert_eq!(owner.input(), &input);
    assert_eq!(owners.len(), 0);
    assert_eq!(drops.get(), 0);
    let row = pending.get_exact(identity).unwrap();
    assert_eq!(row.owned_terminal_result(), Some((nt_status::NtStatus::CANCELLED.raw() as u32, 0)));
    assert_eq!(row.delivery_state, 0);
    assert!(owners.claim_exact(&pending, identity, irp_id).is_none());
    drop(owner);
    assert_eq!(drops.get(), 1);
}

#[test]
fn returning_a_known_basic_terminal_also_settles_its_exact_delivery_row() {
    let (fs, handle, input) = prepared();
    let mut pending = PendingFileIoTable::new();
    let drops = Rc::new(Cell::new(0));
    let mut owners = PendingBasicPreparedTable::new();
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let (identity, irp_id, _) = admit_row(&mut pending, &mut owners, owner);
    let claim = owners.claim_exact(&pending, identity, irp_id).unwrap();

    let terminal = owners.commit_owned_basic_exact(&mut pending, claim, STATUS_SUCCESS).ok().unwrap();
    assert_eq!(pending.get_exact(identity).unwrap().owned_terminal_result(),
        Some((STATUS_SUCCESS, 0)), "returning the move-only owner must settle the same row");
    assert!(pending.get_exact(identity).unwrap().signal_file);
    assert_eq!(drops.get(), 0);
    drop(terminal);
    assert_eq!(drops.get(), 1);
}

#[test]
fn crossed_table_and_duplicate_admission_cannot_take_or_drop_the_original_file() {
    let (fs, handle, input) = prepared();
    let mut pending = PendingFileIoTable::new();
    let drops = Rc::new(Cell::new(0));
    let mut owners = PendingBasicPreparedTable::new();
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let (identity, irp_id, reservation) = admit_row(&mut pending, &mut owners, owner);
    let (other_fs, other_handle, other_input) = prepared();
    let (reason, returned_row, duplicate) = owners.admit_reserved_exact(
        &mut pending, reservation, basic_row(irp_id),
        PendingBasicPreparedOwner::prepare(&other_fs, other_handle, other_input,
            FileReference(Rc::clone(&drops))).ok().unwrap()).err().unwrap();
    assert_eq!(reason, PendingBasicPreparedAdmissionError::SidecarUnavailable);
    assert_eq!(returned_row.irp_id, irp_id);
    assert_eq!(pending.get_exact(identity).unwrap().irp_id, irp_id);
    assert_eq!(drops.get(), 0);
    drop(duplicate);
    assert_eq!(drops.get(), 1);

    let mut peer = PendingBasicPreparedTable::new();
    let mut peer_pending = PendingFileIoTable::new();
    let (peer_fs, peer_handle, peer_input) = prepared();
    let peer_owner = PendingBasicPreparedOwner::prepare(&peer_fs, peer_handle, peer_input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let (peer_identity, _, _) = admit_row(&mut peer_pending, &mut peer, peer_owner);
    let claim = owners.claim_exact(&pending, identity, irp_id).unwrap();
    assert!(peer.claimed_exact(&peer_pending, &claim).is_none());
    let claim = peer.commit_owned_basic_exact(&mut peer_pending, claim, STATUS_SUCCESS).err().unwrap();
    assert_eq!(pending.get_exact(identity).unwrap().owned_terminal_result(), None);
    assert_eq!(peer_pending.get_exact(peer_identity).unwrap().owned_terminal_result(), None);
    let owner = owners.commit_owned_basic_exact(&mut pending, claim, STATUS_SUCCESS).ok().unwrap();
    assert_eq!(owner.input(), &input);
    assert_eq!(owners.len(), 0);
    assert_eq!(drops.get(), 1);
    drop(owner);
    assert_eq!(drops.get(), 2);
    assert_eq!(peer.len(), 1);
}

#[test]
fn uncertain_basic_owner_survives_refusal_until_its_exact_terminal() {
    let (fs, handle, input) = prepared();
    let mut pending = PendingFileIoTable::new();
    let drops = Rc::new(Cell::new(0));
    let mut owners = PendingBasicPreparedTable::new();
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let (identity, irp_id, _) = admit_row(&mut pending, &mut owners, owner);
    let claim = owners.claim_exact(&pending, identity, irp_id).unwrap();
    owners.mark_uncertain_exact(&pending, &claim).unwrap();

    let claim = owners.commit_owned_basic_exact(&mut pending, claim,
        nt_status::NtStatus::PENDING.raw() as u32).err().unwrap();
    assert_eq!(owners.len(), 1);
    assert_eq!(drops.get(), 0);
    assert_eq!(pending.get_exact(identity).unwrap().owned_terminal_result(), None);
    assert!(owners.cancel_unentered_exact(&mut pending, identity, irp_id).is_none());

    let terminal = owners.commit_owned_basic_exact(&mut pending, claim,
        nt_fs::STATUS_INVALID_PARAMETER).ok().unwrap();
    assert_eq!(pending.get_exact(identity).unwrap().owned_terminal_result(),
        Some((nt_fs::STATUS_INVALID_PARAMETER, 0)));
    assert_eq!(pending.get_exact(identity).unwrap().iosb_va, 0);
    assert!(!pending.get_exact(identity).unwrap().signal_file);
    assert_eq!(owners.len(), 0);
    assert_eq!(drops.get(), 0);
    drop(terminal);
    assert_eq!(drops.get(), 1);
}

#[test]
fn failed_preparation_returns_the_native_file_reference() {
    let (fs, _handle, input) = prepared();
    let drops = Rc::new(Cell::new(0));
    let (status, file) = PendingBasicPreparedOwner::prepare(&fs, u64::MAX, input,
        FileReference(Rc::clone(&drops))).err().unwrap();
    assert_eq!(status, nt_fs::STATUS_INVALID_HANDLE);
    assert_eq!(drops.get(), 0);
    drop(file);
    assert_eq!(drops.get(), 1);
}

#[test]
fn full_basic_sidecar_refuses_admission_without_publishing_a_row() {
    let (fs, handle, input) = prepared();
    let mut pending = PendingFileIoTable::new();
    let reservation = pending.reserve().unwrap();
    let identity = reservation.identity();
    let irp_id = pending.local_operation_id(reservation).unwrap();
    let row = basic_row(irp_id);
    let drops = Rc::new(Cell::new(0));
    let mut owners = PendingBasicPreparedTable::with_limit(0);
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();

    // The delivery row and its move-only File owner must be refused together.
    let admission = owners.admit_reserved_exact(&mut pending, reservation, row, owner);
    let (reason, returned_row, returned) = admission.err()
        .expect("the zero-capacity sidecar must refuse admission");

    assert_eq!(reason, PendingBasicPreparedAdmissionError::SidecarUnavailable);
    assert_eq!(returned_row, row, "the Reply-bearing delivery row belongs to the caller");
    assert!(pending.get_exact(identity).is_none(),
        "sidecar refusal must not leave an independently deliverable SET row");
    assert_eq!(pending.len(), 0);
    assert_eq!(pending.local_operation_id(reservation), None);
    let next = pending.reserve().unwrap();
    assert_ne!(next, reservation);
    assert!(pending.cancel_reservation(next));
    assert_eq!(owners.len(), 0);
    assert_eq!(drops.get(), 0, "the refused File reference belongs to the caller");
    drop(returned);
    assert_eq!(drops.get(), 1);
}

#[test]
fn invalid_basic_row_refusal_preserves_park_error_and_both_owners() {
    let (fs, handle, input) = prepared();
    let mut pending = PendingFileIoTable::new();
    let reservation = pending.reserve().unwrap();
    let mut row = basic_row(pending.local_operation_id(reservation).unwrap());
    row.reply_required = false;
    let drops = Rc::new(Cell::new(0));
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let mut owners = PendingBasicPreparedTable::new();

    let (reason, returned_row, returned) = owners
        .admit_reserved_exact(&mut pending, reservation, row, owner).err().unwrap();
    assert_eq!(reason, PendingBasicPreparedAdmissionError::PendingRow(
        PendingFileIoParkError::InvalidRecord));
    assert_eq!(returned_row, row);
    assert!(pending.is_empty());
    assert_eq!(pending.local_operation_id(reservation), None);
    let next = pending.reserve().unwrap();
    assert_ne!(next, reservation);
    assert!(pending.cancel_reservation(next));
    assert_eq!(owners.len(), 0);
    assert_eq!(drops.get(), 0);
    drop(returned);
    assert_eq!(drops.get(), 1);
}

#[test]
fn generically_valid_wrong_operation_cannot_strand_a_basic_sidecar_owner() {
    let (fs, handle, input) = prepared();
    let mut pending = PendingFileIoTable::new();
    let reservation = pending.reserve().unwrap();
    let irp_id = pending.local_operation_id(reservation).unwrap();
    let mut row = basic_row(irp_id);
    row.operation = PendingFileIoOperation::OwnedInline(PendingOwnedInline {
        status: STATUS_SUCCESS, information: 0,
    });

    // The generic table accepts this local SET shape; Basic admission must reject it first.
    let mut generic = PendingFileIoTable::new();
    let generic_reservation = generic.reserve().unwrap();
    let mut generic_row = row;
    generic_row.irp_id = generic.local_operation_id(generic_reservation).unwrap();
    assert!(generic.park_reserved(generic_reservation, generic_row).is_ok());

    let drops = Rc::new(Cell::new(0));
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let mut owners = PendingBasicPreparedTable::new();
    let (reason, returned_row, returned) = owners
        .admit_reserved_exact(&mut pending, reservation, row, owner).err().unwrap();
    assert_eq!(reason, PendingBasicPreparedAdmissionError::PendingRow(
        PendingFileIoParkError::InvalidRecord));
    assert_eq!(returned_row, row);
    assert!(pending.is_empty());
    assert_eq!(pending.local_operation_id(reservation), None);
    assert_eq!(owners.len(), 0);
    assert_eq!(drops.get(), 0);
    drop(returned);
    assert_eq!(drops.get(), 1);
}

#[test]
fn exact_basic_admission_parks_its_row_and_owner() {
    let (fs, handle, input) = prepared();
    let mut pending = PendingFileIoTable::new();
    let reservation = pending.reserve().unwrap();
    let identity = reservation.identity();
    let irp_id = pending.local_operation_id(reservation).unwrap();
    let drops = Rc::new(Cell::new(0));
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let mut owners = PendingBasicPreparedTable::new();

    assert_eq!(owners.admit_reserved_exact(&mut pending, reservation,
        basic_row(irp_id), owner).ok(), Some(identity));
    assert_eq!(pending.len(), 1);
    assert_eq!(owners.len(), 1);
    assert_eq!(pending.get_exact(identity).unwrap().irp_id, irp_id);
    let claim = owners.claim_exact(&pending, identity, irp_id).unwrap();
    assert_eq!(owners.claimed_exact(&pending, &claim).unwrap().input(), &input);
    assert_eq!(drops.get(), 0);
}

#[test]
fn native_admission_refusal_keeps_its_exact_reservation_for_a_real_terminal() {
    let (fs, handle, input) = prepared();
    let mut pending = PendingFileIoTable::new();
    let reservation = pending.reserve().unwrap();
    let irp_id = pending.local_operation_id(reservation).unwrap();
    let row = basic_row(irp_id);
    let before = fs.query_file_object_information(handle).unwrap().metadata;
    let drops = Rc::new(Cell::new(0));
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let mut owners = PendingBasicPreparedTable::with_limit(0);

    let (reason, mut returned_row, returned_owner) = owners
        .try_admit_reserved_exact(&mut pending, reservation, row, owner).err().unwrap();
    assert_eq!(reason, PendingBasicPreparedAdmissionError::SidecarUnavailable);
    assert_eq!(pending.local_operation_id(reservation), Some(irp_id));
    assert_eq!(pending.len(), 0);
    assert!(pending.get_exact(reservation.identity()).is_none());
    assert_eq!(fs.query_file_object_information(handle).unwrap().metadata, before);
    assert_eq!(drops.get(), 0);

    returned_row.operation = PendingFileIoOperation::OwnedInline(PendingOwnedInline {
        status: nt_status::NtStatus::INSUFFICIENT_RESOURCES.raw() as u32,
        information: 0,
    });
    assert!(pending.park_reserved(reservation, returned_row).is_ok());
    assert_eq!(pending.get_exact(reservation.identity()).unwrap().reply_cap, 41);
    assert_eq!(drops.get(), 0, "the fallback row still owns its File reference");
    drop(returned_owner.into_file());
    assert_eq!(drops.get(), 1);
}

#[test]
fn prepared_basic_snapshot_apply_records_one_terminal_across_redrive() {
    let (mut fs, handle, input) = prepared();
    let before = fs.query_file_object_information(handle).unwrap().metadata;
    let drops = Rc::new(Cell::new(0));
    let mut pending = PendingFileIoTable::new();
    let mut owners = PendingBasicPreparedTable::new();
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let (identity, irp_id, _) = admit_row(&mut pending, &mut owners, owner);
    let claim = owners.claim_exact(&pending, identity, irp_id).unwrap();

    let first = owners.apply_snapshot_claimed_exact(&pending, &claim, &mut fs).unwrap();
    assert_eq!(first, (STATUS_SUCCESS, true, true));
    let after = fs.query_file_object_information(handle).unwrap().metadata;
    assert_ne!(after, before);
    assert_eq!(after.last_write_time, 777);
    assert_eq!(owners.apply_snapshot_claimed_exact(&pending, &claim, &mut fs),
        Some((STATUS_SUCCESS, true, false)));
    assert_eq!(fs.query_file_object_information(handle).unwrap().metadata, after);
    assert_eq!(drops.get(), 0);

    let terminal = owners.commit_owned_basic_exact(&mut pending, claim, first.0).ok().unwrap();
    assert_eq!(pending.get_exact(identity).unwrap().owned_terminal_result(), Some((first.0, 0)));
    drop(terminal.into_file());
    assert_eq!(drops.get(), 1);
}

#[test]
fn no_effect_basic_claim_refusal_can_cancel_without_losing_file_or_reply() {
    let (fs, handle, input) = prepared();
    let before = fs.query_file_object_information(handle).unwrap().metadata;
    let drops = Rc::new(Cell::new(0));
    let mut pending = PendingFileIoTable::new();
    let mut owners = PendingBasicPreparedTable::new();
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let (identity, irp_id, _) = admit_row(&mut pending, &mut owners, owner);
    let claim = owners.claim_exact(&pending, identity, irp_id).unwrap();
    assert_eq!(owners.release_unentered_claim_exact(&pending, &claim), Some(()));
    assert!(owners.reclaim_applied_exact(&pending, identity, irp_id).is_none());
    let abandoned = pending.abandon_transfer_exact(identity.slot(), irp_id).unwrap();
    assert_eq!(abandoned.reply_cap, 41,
        "the cancelled caller's exact Reply is returned to teardown");

    let returned = owners.cancel_unentered_exact(&mut pending, identity, irp_id).unwrap();
    assert_eq!(pending.get_exact(identity).unwrap().owned_terminal_result(),
        Some((nt_status::NtStatus::CANCELLED.raw() as u32, 0)));
    let terminal = pending.get_exact(identity).unwrap();
    assert_eq!(terminal.reply_cap, 0);
    assert_eq!(terminal.iosb_va, 0);
    assert!(!terminal.signal_file);
    assert_eq!(fs.query_file_object_information(handle).unwrap().metadata, before);
    assert_eq!(drops.get(), 0);
    drop(returned.into_file());
    assert_eq!(drops.get(), 1);
}

#[test]
fn overlapping_basic_set_rebases_captured_input_on_the_same_file() {
    let (mut fs, handle, input) = prepared();
    let file = FileReference(Rc::new(Cell::new(0)));
    let mut owner = PendingBasicPreparedOwner::prepare(&fs, handle, input, file).ok().unwrap();
    let mut intervening = [0u8; 40];
    intervening[..8].copy_from_slice(&888u64.to_le_bytes());
    assert_eq!(fs.zw_set_information_file(handle, nt_fs::FILE_BASIC_INFORMATION,
        &intervening), STATUS_SUCCESS);

    assert_eq!(owner.apply_snapshot_once(&mut fs), (STATUS_SUCCESS, true));
    let metadata = fs.query_file_object_information(handle).unwrap().metadata;
    assert_eq!(metadata.creation_time, 888,
        "the parked Basic input must preserve a newer independent time field");
    assert_eq!(metadata.last_write_time, 777);
    assert_eq!(owner.apply_snapshot_once(&mut fs), (STATUS_SUCCESS, true));
    assert_eq!(fs.query_file_object_information(handle).unwrap().metadata, metadata);
}

#[test]
fn overlapping_rename_rebases_basic_without_restoring_the_old_path() {
    let (mut fs, handle, input) = prepared();
    let file = FileReference(Rc::new(Cell::new(0)));
    let mut owner = PendingBasicPreparedOwner::prepare(&fs, handle, input, file).ok().unwrap();
    let target: Vec<u8> = "Moved.txt".encode_utf16().flat_map(u16::to_le_bytes).collect();
    assert_eq!(fs.zw_rename_file(handle, nt_fs::FileRenameRoot::SourceParent,
        &target, false), STATUS_SUCCESS);
    let renamed = fs.query_opened_name(handle).unwrap();

    assert_eq!(owner.apply_snapshot_once(&mut fs), (STATUS_SUCCESS, true));
    assert_eq!(fs.query_opened_name(handle).unwrap(), renamed);
    assert_eq!(fs.query_file_object_information(handle).unwrap().metadata.last_write_time, 777);
}

#[test]
fn basic_sidecar_capacity_refuses_before_file_retain_or_signal_reset() {
    let (fs, handle, _) = prepared();
    let before = fs.query_file_object_information(handle).unwrap().metadata;
    let mut pending = PendingFileIoTable::new();
    let primary = pending.reserve_basic_primary().unwrap();
    let mut owners = PendingBasicPreparedTable::<FileReference>::with_limit(0);

    assert!(owners.reserve_admission().is_none());
    assert!(pending.cancel_basic_primary(primary));
    assert_eq!(pending.len(), 0);
    assert_eq!(fs.query_file_object_information(handle).unwrap().metadata, before);
}

#[test]
fn pre_reserved_basic_admits_one_exact_row_without_a_spare_file_slot() {
    let (fs, handle, input) = prepared();
    let drops = Rc::new(Cell::new(0));
    let mut pending = PendingFileIoTable::new();
    let primary = pending.reserve_basic_primary().unwrap();
    let irp_id = pending.basic_primary_local_operation_id(&primary).unwrap();
    let mut owners = PendingBasicPreparedTable::new();
    let sidecar = owners.reserve_admission().unwrap();
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();

    let identity = owners.try_admit_pre_reserved_exact(&mut pending, sidecar,
        primary, basic_row(irp_id), owner).ok().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(owners.len(), 1);
    assert_eq!(pending.get_exact(identity).unwrap().irp_id, irp_id);
    assert_eq!(pending.get_exact(identity).unwrap().reply_cap, 41);
    assert_eq!(drops.get(), 0);
    let next = pending.reserve().unwrap();
    assert_eq!(next.identity().slot(), identity.slot() + 1);
    assert!(pending.cancel_reservation(next));
}

#[test]
fn unused_basic_pair_cancels_without_metadata_effect_or_capacity_loss() {
    let (fs, handle, _) = prepared();
    let before = fs.query_file_object_information(handle).unwrap().metadata;
    let mut pending = PendingFileIoTable::new();
    let primary = pending.reserve_basic_primary().unwrap();
    let identity = primary.identity();
    let mut owners = PendingBasicPreparedTable::<FileReference>::with_limit(1);
    let sidecar = owners.reserve_admission().unwrap();
    assert!(owners.reserve_admission().is_none());

    assert!(owners.cancel_admission(sidecar));
    assert!(pending.cancel_basic_primary(primary));
    let reused_sidecar = owners.reserve_admission().unwrap();
    assert!(owners.cancel_admission(reused_sidecar));
    let reused = pending.reserve().unwrap();
    assert_eq!(reused.identity().slot(), identity.slot());
    assert!(pending.cancel_reservation(reused));
    assert_eq!(fs.query_file_object_information(handle).unwrap().metadata, before);
}

#[test]
fn basic_preparation_error_uses_the_same_primary_inline_terminal() {
    let mut pending = PendingFileIoTable::new();
    let primary = pending.reserve_basic_primary().unwrap();
    let irp_id = pending.basic_primary_local_operation_id(&primary).unwrap();
    let mut owners = PendingBasicPreparedTable::<FileReference>::new();
    let sidecar = owners.reserve_admission().unwrap();
    assert!(owners.cancel_admission(sidecar));
    let mut row = basic_row(irp_id);
    row.operation = PendingFileIoOperation::OwnedInline(PendingOwnedInline {
        status: nt_fs::STATUS_INVALID_PARAMETER, information: 0,
    });
    row.iosb_va = 0;
    row.signal_file = false;

    let identity = pending.try_park_basic_primary(primary, row).ok().unwrap();
    let terminal = pending.get_exact(identity).unwrap();
    assert_eq!(terminal.owned_terminal_result(), Some((nt_fs::STATUS_INVALID_PARAMETER, 0)));
    assert_eq!(terminal.reply_cap, 41);
    assert_eq!(pending.len(), 1);
    assert_eq!(owners.len(), 0);
}

#[test]
fn malformed_basic_commit_returns_both_exact_claims_reply_and_file() {
    let (fs, handle, input) = prepared();
    let drops = Rc::new(Cell::new(0));
    let mut pending = PendingFileIoTable::new();
    let primary = pending.reserve_basic_primary().unwrap();
    let irp_id = pending.basic_primary_local_operation_id(&primary).unwrap();
    let mut owners = PendingBasicPreparedTable::new();
    let sidecar = owners.reserve_admission().unwrap();
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let mut malformed = basic_row(irp_id);
    malformed.busy = Some(PendingFileBusy::new(FileIoBusyOwner {
        key: FileIoWaitKey::LocalOverlay(999), tid: 23,
        mode: nt_io_completion::FileIoMode::SynchronousNonAlertable,
    }));

    let (error, returned, owner, primary, sidecar) = owners
        .try_admit_pre_reserved_exact(&mut pending, sidecar, primary,
            malformed, owner).err().unwrap();
    assert_eq!(error, PendingBasicPreparedAdmissionError::PendingRow(
        PendingFileIoParkError::InvalidRecord));
    assert_eq!(returned, malformed);
    assert_eq!(returned.reply_cap, 41);
    assert!(pending.get_exact(primary.identity()).is_none());
    assert_eq!(owners.len(), 0);
    assert_eq!(drops.get(), 0);
    assert!(owners.cancel_admission(sidecar));
    assert!(pending.cancel_basic_primary(primary));
    drop(owner.into_file());
    assert_eq!(drops.get(), 1);
}
