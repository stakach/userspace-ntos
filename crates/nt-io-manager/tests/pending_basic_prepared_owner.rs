use std::cell::Cell;
use std::rc::Rc;

use nt_fs::{FileSystem, MemFs, FILE_CREATE, FILE_NON_DIRECTORY_FILE,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA, STATUS_SUCCESS,
    SYNCHRONIZE};
use nt_io_manager::{FileIoBusyOwner, FileIoWaitKey, LocalFileObject, PendingBasicPreparedOwner,
    PendingBasicPreparedTable, PendingFileBusy, PendingFileIo, PendingFileIoIdentity,
    PendingFileIoOperation, PendingFileIoTable, PendingFileRoute, PendingOwnedBasicPreflight};

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

fn park_row(table: &mut PendingFileIoTable) -> (PendingFileIoIdentity, u64) {
    let reservation = table.reserve().unwrap();
    let irp_id = table.local_operation_id(reservation).unwrap();
    let row = PendingFileIo {
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
        completion_port_suppressed: true,
        event_obj_idx: u64::MAX,
        ..PendingFileIo::default()
    };
    let slot = table.park_reserved(reservation, row).unwrap();
    (table.identity(slot).unwrap(), irp_id)
}

#[test]
fn prepared_owner_claims_only_the_exact_pending_row_without_early_delivery() {
    let (fs, handle, input) = prepared();
    let mut pending = PendingFileIoTable::new();
    let (identity, irp_id) = park_row(&mut pending);
    let drops = Rc::new(Cell::new(0));
    let mut owners = PendingBasicPreparedTable::new();
    let before = fs.query_file_object_information(handle).unwrap().metadata;
    assert!(owners.park_exact(&pending, identity, irp_id,
        PendingBasicPreparedOwner::prepare(&fs, handle, input,
            FileReference(Rc::clone(&drops))).ok().unwrap()).is_ok());

    let (crossed_row, crossed_irp) = park_row(&mut pending);
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
    let (identity, irp_id) = park_row(&mut pending);
    let drops = Rc::new(Cell::new(0));
    let mut owners = PendingBasicPreparedTable::new();
    assert!(owners.park_exact(&pending, identity, irp_id,
        PendingBasicPreparedOwner::prepare(&fs, handle, input,
            FileReference(Rc::clone(&drops))).ok().unwrap()).is_ok());
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
fn crossed_table_and_duplicate_park_cannot_take_or_drop_the_original_file() {
    let (fs, handle, input) = prepared();
    let mut pending = PendingFileIoTable::new();
    let (identity, irp_id) = park_row(&mut pending);
    let drops = Rc::new(Cell::new(0));
    let mut owners = PendingBasicPreparedTable::new();
    assert!(owners.park_exact(&pending, identity, irp_id,
        PendingBasicPreparedOwner::prepare(&fs, handle, input,
            FileReference(Rc::clone(&drops))).ok().unwrap()).is_ok());
    let (other_fs, other_handle, other_input) = prepared();
    let duplicate = owners.park_exact(&pending, identity, irp_id,
        PendingBasicPreparedOwner::prepare(&other_fs, other_handle, other_input,
            FileReference(Rc::clone(&drops))).ok().unwrap()).err().unwrap();
    assert_eq!(drops.get(), 0);
    drop(duplicate);
    assert_eq!(drops.get(), 1);

    let mut peer = PendingBasicPreparedTable::new();
    let (peer_fs, peer_handle, peer_input) = prepared();
    assert!(peer.park_exact(&pending, identity, irp_id,
        PendingBasicPreparedOwner::prepare(&peer_fs, peer_handle, peer_input,
            FileReference(Rc::clone(&drops))).ok().unwrap()).is_ok());
    let claim = owners.claim_exact(&pending, identity, irp_id).unwrap();
    assert!(peer.claimed_exact(&pending, &claim).is_none());
    let claim = peer.take_terminal_exact(&pending, claim).err().unwrap();
    let owner = owners.take_terminal_exact(&pending, claim).ok().unwrap();
    assert_eq!(owner.input(), &input);
    assert_eq!(owners.len(), 0);
    assert_eq!(drops.get(), 1);
    drop(owner);
    assert_eq!(drops.get(), 2);
    assert_eq!(peer.len(), 1);
}

#[test]
fn failed_preparation_and_full_sidecar_return_the_native_file_reference() {
    let (fs, handle, input) = prepared();
    let drops = Rc::new(Cell::new(0));
    let (status, file) = PendingBasicPreparedOwner::prepare(&fs, u64::MAX, input,
        FileReference(Rc::clone(&drops))).err().unwrap();
    assert_eq!(status, nt_fs::STATUS_INVALID_HANDLE);
    assert_eq!(drops.get(), 0);
    drop(file);
    assert_eq!(drops.get(), 1);

    let mut pending = PendingFileIoTable::new();
    let (identity, irp_id) = park_row(&mut pending);
    let owner = PendingBasicPreparedOwner::prepare(&fs, handle, input,
        FileReference(Rc::clone(&drops))).ok().unwrap();
    let mut owners = PendingBasicPreparedTable::with_limit(0);
    let owner = owners.park_exact(&pending, identity, irp_id, owner).err().unwrap();
    assert_eq!(owners.len(), 0);
    assert_eq!(drops.get(), 1);
    drop(owner);
    assert_eq!(drops.get(), 2);
}
