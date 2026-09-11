use super::super::*;

fn transfer() -> PendingFileIo {
    PendingFileIo {
        route: PendingFileRoute::Hosted(7),
        irp_id: 10,
        major: nt_io_abi::major::IRP_MJ_READ,
        tid: 13,
        event_obj_idx: u64::MAX,
        ..PendingFileIo::default()
    }
}

fn create() -> PendingFileIo {
    PendingFileIo {
        major: nt_io_abi::major::IRP_MJ_CREATE,
        operation: PendingFileIoOperation::Create(PendingFileCreate {
            handle_va: 0x1000,
            reservation_pid: 1,
            reserved_handle: 4,
            reservation_generation: 1,
            status: nt_status::NtStatus::PENDING.raw() as u32,
            ..PendingFileCreate::default()
        }),
        iosb_va: 0x2000,
        ..transfer()
    }
}

#[test]
fn reservation_identity_becomes_visible_only_after_successful_publication() {
    let mut table = PendingFileIoTable::new();
    let reservation = table.reserve().unwrap();
    let identity = reservation.identity();
    assert_eq!(table.identity(identity.slot()), None);
    assert_eq!(table.get_exact(identity), None);
    assert_eq!(table.drain_exact().count(), 0);
    assert_eq!(
        table.park_reserved(reservation, PendingFileIo::default()),
        Err(PendingFileIoParkError::InvalidRecord)
    );
    assert_eq!(table.get_exact(identity), None);
    let pending = transfer();
    assert_eq!(
        table.park_reserved(reservation, pending),
        Ok(identity.slot())
    );
    assert_eq!(table.identity(identity.slot()), Some(identity));
    assert_eq!(table.get_exact(identity), Some(pending));
    assert_eq!(
        table.drain_exact().collect::<Vec<_>>(),
        [(identity, pending)]
    );
    assert!(!table.cancel_reservation(reservation));
}

#[test]
fn foreign_identity_cannot_read_or_mutate_equal_numeric_owner() {
    let mut first = PendingFileIoTable::new();
    let mut second = PendingFileIoTable::new();
    let a = first.park(transfer()).unwrap();
    let b = second.park(transfer()).unwrap();
    let foreign = first.identity(a).unwrap();
    let local = second.identity(b).unwrap();
    assert_eq!(foreign.slot, local.slot);
    assert_eq!(foreign.generation, local.generation);
    assert_ne!(foreign.table, local.table);
    second.mark_backend_acked_exact(b, 10).unwrap();
    let before = second.get_exact(local).unwrap();
    assert_eq!(second.get_exact(foreign), None);
    assert_eq!(second.abandon_transfer_owner_exact(foreign, 10), None);
    assert_eq!(second.finish_owner_exact(foreign, 10), None);
    assert_eq!(second.get_exact(local), Some(before));
    assert!(second.finish_owner_exact(local, 10).is_some());
}

#[test]
fn same_irp_thread_and_reply_reuse_never_reauthorizes_previous_identity() {
    let pending = PendingFileIo {
        reply_cap: 77,
        reply_required: true,
        native_call_transport: true,
        ..transfer()
    };
    let mut table = PendingFileIoTable::new();
    let slot = table.park(pending).unwrap();
    let old = table.identity(slot).unwrap();
    assert_eq!(table.claim_reply_cap_exact(slot, 10), Some(Some(77)));
    table.mark_reply_published_exact(slot, 10).unwrap();
    table.mark_backend_acked_exact(slot, 10).unwrap();
    assert!(table.finish_owner_exact(old, 10).is_some());
    assert_eq!(table.owner_generations[slot], 0);
    assert_eq!(table.identity(slot), None);
    assert_eq!(table.park(pending), Some(slot));
    let current = table.identity(slot).unwrap();
    assert_ne!(old, current);
    assert_eq!(table.get_exact(old), None);
    assert_eq!(table.abandon_transfer_owner_exact(old, 10), None);
    assert_eq!(table.finish_owner_exact(old, 10), None);
    assert_eq!(table.get_exact(current), Some(pending));
}

#[test]
fn moves_preserve_identity_but_reset_and_reuse_do_not() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(transfer()).unwrap();
    let old = table.identity(slot).unwrap();
    let mut moved = alloc::boxed::Box::new(table);
    assert_eq!(moved.get_exact(old), Some(transfer()));
    assert!(!moved.reset());
    moved.mark_backend_acked_exact(slot, 10).unwrap();
    moved.finish_owner_exact(old, 10).unwrap();
    assert!(moved.reset());
    assert!(moved.owner_generations.is_empty());
    let slot = moved.park(transfer()).unwrap();
    let new = moved.identity(slot).unwrap();
    assert_eq!(old.table, new.table);
    assert_eq!(old.slot, new.slot);
    assert_ne!(old.generation, new.generation);
    assert_eq!(moved.get_exact(old), None);
}

#[test]
fn local_zero_file_namespaces_have_full_non_busy_owner_identity() {
    let mut table = PendingFileIoTable::new();
    for (index, file) in [
        LocalFileObject::ReadonlyFile(0),
        LocalFileObject::ReadonlyDirectory(0),
        LocalFileObject::Overlay(0),
        LocalFileObject::Overlay(u64::MAX),
    ]
    .into_iter()
    .enumerate()
    {
        let pending = PendingFileIo {
            route: PendingFileRoute::Local(file),
            irp_id: 10 + index as u64,
            operation: PendingFileIoOperation::LocalInline(PendingLocalInline::default()),
            ..transfer()
        };
        let reservation = table.reserve().unwrap();
        let identity = reservation.identity();
        assert!(table.park_reserved(reservation, pending).is_ok());
        assert_eq!(table.get_exact(identity), Some(pending));
        assert!(table.get_exact(identity).unwrap().busy.is_none());
    }
    assert_eq!(table.drain_exact().count(), 4);
}

#[test]
fn retarget_preserves_owner_but_rejects_stale_irp_phase_and_foreign_identity() {
    let pending = PendingFileIo {
        major: nt_io_abi::major::IRP_MJ_QUERY_INFORMATION,
        operation: PendingFileIoOperation::SetFileName(PendingSetFileNameOperation {
            transaction_id: 1,
            target_file_id: 0,
        }),
        iosb_va: 0x2000,
        native_call_transport: true,
        resume_ip: 0x3000,
        resume_sp: 0x4000,
        resume_flags: 0x202,
        ..transfer()
    };
    let mut table = PendingFileIoTable::new();
    let mut other = PendingFileIoTable::new();
    let slot = table.park(pending).unwrap();
    let identity = table.identity(slot).unwrap();
    let other_slot = other.park(pending).unwrap();
    let foreign = other.identity(other_slot).unwrap();
    assert_eq!(
        table.retarget_set_file_name_query_owner_exact(
            foreign,
            10,
            11,
            nt_io_abi::major::IRP_MJ_CREATE,
            8,
        ),
        None
    );
    table
        .retarget_set_file_name_query_owner_exact(
            identity,
            10,
            11,
            nt_io_abi::major::IRP_MJ_CREATE,
            8,
        )
        .unwrap();
    assert_eq!(table.identity(slot), Some(identity));
    let target_create = table.get_exact(identity).unwrap();
    assert_eq!(target_create.irp_id, 11);
    assert!(target_create.native_call_transport);
    assert_eq!(target_create.resume_ip, pending.resume_ip);
    assert_eq!(target_create.resume_sp, pending.resume_sp);
    assert_eq!(target_create.resume_flags, pending.resume_flags);
    assert_eq!(table.abandon_transfer_owner_exact(identity, 10), None);
    assert_eq!(
        table.retarget_set_file_name_irp_owner_exact(foreign, 11, 12),
        None
    );
    assert_eq!(
        table.retarget_set_file_name_irp_owner_exact(identity, 10, 12),
        None
    );
    table
        .retarget_set_file_name_irp_owner_exact(identity, 11, 12)
        .unwrap();
    assert_eq!(table.identity(slot), Some(identity));
    let source_set = table.get_exact(identity).unwrap();
    assert_eq!(source_set.irp_id, 12);
    assert!(source_set.native_call_transport);
    assert_eq!(source_set.resume_ip, pending.resume_ip);
    assert_eq!(source_set.resume_sp, pending.resume_sp);
    assert_eq!(source_set.resume_flags, pending.resume_flags);
}

#[test]
fn abandonment_keeps_identity_and_enforces_existing_reply_claim_policy() {
    let pending = PendingFileIo {
        reply_cap: 77,
        reply_required: true,
        native_call_transport: true,
        ..transfer()
    };
    let mut table = PendingFileIoTable::new();
    let slot = table.park(pending).unwrap();
    let identity = table.identity(slot).unwrap();
    assert_eq!(table.claim_reply_cap_exact(slot, 10), Some(Some(77)));
    assert_eq!(table.abandon_transfer_owner_exact(identity, 10), None);
    table.restore_reply_cap_exact(slot, 10, 77).unwrap();
    assert_eq!(
        table.abandon_transfer_owner_exact(identity, 10),
        Some(pending)
    );
    let abandoned = table.get_exact(identity).unwrap();
    assert!(abandoned.consumer_abandoned);
    assert!(!abandoned.native_call_transport);
    assert_eq!(table.identity(slot), Some(identity));
    assert_eq!(table.abandon_transfer_owner_exact(identity, 10), None);
}

#[test]
fn every_specialized_or_legacy_removal_clears_owner_generation() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(create()).unwrap();
    let first = table.identity(slot).unwrap();
    assert_eq!(table.take_create_owner_exact(first, 11), None);
    assert!(table.take_create_owner_exact(first, 10).is_some());
    assert_eq!(table.owner_generations[slot], 0);
    assert_eq!(table.park(create()), Some(slot));
    let second = table.identity(slot).unwrap();
    assert_eq!(table.take_create_owner_exact(first, 10), None);
    assert_eq!(table.take_thread_creates_with(13, |_| {}), 1);
    assert_eq!(table.owner_generations[slot], 0);
    assert_eq!(table.get_exact(second), None);
    assert_eq!(table.park(transfer()), Some(slot));
    let third = table.identity(slot).unwrap();
    assert_eq!(table.take_thread_with(13, |_| {}), 1);
    assert_eq!(table.owner_generations[slot], 0);
    assert_eq!(table.get_exact(third), None);
    assert!(table.is_empty());
    assert!(table.reset());
}
