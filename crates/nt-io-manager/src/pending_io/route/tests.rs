use super::*;
use crate::pending_io::*;

const IRP: u64 = 41;
const TID: u64 = 42;

fn inline(file: LocalFileObject) -> PendingFileIo {
    PendingFileIo {
        route: PendingFileRoute::Local(file),
        irp_id: IRP,
        major: nt_io_abi::major::IRP_MJ_READ,
        operation: PendingFileIoOperation::LocalInline(PendingLocalInline {
            status: 0,
            information: 0,
        }),
        tid: TID,
        event_obj_idx: u64::MAX,
        ..PendingFileIo::default()
    }
}

fn notification(file: LocalFileObject) -> PendingFileIo {
    PendingFileIo {
        major: nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL,
        operation: PendingFileIoOperation::LocalDirectoryNotify(PendingLocalDirectoryNotify {
            notify_id: 43,
            status: 0x103,
            information: 0,
            alertable: true,
        }),
        iosb_va: 0x1000,
        reply_cap: 44,
        reply_required: true,
        ..inline(file)
    }
}

#[test]
fn local_zero_is_valid_in_each_independent_file_object_namespace() {
    for file in [
        LocalFileObject::ReadonlyFile(0),
        LocalFileObject::ReadonlyDirectory(0),
        LocalFileObject::Overlay(0),
    ] {
        let mut table = PendingFileIoTable::new();
        let slot = table.park(inline(file)).unwrap();
        let pending = table.get(slot).unwrap();
        assert_eq!(pending.local_file_object(), Some(file));
        assert_eq!(pending.hosted_file_id(), None);
        assert!(pending.is_local());
        assert!(table.completion_surfaces_settled_exact(slot, IRP));
        table.mark_backend_acked_exact(slot, IRP).unwrap();
        table
            .mark_local_reference_released_exact(slot, IRP)
            .unwrap();
        assert_eq!(
            table.finish_exact(slot, IRP).unwrap().route,
            PendingFileRoute::Local(file)
        );
    }
}

#[test]
fn default_and_zero_hosted_routes_are_invalid_without_consuming_reservations() {
    let mut table = PendingFileIoTable::new();
    let claim = table.reserve().unwrap();
    let mut pending = inline(LocalFileObject::Overlay(0));
    pending.operation = PendingFileIoOperation::Transfer;
    pending.route = PendingFileRoute::default();
    assert_eq!(pending.route, PendingFileRoute::Hosted(0));
    assert_eq!(
        table.park_reserved(claim, pending),
        Err(PendingFileIoParkError::InvalidRecord)
    );
    assert!(table.local_operation_id(claim).is_some());
    pending.route = PendingFileRoute::Hosted(1);
    assert!(table.park_reserved(claim, pending).is_ok());
}

#[test]
fn same_numeric_hosted_file_readonly_file_directory_and_overlay_are_distinct() {
    let routes = [
        PendingFileRoute::Hosted(7),
        PendingFileRoute::Local(LocalFileObject::ReadonlyFile(7)),
        PendingFileRoute::Local(LocalFileObject::ReadonlyDirectory(7)),
        PendingFileRoute::Local(LocalFileObject::Overlay(7)),
    ];
    for (index, route) in routes.iter().enumerate() {
        for (other_index, other) in routes.iter().enumerate() {
            assert_eq!(route == other, index == other_index);
        }
    }
}

#[test]
fn every_local_route_rejects_provider_completion_even_when_numbers_match() {
    for file in [
        LocalFileObject::ReadonlyFile(7),
        LocalFileObject::ReadonlyDirectory(7),
        LocalFileObject::Overlay(7),
    ] {
        let mut table = PendingFileIoTable::new();
        let slot = table.park(inline(file)).unwrap();
        assert!(!table.matches_completion_exact(slot, IRP, 7, TID, nt_io_abi::major::IRP_MJ_READ));
    }
}

#[test]
fn hosted_and_overlay_u64_identities_never_lose_high_bits() {
    for id in [1, 0x1000_0000_0000_0000, 0xffff_ffff_0000_0000, u64::MAX] {
        let mut table = PendingFileIoTable::new();
        let slot = table.park(inline(LocalFileObject::Overlay(id))).unwrap();
        assert_eq!(
            table.get(slot).unwrap().local_file_object(),
            Some(LocalFileObject::Overlay(id))
        );
        let mut hosted = inline(LocalFileObject::Overlay(0));
        hosted.route = PendingFileRoute::Hosted(id);
        hosted.operation = PendingFileIoOperation::Transfer;
        hosted.irp_id += 1;
        let slot = table.park(hosted).unwrap();
        assert_eq!(table.get(slot).unwrap().hosted_file_id(), Some(id));
        assert!(table.matches_completion_exact(
            slot,
            IRP + 1,
            id,
            TID,
            nt_io_abi::major::IRP_MJ_READ
        ));
    }
}

#[test]
fn readonly_object_numbers_preserve_the_entire_u32_range() {
    for file in [
        LocalFileObject::ReadonlyFile(u32::MAX),
        LocalFileObject::ReadonlyDirectory(u32::MAX),
    ] {
        let mut table = PendingFileIoTable::new();
        let slot = table.park(inline(file)).unwrap();
        assert_eq!(table.get(slot).unwrap().local_file_object(), Some(file));
    }
}

#[test]
fn route_and_operation_domains_must_agree_before_owner_publication() {
    let local = LocalFileObject::Overlay(7);
    let mut local_on_hosted = inline(local);
    local_on_hosted.route = PendingFileRoute::Hosted(7);
    let mut provider_on_local = inline(local);
    provider_on_local.operation = PendingFileIoOperation::Transfer;
    let mut table = PendingFileIoTable::new();
    let claim = table.reserve().unwrap();
    for pending in [local_on_hosted, provider_on_local] {
        assert_eq!(
            table.park_reserved(claim, pending),
            Err(PendingFileIoParkError::InvalidRecord)
        );
        assert!(table.local_operation_id(claim).is_some());
    }
    assert!(table.park_reserved(claim, inline(local)).is_ok());
}

#[test]
fn byte_lock_rejects_readonly_directory_but_accepts_file_and_overlay() {
    for (file, allowed) in [
        (LocalFileObject::ReadonlyFile(0), true),
        (LocalFileObject::ReadonlyDirectory(0), false),
        (LocalFileObject::Overlay(0), true),
    ] {
        let mut pending = inline(file);
        pending.major = nt_io_abi::major::IRP_MJ_LOCK_CONTROL;
        pending.operation = PendingFileIoOperation::LocalByteLock(PendingLocalByteLock {
            wait_id: 1,
            status: 0x103,
            alertable: false,
        });
        pending.iosb_va = 0x1000;
        assert_eq!(PendingFileIoTable::new().park(pending).is_some(), allowed);
    }
}

#[test]
fn notification_rejects_readonly_file_but_accepts_directory_and_overlay() {
    for (file, allowed) in [
        (LocalFileObject::ReadonlyFile(0), false),
        (LocalFileObject::ReadonlyDirectory(0), true),
        (LocalFileObject::Overlay(0), true),
    ] {
        assert_eq!(
            PendingFileIoTable::new().park(notification(file)).is_some(),
            allowed
        );
    }
}

#[test]
fn buffered_read_and_directory_query_do_not_cross_readonly_object_tables() {
    for major in [
        nt_io_abi::major::IRP_MJ_READ,
        nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL,
    ] {
        for file in [
            LocalFileObject::ReadonlyFile(0),
            LocalFileObject::ReadonlyDirectory(0),
            LocalFileObject::Overlay(0),
        ] {
            let mut table = PendingFileIoTable::new();
            let claim = table.reserve().unwrap();
            let mut pending = inline(file);
            pending.irp_id = table.local_operation_id(claim).unwrap();
            pending.major = major;
            pending.operation = PendingFileIoOperation::LocalBuffered(PendingLocalBuffered {
                status: 0,
                information: 0,
            });
            table.reserve_local_output(claim, 0).unwrap();
            let allowed = match file {
                LocalFileObject::ReadonlyFile(_) => major == nt_io_abi::major::IRP_MJ_READ,
                LocalFileObject::ReadonlyDirectory(_) => {
                    major == nt_io_abi::major::IRP_MJ_DIRECTORY_CONTROL
                }
                LocalFileObject::Overlay(_) => true,
            };
            assert_eq!(table.park_reserved(claim, pending).is_ok(), allowed);
        }
    }
}

#[test]
fn retained_flush_requires_overlay_backing_and_keeps_zero_object_identity() {
    for (file, allowed) in [
        (LocalFileObject::ReadonlyFile(0), false),
        (LocalFileObject::ReadonlyDirectory(0), false),
        (LocalFileObject::Overlay(0), true),
    ] {
        let mut table = PendingFileIoTable::new();
        let claim = table.reserve().unwrap();
        let mut pending = inline(file);
        pending.irp_id = table.local_operation_id(claim).unwrap();
        pending.major = nt_io_abi::major::IRP_MJ_FLUSH_BUFFERS;
        pending.operation = PendingFileIoOperation::LocalFlush(
            PendingLocalFlush::new(0, LocalFlushMode::SynchronousApi).unwrap(),
        );
        pending.iosb_va = 0x1000;
        pending.completion_port_suppressed = true;
        assert_eq!(table.park_reserved(claim, pending).is_ok(), allowed);
    }
}

#[test]
fn apc_interruption_matches_the_full_route_not_only_its_object_number() {
    let route = PendingFileRoute::Local(LocalFileObject::ReadonlyDirectory(7));
    let mut table = PendingFileIoTable::new();
    let slot = table
        .park(notification(LocalFileObject::ReadonlyDirectory(7)))
        .unwrap();
    for wrong in [
        PendingFileRoute::Hosted(7),
        PendingFileRoute::Local(LocalFileObject::ReadonlyFile(7)),
        PendingFileRoute::Local(LocalFileObject::Overlay(7)),
    ] {
        assert!(table
            .mark_user_apc_interrupt_requested_exact(slot, IRP, wrong, TID)
            .is_none());
        assert!(!table.get(slot).unwrap().user_apc_interrupt_requested);
    }
    assert!(table
        .mark_user_apc_interrupt_requested_exact(slot, IRP, route, TID)
        .is_some());
}

#[test]
fn abandonment_preserves_typed_route_through_terminal_reference_retirement() {
    let file = LocalFileObject::Overlay(u64::MAX);
    let mut table = PendingFileIoTable::new();
    let mut pending = inline(file);
    pending.iosb_va = 0x1000;
    pending.reply_required = true;
    pending.reply_cap = 1;
    let slot = table.park(pending).unwrap();
    assert_eq!(table.abandon_thread_transfers_with(TID, |_| {}), 1);
    assert_eq!(
        table.get(slot).unwrap().route,
        PendingFileRoute::Local(file)
    );
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    assert!(table.finish_exact(slot, IRP).is_none());
    table
        .mark_local_reference_released_exact(slot, IRP)
        .unwrap();
    assert_eq!(
        table.finish_exact(slot, IRP).unwrap().route,
        PendingFileRoute::Local(file)
    );
}
