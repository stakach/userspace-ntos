//! Paired pending-I/O and logical-caller ownership, using the real policy tables and PM lifetimes.
//! ThreadBinding values represent independently admitted native runtime fixtures, not VM proof.

use nt_io_manager::{
    PendingFileCreate, PendingFileIo, PendingFileIoIdentity, PendingFileIoOperation,
    PendingFileIoTable, PendingFileRoute, PendingSetFileNameOperation,
};
use nt_process::ProcessManager;
use nt_user_host::pending_caller::{PendingCallerError, PendingCallerTable};
use nt_user_host::process_identity::{ProcessGeneration, ProcessIdentity};
use nt_user_host::provider_logical_caller::{ProviderCallerError, ProviderLogicalCaller};
use nt_user_host::thread_binding::ThreadBinding;

type Callers = PendingCallerTable<PendingFileIoIdentity>;

fn caller() -> (ProcessManager, ThreadBinding<()>, ProviderLogicalCaller) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("pending-owner.exe", None, None);
    pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let tid = pm.create_thread(pid, 0x2000, 0, false).unwrap();
    let binding = ThreadBinding {
        pi: 0,
        process: ProcessIdentity {
            pid,
            generation: ProcessGeneration::Hosted(3),
        },
        tid: u64::from(tid),
        badge: 0,
        role: (),
        tcb: 8,
        reservations: None,
    };
    let caller = ProviderLogicalCaller::capture(binding, pm.thread_lifetime(tid).unwrap()).unwrap();
    (pm, binding, caller)
}

fn transfer(caller: ProviderLogicalCaller) -> PendingFileIo {
    PendingFileIo {
        route: PendingFileRoute::Hosted(7),
        irp_id: 10,
        major: nt_io_abi::major::IRP_MJ_READ,
        pi: caller.pi() as u32,
        tid: u64::from(caller.thread().thread_id()),
        badge: caller.badge(),
        reply_cap: 77,
        reply_required: true,
        native_call_transport: true,
        event_obj_idx: u64::MAX,
        ..PendingFileIo::default()
    }
}

fn publish(
    core: &mut PendingFileIoTable,
    callers: &mut Callers,
    pending: PendingFileIo,
    caller: ProviderLogicalCaller,
) -> PendingFileIoIdentity {
    let reservation = core.reserve().unwrap();
    let id = reservation.identity();
    callers.reserve(id.slot(), id, caller).unwrap();
    assert_eq!(callers.get_reserved(id.slot(), id), Some(caller));
    assert_eq!(callers.get_published(id.slot(), id), None);
    assert_eq!(core.get_exact(id), None);
    let capacity = (
        core.allocation_capacity(),
        core.local_output_allocation_capacity(),
        core.owner_generation_allocation_capacity(),
        callers.capacity(),
    );
    core.park_reserved(reservation, pending).unwrap();
    assert_eq!(callers.publish(id.slot(), id), Ok(caller));
    assert_eq!(
        capacity,
        (
            core.allocation_capacity(),
            core.local_output_allocation_capacity(),
            core.owner_generation_allocation_capacity(),
            callers.capacity()
        )
    );
    assert_eq!(core.get_exact(id), Some(pending));
    assert_eq!(callers.get_reserved(id.slot(), id), None);
    id
}

fn complete(core: &mut PendingFileIoTable, id: PendingFileIoIdentity, irp: u64) {
    let pending = core.get_exact(id).unwrap();
    if pending.reply_required {
        assert_eq!(
            core.claim_reply_cap_exact(id.slot(), irp),
            Some(Some(pending.reply_cap))
        );
        core.mark_reply_published_exact(id.slot(), irp).unwrap();
    }
    core.mark_backend_acked_exact(id.slot(), irp).unwrap();
    core.finish_owner_exact(id, irp).unwrap();
}

#[test]
fn predispatch_reservations_publish_without_growing_either_owner_table() {
    let (pm, binding, caller) = caller();
    let mut core = PendingFileIoTable::new();
    let mut callers = Callers::new();
    let id = publish(&mut core, &mut callers, transfer(caller), caller);
    let published = callers.get_published(id.slot(), id).unwrap();
    assert_eq!(
        published.validate(Some(binding), pm.thread_lifetime(binding.tid as u32)),
        Ok(())
    );
    assert_eq!(
        callers.cancel_reserved(id.slot(), id),
        Err(PendingCallerError::InvalidPhase)
    );
    assert!(!callers.reset());
    complete(&mut core, id, 10);
    assert_eq!(callers.retire_published(id.slot(), id), Ok(caller));
    assert!(core.reset());
    assert!(callers.reset());
}

#[test]
fn provenance_reservation_refusal_rolls_back_original_core_claim_without_touching_peer() {
    let (_, _, caller) = caller();
    let mut core = PendingFileIoTable::new();
    let mut peer = PendingFileIoTable::new();
    let mut callers = Callers::new();
    let peer_id = publish(&mut peer, &mut callers, transfer(caller), caller);
    let reservation = core.reserve().unwrap();
    let id = reservation.identity();
    assert_eq!(id.slot(), peer_id.slot());
    assert_eq!(
        callers.reserve(id.slot(), id, caller),
        Err(PendingCallerError::Occupied)
    );
    assert!(core.cancel_reservation(reservation));
    assert_eq!(core.get_exact(id), None);
    assert!(core.is_empty());
    assert_eq!(callers.get_published(peer_id.slot(), peer_id), Some(caller));
    assert_eq!(peer.get_exact(peer_id), Some(transfer(caller)));

    // Capacity overflow is a deterministic allocation refusal, not a mocked successful reserve.
    let mut empty_callers = Callers::new();
    let reservation = core.reserve().unwrap();
    let id = reservation.identity();
    assert_eq!(
        empty_callers.reserve(usize::MAX - 1, id, caller),
        Err(PendingCallerError::AllocationFailed)
    );
    assert!(core.cancel_reservation(reservation));
    assert!(core.is_empty());
    assert!(empty_callers.is_empty());
    complete(&mut peer, peer_id, 10);
    callers.retire_published(peer_id.slot(), peer_id).unwrap();
}

#[test]
fn unused_pair_cancellation_does_not_publish_or_authorize_a_later_reservation() {
    let (_, _, caller) = caller();
    let mut core = PendingFileIoTable::new();
    let mut callers = Callers::new();
    let reservation = core.reserve().unwrap();
    let old = reservation.identity();
    callers.reserve(old.slot(), old, caller).unwrap();
    assert_eq!(callers.cancel_reserved(old.slot(), old), Ok(caller));
    assert!(core.cancel_reservation(reservation));
    assert!(core.is_empty());
    assert!(callers.is_empty());
    let new = publish(&mut core, &mut callers, transfer(caller), caller);
    assert_eq!(old.slot(), new.slot());
    assert_ne!(old, new);
    assert!(callers.publish(old.slot(), old).is_err());
    assert!(callers.cancel_reserved(old.slot(), old).is_err());
    assert_eq!(callers.get_published(new.slot(), new), Some(caller));
    complete(&mut core, new, 10);
    callers.retire_published(new.slot(), new).unwrap();
}

#[test]
fn same_irp_tid_and_cap_reuse_cannot_validate_or_retire_previous_caller() {
    let (mut pm, binding, old_caller) = caller();
    let mut core = PendingFileIoTable::new();
    let mut callers = Callers::new();
    let old = publish(&mut core, &mut callers, transfer(old_caller), old_caller);
    complete(&mut core, old, 10);
    callers.retire_published(old.slot(), old).unwrap();
    let tid = binding.tid as u32;
    pm.terminate_thread(tid, 0).unwrap();
    let plan = pm
        .prepare_thread_activation(tid, 0x3000, 0, false, 0x7000, 0, false)
        .unwrap();
    pm.commit_thread_activation(plan).unwrap();
    let lifetime = pm.thread_lifetime(tid).unwrap();
    let new_caller = ProviderLogicalCaller::capture(binding, lifetime).unwrap();
    assert_eq!(
        old_caller.validate(Some(binding), Some(lifetime)),
        Err(ProviderCallerError::LifetimeChanged)
    );
    let new = publish(&mut core, &mut callers, transfer(new_caller), new_caller);
    assert_eq!(new.slot(), old.slot());
    assert_ne!(new, old);
    assert_eq!(core.get_exact(old), None);
    assert_eq!(callers.get_published(old.slot(), old), None);
    assert!(callers.retire_published(old.slot(), old).is_err());
    assert_eq!(callers.get_published(new.slot(), new), Some(new_caller));
    assert_eq!(new_caller.validate(Some(binding), Some(lifetime)), Ok(()));
    complete(&mut core, new, 10);
    callers.retire_published(new.slot(), new).unwrap();
}

#[test]
fn rename_and_consumer_abandonment_preserve_caller_until_exact_owner_finish() {
    let (_, _, caller) = caller();
    let mut core = PendingFileIoTable::new();
    let mut callers = Callers::new();
    let pending = PendingFileIo {
        major: nt_io_abi::major::IRP_MJ_QUERY_INFORMATION,
        operation: PendingFileIoOperation::SetFileName(PendingSetFileNameOperation {
            transaction_id: 1,
            target_file_id: 0,
        }),
        iosb_va: 0x2000,
        ..transfer(caller)
    };
    let id = publish(&mut core, &mut callers, pending, caller);
    core.retarget_set_file_name_query_owner_exact(id, 10, 11, nt_io_abi::major::IRP_MJ_CREATE, 8)
        .unwrap();
    assert_eq!(callers.get_published(id.slot(), id), Some(caller));
    core.retarget_set_file_name_irp_owner_exact(id, 11, 12)
        .unwrap();
    assert_eq!(core.identity(id.slot()), Some(id));
    assert_eq!(core.abandon_transfer_owner_exact(id, 10), None);
    core.abandon_transfer_owner_exact(id, 12).unwrap();
    assert!(core.get_exact(id).unwrap().consumer_abandoned);
    assert!(!core.get_exact(id).unwrap().native_call_transport);
    assert_eq!(callers.get_published(id.slot(), id), Some(caller));
    complete(&mut core, id, 12);
    assert_eq!(callers.retire_published(id.slot(), id), Ok(caller));
    assert!(callers.is_empty());
}

#[test]
fn create_teardown_removes_whole_batch_metadata_before_reentrant_cleanup_effects() {
    let (_, _, caller) = caller();
    let mut core = PendingFileIoTable::new();
    let mut callers = Callers::new();
    let mut ids = Vec::new();
    for irp_id in [10, 11] {
        let pending = PendingFileIo {
            irp_id,
            major: nt_io_abi::major::IRP_MJ_CREATE,
            operation: PendingFileIoOperation::Create(PendingFileCreate {
                handle_va: 0x1000,
                reservation_pid: caller.process().pid,
                reserved_handle: 4,
                reservation_generation: irp_id,
                status: nt_status::NtStatus::PENDING.raw() as u32,
                ..PendingFileCreate::default()
            }),
            iosb_va: 0x2000,
            reply_cap: 0,
            reply_required: false,
            ..transfer(caller)
        };
        ids.push(publish(&mut core, &mut callers, pending, caller));
    }
    let peer = PendingFileIo {
        irp_id: 12,
        ..transfer(caller)
    };
    let peer_id = publish(&mut core, &mut callers, peer, caller);
    let mut batch = Vec::new();
    assert_eq!(
        core.take_thread_creates_exact_with(peer.tid, |id, pending| {
            callers.retire_published(id.slot(), id).unwrap();
            batch.push((id, pending));
        }),
        2
    );
    for id in &ids {
        assert_eq!(core.get_exact(*id), None);
        assert_eq!(callers.get_published(id.slot(), *id), None);
    }
    assert_eq!(core.get_exact(peer_id), Some(peer));
    assert_eq!(callers.get_published(peer_id.slot(), peer_id), Some(caller));

    // This is the first effect callback, after all source/metadata removals. Reentrant work
    // reuses the first slot and numeric IRP; later callbacks still hold only old identities.
    let replacement = publish(&mut core, &mut callers, batch[0].1, caller);
    assert_eq!(replacement.slot(), ids[0].slot());
    for (old, _) in batch {
        assert!(callers.retire_published(old.slot(), old).is_err());
        assert_eq!(core.get_exact(old), None);
        assert_eq!(
            callers.get_published(replacement.slot(), replacement),
            Some(caller)
        );
    }
    core.take_create_owner_exact(replacement, 10).unwrap();
    callers
        .retire_published(replacement.slot(), replacement)
        .unwrap();
    complete(&mut core, peer_id, 12);
    callers.retire_published(peer_id.slot(), peer_id).unwrap();
    assert!(core.is_empty());
    assert!(callers.is_empty());
}
