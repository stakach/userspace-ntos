use super::*;

const IRP: u64 = 10;
const TID: u64 = 7;
const CAP: u64 = 4;
const ERROR: u32 = 0xc000_0001;

fn request() -> PendingFileIo {
    PendingFileIo {
        route: PendingFileRoute::Hosted(1),
        irp_id: IRP,
        tid: TID,
        major: nt_io_abi::major::IRP_MJ_READ,
        event_obj_idx: u64::MAX,
        reply_cap: CAP,
        reply_required: true,
        native_call_transport: true,
        busy: Some(test_busy(1, TID)),
        ..PendingFileIo::default()
    }
}

fn claimed() -> (PendingFileIoTable, PendingFileIoIdentity) {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(request()).unwrap();
    let identity = table.identity(slot).unwrap();
    table.request_user_apc_interruption(identity, IRP).unwrap();
    (table, identity)
}

fn receipt(
    table: &mut PendingFileIoTable,
    identity: PendingFileIoIdentity,
    receipt: PendingFileApcReceipt,
) {
    test_apc_receipt(table, identity, receipt);
}

fn stage_ready(table: &mut PendingFileIoTable, identity: PendingFileIoIdentity) {
    receipt(table, identity, PendingFileApcReceipt::CancelSelected);
    let mut lease = table.begin_apc_delivery(identity, IRP).unwrap();
    let mut release = table.begin_busy_release_exact(identity.slot, IRP).unwrap();
    table.record_busy_release(&mut release, Ok(0)).unwrap();
    table.finish_apc_delivery(&mut lease).unwrap();
    let mut wake = table.begin_busy_wake_exact(identity.slot, IRP).unwrap();
    table.record_busy_wake(&mut wake, Ok(())).unwrap();
    table.ready_apc_terminal(identity, IRP, 0).unwrap();
}

fn at(effect: PendingFileApcEffect) -> (PendingFileIoTable, PendingFileIoIdentity) {
    use PendingFileApcEffect as E;
    use PendingFileApcReceipt as R;
    let (mut table, identity) = claimed();
    match effect {
        E::CancelSelect => {}
        E::ReleaseApcClaim => receipt(&mut table, identity, R::CancelNotSelected),
        E::RevokeReply | E::RetypeReply => {
            receipt(&mut table, identity, R::CancelSelected);
            table.request_apc_teardown(identity).unwrap();
            if effect == E::RetypeReply {
                receipt(&mut table, identity, R::ReplyRevoked);
            }
        }
        E::Stage | E::Send | E::RetireSentReply => {
            stage_ready(&mut table, identity);
            if effect != E::Stage {
                receipt(&mut table, identity, R::Staged);
            }
            if effect == E::RetireSentReply {
                receipt(&mut table, identity, R::Sent);
            }
        }
    }
    (table, identity)
}

#[test]
fn selection_owns_reply_and_excludes_delivery_teardown_extraction_and_ack() {
    let (mut table, identity) = claimed();
    assert!(table.user_apc_interrupt_candidate(TID).is_none());
    assert!(table.request_user_apc_interruption(identity, IRP).is_err());
    let mut selecting = table.begin_apc_step(identity).unwrap();
    assert!(table.begin_apc_delivery(identity, IRP).is_err());
    assert!(table
        .mark_delivery_exact(identity.slot, IRP, IO_DELIVERY_IOSB_PUBLISHED)
        .is_none());
    assert!(table.begin_busy_release_exact(identity.slot, IRP).is_err());
    assert!(table.claim_reply_cap_exact(identity.slot, IRP).is_none());
    assert!(table.abandon_transfer_owner_exact(identity, IRP).is_none());
    assert_eq!(
        table.abandon_thread_transfers_with(TID, |_| panic!("APC owner escaped")),
        0
    );
    assert_eq!(
        table.take_thread_with(TID, |_| panic!("APC owner escaped")),
        0
    );
    assert!(table.mark_backend_acked_exact(identity.slot, IRP).is_none());
    assert!(table.finish_owner_exact(identity, IRP).is_none());
    assert!(!table.reset());
    table
        .record_apc_step(
            &mut selecting,
            PendingFileApcOutcome::Completed(PendingFileApcReceipt::CancelSelected),
        )
        .unwrap();
    assert_eq!(
        table.apc(identity).unwrap().phase,
        PendingFileApcPhase::AwaitTerminal
    );
}

#[test]
fn not_selected_retains_claim_until_cleanup_then_restores_ordinary_completion() {
    let (mut table, identity) = claimed();
    receipt(
        &mut table,
        identity,
        PendingFileApcReceipt::CancelNotSelected,
    );
    assert!(table.begin_apc_delivery(identity, IRP).is_err());
    assert!(table.finish_apc(identity).is_err());
    assert!(table.has_apc_for_thread(TID));
    receipt(
        &mut table,
        identity,
        PendingFileApcReceipt::ApcClaimReleased,
    );
    assert!(table.has_apc_runtime_dependency_matching(|pending| pending.tid == TID));
    let view = table.finish_apc(identity).unwrap();
    assert_eq!(view.selected, Some(false));
    assert_eq!(view.pending.reply_cap, CAP);
    assert_eq!(view.pending.delivery_state, 0);
    assert!(!table.has_apc_for_thread(TID));
    assert!(table.begin_apc_delivery(identity, IRP).is_ok());
}

#[test]
fn real_terminal_status_requires_finished_prefix_and_settled_busy_wake() {
    let (mut table, identity) = claimed();
    receipt(&mut table, identity, PendingFileApcReceipt::CancelSelected);
    assert_eq!(
        table.ready_apc_terminal(identity, IRP, 0x103),
        Err(PendingFileApcError::InvalidTerminal)
    );
    assert_eq!(
        table.ready_apc_terminal(identity, IRP, 0),
        Err(PendingFileApcError::UnsettledSurfaces)
    );
    let mut lease = table.begin_apc_delivery(identity, IRP).unwrap();
    assert!(table.ready_apc_terminal(identity, IRP, 0).is_err());
    let mut release = table.begin_busy_release_exact(identity.slot, IRP).unwrap();
    table.record_busy_release(&mut release, Ok(1)).unwrap();
    table.finish_apc_delivery(&mut lease).unwrap();
    assert!(table.ready_apc_terminal(identity, IRP, 0).is_err());
    let mut wake = table.begin_busy_wake_exact(identity.slot, IRP).unwrap();
    table.record_busy_wake(&mut wake, Err(ERROR)).unwrap();
    assert!(table.ready_apc_terminal(identity, IRP, 0).is_err());
    let mut wake = table.begin_busy_wake_exact(identity.slot, IRP).unwrap();
    table.record_busy_wake(&mut wake, Ok(())).unwrap();
    table.ready_apc_terminal(identity, IRP, 0).unwrap();
    assert_eq!(table.apc(identity).unwrap().terminal_status, Some(0));
    assert!(table.ready_apc_terminal(identity, IRP, ERROR).is_err());
}

#[test]
fn sent_cap_is_retained_until_checked_retirement_and_claim_cleanup() {
    let (mut table, identity) = at(PendingFileApcEffect::Send);
    receipt(&mut table, identity, PendingFileApcReceipt::Sent);
    assert_eq!(table.get_exact(identity).unwrap().reply_cap, CAP);
    let mut retire = table.begin_apc_step(identity).unwrap();
    assert_eq!(retire.effect(), PendingFileApcEffect::RetireSentReply);
    table
        .record_apc_step(&mut retire, PendingFileApcOutcome::NotEntered(ERROR))
        .unwrap();
    assert_eq!(table.get_exact(identity).unwrap().reply_cap, CAP);
    receipt(
        &mut table,
        identity,
        PendingFileApcReceipt::SentReplyRetired,
    );
    assert_eq!(table.get_exact(identity).unwrap().reply_cap, 0);
    assert!(table.mark_backend_acked_exact(identity.slot, IRP).is_none());
    receipt(
        &mut table,
        identity,
        PendingFileApcReceipt::ApcClaimReleased,
    );
    assert!(table.finish_owner_exact(identity, IRP).is_none());
    table.finish_apc(identity).unwrap();
    table.mark_backend_acked_exact(identity.slot, IRP).unwrap();
    assert!(table.finish_owner_exact(identity, IRP).is_some());
    assert!(table.reset());
}

#[test]
fn teardown_waits_for_prefix_exit_before_detaching_without_losing_reply() {
    let (mut table, identity) = claimed();
    receipt(&mut table, identity, PendingFileApcReceipt::CancelSelected);
    let mut lease = table.begin_apc_delivery(identity, IRP).unwrap();
    table.request_apc_teardown(identity).unwrap();
    assert!(!table.get_exact(identity).unwrap().consumer_abandoned);
    assert!(table.has_apc_runtime_dependency_matching(|_| true));
    assert!(table.finish_apc(identity).is_err());
    table.finish_apc_delivery(&mut lease).unwrap();
    let pending = table.get_exact(identity).unwrap();
    assert!(pending.consumer_abandoned);
    assert_eq!(pending.reply_cap, CAP);
    assert!(!pending.reply_required);
    assert!(!table.has_apc_runtime_dependency_matching(|_| true));
    assert!(table.has_apc_for_thread(TID));
    receipt(&mut table, identity, PendingFileApcReceipt::ReplyRevoked);
    assert_eq!(table.get_exact(identity).unwrap().reply_cap, CAP);
    receipt(&mut table, identity, PendingFileApcReceipt::ReplyRetyped);
    receipt(
        &mut table,
        identity,
        PendingFileApcReceipt::ApcClaimReleased,
    );
    table.finish_apc(identity).unwrap();
    assert!(table
        .get_exact(identity)
        .unwrap()
        .busy
        .unwrap()
        .release_pending());
}

#[test]
fn teardown_during_stage_and_send_preserves_exact_accepted_effect() {
    for (effect, accepted, next) in [
        (
            PendingFileApcEffect::Stage,
            PendingFileApcReceipt::Staged,
            PendingFileApcEffect::RevokeReply,
        ),
        (
            PendingFileApcEffect::Send,
            PendingFileApcReceipt::Sent,
            PendingFileApcEffect::RetireSentReply,
        ),
    ] {
        let (mut table, identity) = at(effect);
        let mut ticket = table.begin_apc_step(identity).unwrap();
        table.request_apc_teardown(identity).unwrap();
        assert!(!table.get_exact(identity).unwrap().consumer_abandoned);
        assert!(table.has_apc_runtime_dependency_matching(|_| true));
        table
            .record_apc_step(&mut ticket, PendingFileApcOutcome::Completed(accepted))
            .unwrap();
        assert!(table.get_exact(identity).unwrap().consumer_abandoned);
        assert!(!table.has_apc_runtime_dependency_matching(|_| true));
        assert_eq!(table.get_exact(identity).unwrap().reply_cap, CAP);
        assert_eq!(table.begin_apc_step(identity).unwrap().effect(), next);
    }
}

#[test]
fn every_indeterminate_or_dropped_effect_retains_owner_and_never_replays() {
    for effect in [
        PendingFileApcEffect::CancelSelect,
        PendingFileApcEffect::Stage,
        PendingFileApcEffect::Send,
        PendingFileApcEffect::RetireSentReply,
        PendingFileApcEffect::RevokeReply,
        PendingFileApcEffect::RetypeReply,
        PendingFileApcEffect::ReleaseApcClaim,
    ] {
        for uncertain in [false, true] {
            let (mut table, identity) = at(effect);
            let mut ticket = table.begin_apc_step(identity).unwrap();
            table.request_apc_teardown(identity).unwrap();
            if uncertain {
                table
                    .record_apc_step(&mut ticket, PendingFileApcOutcome::Indeterminate(ERROR))
                    .unwrap();
            }
            drop(ticket);
            assert!(table.begin_apc_step(identity).is_err());
            assert!(table.finish_apc(identity).is_err());
            assert!(table.finish_owner_exact(identity, IRP).is_none());
            assert!(table.has_apc_for_thread(TID));
            assert_eq!(
                table.has_apc_runtime_dependency_matching(|_| true),
                matches!(
                    effect,
                    PendingFileApcEffect::CancelSelect
                        | PendingFileApcEffect::Stage
                        | PendingFileApcEffect::Send
                )
            );
            assert!(!table.reset());
        }
    }
}

#[test]
fn cancelled_claim_cleanup_is_not_repeated_when_late_teardown_needs_cap_retirement() {
    let (mut table, identity) = at(PendingFileApcEffect::ReleaseApcClaim);
    receipt(
        &mut table,
        identity,
        PendingFileApcReceipt::ApcClaimReleased,
    );
    table.request_apc_teardown(identity).unwrap();
    receipt(&mut table, identity, PendingFileApcReceipt::ReplyRevoked);
    assert_eq!(
        test_apc_receipt(&mut table, identity, PendingFileApcReceipt::ReplyRetyped),
        PendingFileApcPhase::Complete
    );
    assert!(table.begin_apc_step(identity).is_err());
    table.finish_apc(identity).unwrap();
}

#[test]
fn ordinary_prefix_excludes_apc_takeover_and_nested_prefix_and_rejects_aba_receipt() {
    let mut table = PendingFileIoTable::new();
    let slot = table.park(request()).unwrap();
    let old = table.identity(slot).unwrap();
    let mut lease = table.begin_apc_delivery(old, IRP).unwrap();
    assert!(table.user_apc_interrupt_candidate(TID).is_none());
    assert!(table.request_user_apc_interruption(old, IRP).is_err());
    assert!(table.begin_apc_delivery(old, IRP).is_err());
    assert_eq!(table.finish_apc_delivery(&mut lease), Ok(None));
    assert!(table.user_apc_interrupt_candidate(TID).is_some());
    // Ordinary rows retain their existing teardown policy; replacing that policy is separate.
    let mut plain = request();
    plain.busy = None;
    table.abandon_transfer_owner_exact(old, IRP).unwrap();
    settle_test_busy(&mut table, slot, IRP);
    table.mark_backend_acked_exact(slot, IRP).unwrap();
    table.finish_owner_exact(old, IRP).unwrap();
    let slot = table.park(plain).unwrap();
    let removed = table.identity(slot).unwrap();
    let mut old_lease = table.begin_apc_delivery(removed, IRP).unwrap();
    table.take_thread_with(TID, |_| {});
    assert_eq!(table.park(plain), Some(slot));
    let current = table.identity(slot).unwrap();
    let mut current_lease = table.begin_apc_delivery(current, IRP).unwrap();
    assert_eq!(
        table.finish_apc_delivery(&mut old_lease),
        Err(PendingFileApcError::WrongIdentity)
    );
    assert_eq!(table.finish_apc_delivery(&mut current_lease), Ok(None));
}

#[test]
fn attempt_authority_is_cross_table_exact_and_exhaustion_precedes_effect_entry() {
    let (mut table, identity) = claimed();
    let (mut other, other_identity) = claimed();
    let mut ticket = table.begin_apc_step(identity).unwrap();
    assert_eq!(
        other.record_apc_step(
            &mut ticket,
            PendingFileApcOutcome::Completed(PendingFileApcReceipt::CancelSelected)
        ),
        Err(PendingFileApcError::WrongIdentity)
    );
    assert!(matches!(
        other.apc(other_identity).unwrap().phase,
        PendingFileApcPhase::Ready { .. }
    ));
    assert_eq!(
        table.record_apc_step(
            &mut ticket,
            PendingFileApcOutcome::Completed(PendingFileApcReceipt::Sent)
        ),
        Err(PendingFileApcError::WrongReceipt)
    );
    table
        .record_apc_step(&mut ticket, PendingFileApcOutcome::NotEntered(ERROR))
        .unwrap();
    table.next_apc_attempt = u64::MAX;
    let mut last = table.begin_apc_step(identity).unwrap();
    table
        .record_apc_step(&mut last, PendingFileApcOutcome::NotEntered(ERROR))
        .unwrap();
    assert!(matches!(
        table.begin_apc_step(identity),
        Err(PendingFileApcError::Exhausted)
    ));
    assert!(matches!(
        table.apc(identity).unwrap().phase,
        PendingFileApcPhase::Ready { .. }
    ));
    assert!(table.has_apc_for_thread(TID));
}

#[test]
fn local_terminal_status_and_surfaces_are_verified_without_synthetic_busy() {
    let mut table = PendingFileIoTable::new();
    let pending = PendingFileIo {
        route: PendingFileRoute::Local(LocalFileObject::Overlay(0)),
        busy: None,
        major: nt_io_abi::major::IRP_MJ_LOCK_CONTROL,
        iosb_va: 0x1000,
        operation: PendingFileIoOperation::LocalByteLock(PendingLocalByteLock {
            wait_id: 1,
            status: 0x103,
            alertable: true,
        }),
        ..request()
    };
    let slot = table.park(pending).unwrap();
    let identity = table.identity(slot).unwrap();
    table.request_user_apc_interruption(identity, IRP).unwrap();
    receipt(&mut table, identity, PendingFileApcReceipt::CancelSelected);
    assert!(table.complete_local_byte_lock_exact(IRP, 1, ERROR));
    let mut lease = table.begin_apc_delivery(identity, IRP).unwrap();
    table
        .mark_delivery_exact(slot, IRP, IO_DELIVERY_IOSB_PUBLISHED)
        .unwrap();
    table.finish_apc_delivery(&mut lease).unwrap();
    assert_eq!(
        table.ready_apc_terminal(identity, IRP, 0),
        Err(PendingFileApcError::InvalidTerminal)
    );
    table.ready_apc_terminal(identity, IRP, ERROR).unwrap();
    assert_eq!(table.apc(identity).unwrap().terminal_status, Some(ERROR));
}
