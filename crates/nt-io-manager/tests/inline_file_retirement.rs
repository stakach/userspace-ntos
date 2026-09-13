//! Real File policy composed with inline retirement, without a fabricated pending IRP.
//! Wake/callout and uncertainty outcomes are fixture-supplied, not native IPC proof.

use nt_io_completion::{
    CompletionPortTable, FileCompletionBinding, FileCompletionTable, FileIoAcquireResult,
    FileIoMode,
};
use nt_io_manager::inline_file_retirement::{
    InlineFileRetirementEffect as Effect, InlineFileRetirementIdentity as Identity,
    InlineFileRetirementOutcome as Outcome, InlineFileRetirementPhase as Phase,
    InlineFileRetirementTable as Table,
};
use nt_io_manager::*;

const FILE: u64 = 10;
const DEVICE: u64 = 7;
const FIRST: u64 = 20;
const SECOND: u64 = 21;
const PI: u32 = 2;
const SERVICE: u32 = 191;
const MODE: FileIoMode = FileIoMode::SynchronousNonAlertable;
const REFUSED: u32 = 0xc000_0001;

fn owner(tid: u64) -> FileIoBusyOwner {
    FileIoBusyOwner {
        key: FileIoWaitKey::Hosted(FILE),
        tid,
        mode: MODE,
    }
}

fn fixture(tid: u64) -> (FileCompletionTable<1>, Table, Identity) {
    let mut files = FileCompletionTable::new();
    files.insert_file_with_mode(FILE, DEVICE, MODE).unwrap();
    let mut retained = Table::new();
    let reserved = retained.reserve(owner(tid)).unwrap();
    assert_eq!(
        files.acquire_file_io(FILE, tid),
        Ok(FileIoAcquireResult::Acquired)
    );
    let identity = retained.activate(reserved).unwrap();
    (files, retained, identity)
}

fn release_policy(files: &mut FileCompletionTable<1>, retained: &mut Table, id: Identity) {
    let mut attempt = retained.begin_step(id).unwrap();
    assert_eq!(attempt.effect(), Effect::ReleasePolicy);
    let release = files.release_io(FILE, attempt.owner().tid).unwrap();
    retained
        .record_step(
            &mut attempt,
            Outcome::PolicyReleased {
                waiters: release.waiters,
            },
        )
        .unwrap();
}

fn complete_effect(retained: &mut Table, id: Identity, effect: Effect) {
    let mut attempt = retained.begin_step(id).unwrap();
    assert_eq!(attempt.effect(), effect);
    retained
        .record_step(&mut attempt, Outcome::Completed(effect))
        .unwrap();
}

fn release_reference(files: &mut FileCompletionTable<1>, retained: &mut Table, id: Identity) {
    let mut attempt = retained.begin_step(id).unwrap();
    assert_eq!(attempt.effect(), Effect::ReleaseReference);
    let receipt = files.release_file(FILE).unwrap();
    retained
        .record_step(&mut attempt, Outcome::ReferenceReleased(receipt))
        .unwrap();
}

fn close_handle(files: &mut FileCompletionTable<1>) {
    assert!(files.release_handle(FILE).unwrap().cleanup_required);
    assert_eq!(
        files.begin_cleanup(FILE),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
}

fn cleanup(files: &mut FileCompletionTable<1>) {
    assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(true));
    assert_eq!(files.mark_cleanup_lifecycle_started(FILE), Ok(true));
    files.release_cleanup_io(FILE).unwrap();
    assert!(
        !files
            .release_cleanup_reference(FILE)
            .unwrap()
            .close_required
    );
}

fn queue_second(files: &mut FileCompletionTable<1>) -> SynchronousFileWaitTable {
    let mut waiters = SynchronousFileWaitTable::new();
    let reservation = waiters.reserve().unwrap();
    assert_eq!(
        files.acquire_file_io(FILE, SECOND),
        Ok(FileIoAcquireResult::Contended { alertable: false })
    );
    let mut waiter = SynchronousFileWaiter::waiting(
        FileIoWaitRoute::Hosted {
            file_id: FILE,
            device_id: DEVICE,
            fs_context: 9,
        },
        0x40,
        3,
        SERVICE,
        PI,
        SECOND,
        SECOND + 100,
        MODE,
        true,
        0,
        0x1002,
        0x2000,
        0x202,
    );
    waiter.reply_cap = SECOND + 200;
    waiters.park_reserved(reservation, waiter).unwrap();
    waiters
}

fn promote_and_ack(files: &mut FileCompletionTable<1>, waiters: &mut SynchronousFileWaitTable) {
    let (slot, waiter) = waiters
        .oldest_waiting_for_file(FileIoWaitKey::Hosted(FILE))
        .unwrap();
    assert_eq!(waiter.tid, SECOND);
    files.promote_io_waiter(FILE, SECOND).unwrap();
    waiters
        .promote_exact(slot, FileIoWaitKey::Hosted(FILE), SECOND)
        .unwrap();
    let id = waiters
        .retry_identity(slot, FileIoWaitKey::Hosted(FILE), SECOND)
        .unwrap();
    let mut retry = waiters.begin_retry(id).unwrap();
    waiters
        .record_retry(&mut retry, SynchronousFileRetryOutcome::Acknowledged)
        .unwrap();
    assert!(waiters.finish_retry(id, Ok(())).unwrap());
}

#[test]
fn inline_terminal_keeps_busy_and_reference_until_retirement_without_pending_irp() {
    let (mut files, mut retained, id) = fixture(FIRST);
    let pending = PendingFileIoTable::new();
    // The real request may have ACKed already; terminal cleanup creates no backend identity.
    files.set_signaled(FILE, true).unwrap();
    close_handle(&mut files);
    assert!(pending.is_empty());
    assert!(retained.begin_step(id).is_err());
    assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(false));
    retained.retire_active(id).unwrap();
    release_policy(&mut files, &mut retained, id);
    let mut wake = retained.begin_step(id).unwrap();
    assert_eq!(wake.effect(), Effect::Wake);
    cleanup(&mut files);
    assert!(retained.begin_step(id).is_err());
    retained
        .record_step(&mut wake, Outcome::Completed(Effect::Wake))
        .unwrap();
    release_reference(&mut files, &mut retained, id);
    let receipt = retained.get(id).unwrap().reference_release.unwrap();
    assert!(receipt.close_required);
    assert!(!receipt.cleanup_required);
    assert!(files.io_mode(FILE).is_err());
    assert!(retained.finish(id).is_none());
    complete_effect(&mut retained, id, Effect::ReferenceFollowup);
    assert_eq!(retained.finish(id), Some(owner(FIRST)));
    assert!(retained.is_empty());
    assert!(pending.is_empty());
}

#[test]
fn fresh_acquisition_and_policy_refusal_keep_one_retirement_reference() {
    let (mut files, mut retained, id) = fixture(FIRST);
    close_handle(&mut files);
    retained.retire_active(id).unwrap();
    let mut release = retained.begin_step(id).unwrap();
    let status = files.release_io(FILE, SECOND).unwrap_err();
    retained
        .record_step(&mut release, Outcome::NotEntered(status))
        .unwrap();
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(FIRST)));
    assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(false));
    release_policy(&mut files, &mut retained, id);
    assert!(retained
        .record_step(&mut release, Outcome::PolicyReleased { waiters: 0 })
        .is_err());
    cleanup(&mut files);
    complete_effect(&mut retained, id, Effect::Wake);
    release_reference(&mut files, &mut retained, id);
    complete_effect(&mut retained, id, Effect::ReferenceFollowup);
    retained.finish(id).unwrap();
    assert!(files.io_mode(FILE).is_err());
}

#[test]
fn wake_reentry_adopts_promoted_grant_into_pre_reserved_inline_owner() {
    let (mut files, mut retained, first) = fixture(FIRST);
    let mut waiters = queue_second(&mut files);
    close_handle(&mut files);
    retained.retire_active(first).unwrap();
    release_policy(&mut files, &mut retained, first);
    assert_eq!(retained.get(first).unwrap().policy_waiters, Some(1));
    let mut wake = retained.begin_step(first).unwrap();
    promote_and_ack(&mut files, &mut waiters);
    // Reentrant ingress reserves terminal cleanup before consuming its policy grant.
    let reservation = retained.reserve(owner(SECOND)).unwrap();
    let mut ingress = waiters
        .begin_ingress(PI, SECOND, SECOND + 100, SERVICE)
        .unwrap()
        .unwrap();
    let mut adoption = waiters.begin_adoption(&mut ingress).unwrap();
    let adopted = files.adopt_io_grant(FILE, SECOND);
    assert!(waiters
        .record_adoption(&mut adoption, adopted)
        .unwrap()
        .is_some());
    let second = retained.activate(reservation).unwrap();
    assert!(waiters.is_empty());
    assert!(retained.begin_step(first).is_err());
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(SECOND)));
    retained
        .record_step(&mut wake, Outcome::Completed(Effect::Wake))
        .unwrap();
    release_reference(&mut files, &mut retained, first);
    complete_effect(&mut retained, first, Effect::ReferenceFollowup);
    retained.finish(first).unwrap();
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(SECOND)));
    assert_eq!(files.promote_cleanup_if_ready(FILE), Ok(false));
    retained.retire_active(second).unwrap();
    release_policy(&mut files, &mut retained, second);
    cleanup(&mut files);
    complete_effect(&mut retained, second, Effect::Wake);
    release_reference(&mut files, &mut retained, second);
    complete_effect(&mut retained, second, Effect::ReferenceFollowup);
    retained.finish(second).unwrap();
    assert!(files.io_mode(FILE).is_err());
    assert!(retained.is_empty());
}

#[test]
fn accepted_pending_irp_receives_active_busy_without_inline_release() {
    let (mut files, mut retained, id) = fixture(FIRST);
    let mut pending = PendingFileIoTable::new();
    let reservation = pending.reserve().unwrap();
    let busy = retained.active_owner(id).unwrap();
    let slot = pending
        .park_reserved(
            reservation,
            PendingFileIo {
                route: PendingFileRoute::Hosted(FILE),
                irp_id: 91,
                major: 3,
                tid: FIRST,
                pi: PI,
                busy: Some(PendingFileBusy::new(busy)),
                event_obj_idx: u64::MAX,
                ..PendingFileIo::default()
            },
        )
        .unwrap();
    assert_eq!(retained.transfer_active(id), Ok(busy));
    assert!(retained.retire_active(id).is_err());
    assert!(retained.is_empty());
    assert_eq!(files.io_lock_owner(FILE), Ok(Some(FIRST)));
    assert_eq!(pending.get(slot).unwrap().busy.unwrap().owner(), busy);
    let mut attempt = pending.begin_busy_release_exact(slot, 91).unwrap();
    let released = files.release_io(FILE, FIRST).map(|release| release.waiters);
    pending.record_busy_release(&mut attempt, released).unwrap();
    assert_eq!(files.io_lock_owner(FILE), Ok(None));
    assert!(retained.begin_step(id).is_err());
}

#[test]
fn final_reference_followup_survives_file_row_retirement_and_caller_exit() {
    let mut pm = nt_process::ProcessManager::new();
    let pid = pm.create_process("inline-owner.exe", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let (mut files, mut retained, id) = fixture(tid as u64);
    let mut ports = CompletionPortTable::<1, 1>::new();
    let port_id = ports.create(1).unwrap();
    // NT forbids associating a synchronous File with an IOCP. Its inline retirement must
    // preserve the empty followup receipt, not synthesize a port reference to release.
    assert_eq!(
        files.associate(
            FILE,
            FileCompletionBinding {
                port_id,
                key_context: 17,
            },
        ),
        Err(nt_fs::STATUS_INVALID_PARAMETER)
    );
    close_handle(&mut files);
    retained.retire_active(id).unwrap();
    pm.terminate_thread(tid, 0).unwrap();
    release_policy(&mut files, &mut retained, id);
    cleanup(&mut files);
    complete_effect(&mut retained, id, Effect::Wake);
    release_reference(&mut files, &mut retained, id);
    assert!(files.io_mode(FILE).is_err());
    assert_eq!(
        retained.get(id).unwrap().reference_release.unwrap().port_id,
        None
    );
    let mut followup = retained.begin_step(id).unwrap();
    retained
        .record_step(&mut followup, Outcome::NotEntered(REFUSED))
        .unwrap();
    assert_eq!(ports.depth(port_id), Ok(0));
    assert!(retained.finish(id).is_none());
    let mut retry = retained.begin_step(id).unwrap();
    assert_eq!(retry.effect(), Effect::ReferenceFollowup);
    assert_eq!(retry.reference_release().unwrap().port_id, None);
    retained
        .record_step(&mut retry, Outcome::Completed(Effect::ReferenceFollowup))
        .unwrap();
    retained.finish(id).unwrap();
    assert_eq!(ports.depth(port_id), Ok(0));
    ports.release(port_id).unwrap();
    assert!(retained.is_empty());
}

#[test]
fn dropped_wake_ticket_cannot_replay_policy_or_retire_reference() {
    let (mut files, mut retained, id) = fixture(FIRST);
    close_handle(&mut files);
    retained.retire_active(id).unwrap();
    release_policy(&mut files, &mut retained, id);
    let wake = retained.begin_step(id).unwrap();
    assert_eq!(wake.effect(), Effect::Wake);
    cleanup(&mut files);
    drop(wake);
    assert!(retained.begin_step(id).is_err());
    assert!(retained.finish(id).is_none());
    assert!(!retained.reset());
    assert_eq!(files.io_mode(FILE), Ok(MODE));
    assert!(matches!(
        retained.get(id).unwrap().phase,
        Phase::Invoking {
            effect: Effect::Wake,
            ..
        }
    ));
}

#[test]
fn uncertain_reference_receipt_cannot_decrement_again_after_final_row_disappears() {
    let (mut files, mut retained, id) = fixture(FIRST);
    close_handle(&mut files);
    retained.retire_active(id).unwrap();
    release_policy(&mut files, &mut retained, id);
    cleanup(&mut files);
    complete_effect(&mut retained, id, Effect::Wake);
    let mut release = retained.begin_step(id).unwrap();
    let receipt = files.release_file(FILE).unwrap();
    assert!(receipt.close_required);
    retained
        .record_step(&mut release, Outcome::Indeterminate(REFUSED))
        .unwrap();
    assert!(files.io_mode(FILE).is_err());
    assert!(retained.begin_step(id).is_err());
    assert!(retained.finish(id).is_none());
    assert!(matches!(
        retained.get(id).unwrap().phase,
        Phase::Indeterminate {
            effect: Effect::ReleaseReference,
            ..
        }
    ));
}
