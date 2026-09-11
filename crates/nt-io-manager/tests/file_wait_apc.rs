//! Alertable File-wait interruption with real File policy, APC claims, and AMD64 frame preparation.
//! TCB reads/writes, user-memory publication, Reply sends, and cap effects are controlled fixtures.

use nt_io_completion::{FileCompletionTable, FileIoAcquireResult, FileIoMode};
use nt_io_manager::*;
use nt_process::{ProcessManager, ThreadId, UserApc, UserApcClaim};
use nt_thread_start::amd64_context::{
    prepare_user_apc, PreparedUserApc, UserApcContinuation, UserApcPayload,
    LEGACY_FLOATING_POINT_BYTES,
};

const FILE: u64 = 17;
const DEVICE: u64 = 7;
const ACTIVE: u64 = 100;
const CAP: u64 = 47;
const REFUSED: u32 = 13;
const USER_APC: u32 = 0xc0;
const MODE: FileIoMode = FileIoMode::SynchronousAlertable;
const APC: UserApc = UserApc {
    routine: 0x8014_0000,
    normal_context: 0x11,
    system_argument1: 0x22,
    system_argument2: 0x33,
};

struct Fixture {
    pm: ProcessManager,
    tid: ThreadId,
    claim: UserApcClaim,
    files: FileCompletionTable<1>,
    table: SynchronousFileWaitTable,
    identity: SynchronousFileWaitIdentity,
    registers: [u64; 20],
    installed_frames: usize,
    sent_replies: usize,
    cap_reusable: bool,
}

impl Fixture {
    fn new() -> Self {
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("apc-wait.exe", None, None);
        pm.create_thread(pid, 0x1000, 0, false).unwrap();
        let tid = pm.create_thread(pid, 0x2000, 0, false).unwrap();
        pm.queue_kernel_user_apc(tid, APC).unwrap();
        pm.queue_kernel_user_apc(tid, APC).unwrap();
        let claim = pm.claim_user_apc(tid).unwrap().unwrap();
        let mut files = FileCompletionTable::new();
        files.insert_file_with_mode(FILE, DEVICE, MODE).unwrap();
        assert_eq!(
            files.acquire_file_io(FILE, ACTIVE),
            Ok(FileIoAcquireResult::Acquired)
        );
        let mut table = SynchronousFileWaitTable::new();
        let reservation = table.reserve().unwrap();
        assert_eq!(
            files.acquire_file_io(FILE, u64::from(tid)),
            Ok(FileIoAcquireResult::Contended { alertable: true })
        );
        let mut waiter = SynchronousFileWaiter::waiting(
            FileIoWaitRoute::Hosted {
                file_id: FILE,
                device_id: DEVICE,
                fs_context: 9,
            },
            0x40,
            1,
            191,
            pid,
            u64::from(tid),
            u64::from(tid) + 100,
            MODE,
            true,
            0,
            0x8010_1234,
            0x10_0000 - 168,
            0x202,
        );
        waiter.reply_cap = CAP;
        let slot = table.park_reserved(reservation, waiter).unwrap();
        let identity = table.wait_identity(slot, waiter.key(), waiter.tid).unwrap();
        table.request_user_apc_interruption(identity).unwrap();
        let mut registers = core::array::from_fn(|index| 0x100 + index as u64);
        registers[0] = 0x8010_1234;
        registers[1] = 0x10_0000 - 168;
        registers[2] = 0x202;
        Self {
            pm,
            tid,
            claim,
            files,
            table,
            identity,
            registers,
            installed_frames: 0,
            sent_replies: 0,
            cap_reusable: false,
        }
    }

    fn record(
        &mut self,
        effect: SynchronousFileCancelEffect,
        outcome: SynchronousFileCancelOutcome,
    ) {
        let mut attempt = self.table.begin_cancellation(self.identity).unwrap();
        assert_eq!(attempt.effect(), effect);
        self.table
            .record_cancellation(&mut attempt, outcome)
            .unwrap();
    }

    fn cancel_file_wait(&mut self) {
        use SynchronousFileCancelEffect as Effect;
        use SynchronousFileCancelReceipt as Receipt;
        let mut policy = self.table.begin_cancellation(self.identity).unwrap();
        assert_eq!(policy.effect(), Effect::Policy);
        assert_eq!(self.files.cancel_io_waiter(FILE), Ok(0));
        self.table
            .record_cancellation(
                &mut policy,
                SynchronousFileCancelOutcome::Completed(Receipt::HostedPolicy { waiters: 0 }),
            )
            .unwrap();
        self.record(
            Effect::Wake,
            SynchronousFileCancelOutcome::Completed(Receipt::Wake),
        );
        let mut reference = self.table.begin_cancellation(self.identity).unwrap();
        assert_eq!(reference.effect(), Effect::HostedReference);
        let release = self.files.release_file(FILE).unwrap();
        assert!(!release.close_required);
        self.table
            .record_cancellation(
                &mut reference,
                SynchronousFileCancelOutcome::Completed(Receipt::HostedReference(release)),
            )
            .unwrap();
        assert_eq!(self.files.io_lock_owner(FILE), Ok(Some(ACTIVE)));
        assert_eq!(self.files.io_waiter_count(FILE), Ok(0));
        assert!(self.pm.validate_user_apc_claim(&self.claim));
    }

    fn frame(&self) -> PreparedUserApc {
        let mut floating_point = [0; LEGACY_FLOATING_POINT_BYTES];
        floating_point[..2].copy_from_slice(&0x037fu16.to_le_bytes());
        floating_point[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        let apc = self.claim.apc();
        prepare_user_apc(
            &self.registers,
            &floating_point,
            UserApcContinuation::NativeCall,
            0x8012_3000,
            UserApcPayload {
                routine: apc.routine,
                normal_context: apc.normal_context,
                system_argument1: apc.system_argument1,
                system_argument2: apc.system_argument2,
            },
            USER_APC,
            0x7fff_ffff_ffff,
        )
        .unwrap()
    }

    fn install(&mut self, plan: &PreparedUserApc) {
        // The fixture acknowledges user frame publication and a non-resuming TCB register write.
        // Validation follows all potentially reentrant preparation; commit follows accepted install.
        assert!(self.pm.validate_user_apc_claim(&self.claim));
        for index in 0..self.registers.len() {
            if plan.install.register_mask & (1 << index) != 0 {
                self.registers[index] = plan.install.registers[index];
            }
        }
        self.installed_frames += 1;
        assert_eq!(self.pm.commit_user_apc_claim(&mut self.claim), Ok(APC));
    }

    fn stage(&mut self, accepted: bool) -> PreparedUserApc {
        let mut attempt = self.table.begin_cancellation(self.identity).unwrap();
        assert_eq!(attempt.effect(), SynchronousFileCancelEffect::StageUserApc);
        let plan = self.frame();
        let outcome = if accepted {
            self.install(&plan);
            SynchronousFileCancelOutcome::Completed(SynchronousFileCancelReceipt::UserApcStaged)
        } else {
            SynchronousFileCancelOutcome::NotEntered(REFUSED)
        };
        self.table
            .record_cancellation(&mut attempt, outcome)
            .unwrap();
        plan
    }

    fn close(mut self) {
        self.pm.release_user_apc_claim(&mut self.claim).unwrap();
        self.files.release_io(FILE, ACTIVE).unwrap();
        self.files.release_file(FILE).unwrap();
        assert!(self.files.release_handle(FILE).unwrap().cleanup_required);
        assert_eq!(
            self.files.begin_cleanup(FILE),
            Ok(FileIoAcquireResult::Acquired)
        );
        self.files.mark_cleanup_lifecycle_started(FILE).unwrap();
        self.files.release_cleanup_io(FILE).unwrap();
        assert!(
            self.files
                .release_cleanup_reference(FILE)
                .unwrap()
                .close_required
        );
        assert!(self.table.is_empty());
    }
}

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn staging_and_reply_retirement_retries_preserve_one_exact_apc_and_native_continuation() {
    use SynchronousFileCancelEffect as Effect;
    use SynchronousFileCancelOutcome as Outcome;
    use SynchronousFileCancelReceipt as Receipt;
    let mut fixture = Fixture::new();
    fixture.cancel_file_wait();
    let original = fixture.registers;
    let failed = fixture.stage(false);
    assert_eq!(fixture.registers, original);
    assert_eq!(fixture.installed_frames, 0);
    assert_eq!(fixture.pm.peek_user_apc(fixture.tid), None);
    assert_eq!(fixture.pm.take_user_apc(fixture.tid), None);
    assert!(fixture.pm.claim_user_apc(fixture.tid).is_err());
    let installed = fixture.stage(true);
    assert_eq!(failed, installed);
    assert_eq!(word(&installed.frame, 0x18), APC.routine);
    assert_eq!(word(&installed.frame, 0xf8), original[0]);
    assert_eq!(word(&installed.frame, 0x98), original[1]);
    assert_eq!(word(&installed.frame, 0xa8), 1);
    assert_eq!(word(&installed.frame, 0xc8), u64::from(USER_APC));
    assert_eq!(fixture.pm.peek_user_apc(fixture.tid), Some(APC));
    assert_eq!(fixture.installed_frames, 1);
    fixture.record(Effect::SendUserApc, Outcome::NotEntered(REFUSED));
    assert_eq!(fixture.installed_frames, 1);
    assert!(fixture
        .pm
        .commit_user_apc_claim(&mut fixture.claim)
        .is_err());
    fixture.record(
        Effect::SendUserApc,
        Outcome::Completed(Receipt::UserApcReplySent),
    );
    fixture.sent_replies += 1;
    fixture.record(Effect::RetireApcReplyCap, Outcome::NotEntered(REFUSED));
    assert!(!fixture.cap_reusable);
    assert!(fixture
        .table
        .finish_cancellation(fixture.identity)
        .is_none());
    fixture.record(
        Effect::RetireApcReplyCap,
        Outcome::Completed(Receipt::UserApcReplyCapRetired),
    );
    fixture.cap_reusable = true;
    assert!(fixture
        .table
        .has_runtime_dependency_for_thread(u64::from(fixture.tid)));
    fixture.table.finish_cancellation(fixture.identity).unwrap();
    assert!(!fixture
        .table
        .has_runtime_dependency_for_thread(u64::from(fixture.tid)));
    assert_eq!(fixture.sent_replies, 1);
    assert_eq!(fixture.pm.take_user_apc(fixture.tid), Some(APC));
    assert_eq!(fixture.pm.take_user_apc(fixture.tid), None);
    fixture.close();
}

#[test]
fn uncertain_send_retains_staged_ownership_without_consuming_the_identical_next_apc() {
    let mut fixture = Fixture::new();
    fixture.cancel_file_wait();
    fixture.stage(true);
    fixture.record(
        SynchronousFileCancelEffect::SendUserApc,
        SynchronousFileCancelOutcome::Indeterminate(REFUSED),
    );
    assert!(fixture.table.begin_cancellation(fixture.identity).is_err());
    assert!(fixture
        .table
        .finish_cancellation(fixture.identity)
        .is_none());
    assert!(fixture
        .table
        .has_runtime_dependency_for_thread(u64::from(fixture.tid)));
    assert_eq!(fixture.installed_frames, 1);
    assert!(!fixture.cap_reusable);
    assert_eq!(fixture.pm.peek_user_apc(fixture.tid), Some(APC));
    fixture
        .table
        .request_cancellation(fixture.identity)
        .unwrap();
    assert!(fixture.table.begin_cancellation(fixture.identity).is_err());
    assert!(fixture
        .table
        .has_runtime_dependency_for_thread(u64::from(fixture.tid)));
    assert_eq!(fixture.pm.peek_user_apc(fixture.tid), Some(APC));
}

#[test]
fn teardown_during_staging_never_sends_or_replays_the_selected_apc() {
    use SynchronousFileCancelEffect as Effect;
    use SynchronousFileCancelOutcome as Outcome;
    use SynchronousFileCancelReceipt as Receipt;
    for installed_before_teardown in [false, true] {
        let mut fixture = Fixture::new();
        fixture.cancel_file_wait();
        let mut stage = fixture.table.begin_cancellation(fixture.identity).unwrap();
        assert_eq!(stage.effect(), Effect::StageUserApc);
        let plan = fixture.frame();
        if installed_before_teardown {
            fixture.install(&plan);
        }
        fixture
            .table
            .request_cancellation(fixture.identity)
            .unwrap();
        fixture.pm.terminate_thread(fixture.tid, 0).unwrap();
        assert!(fixture.table.begin_cancellation(fixture.identity).is_err());
        let outcome = if installed_before_teardown {
            Outcome::Completed(Receipt::UserApcStaged)
        } else {
            Outcome::NotEntered(REFUSED)
        };
        fixture
            .table
            .record_cancellation(&mut stage, outcome)
            .unwrap();
        assert!(!fixture.pm.validate_user_apc_claim(&fixture.claim));
        fixture
            .pm
            .release_user_apc_claim(&mut fixture.claim)
            .unwrap();
        assert_eq!(fixture.sent_replies, 0);
        assert_eq!(
            fixture.installed_frames,
            usize::from(installed_before_teardown)
        );
        fixture.record(
            Effect::RevokeReply,
            Outcome::Completed(Receipt::ReplyRevoked),
        );
        fixture.record(
            Effect::RetireReplyCap,
            Outcome::Completed(Receipt::ReplyCapRetired),
        );
        fixture.cap_reusable = true;
        fixture.table.finish_cancellation(fixture.identity).unwrap();
        assert!(!fixture.pm.has_user_apc(fixture.tid));
        fixture.close();
    }
}

#[test]
fn acknowledged_send_during_teardown_retires_its_reply_without_revoking_it() {
    use SynchronousFileCancelEffect as Effect;
    use SynchronousFileCancelOutcome as Outcome;
    use SynchronousFileCancelReceipt as Receipt;
    let mut fixture = Fixture::new();
    fixture.cancel_file_wait();
    fixture.stage(true);
    let mut send = fixture.table.begin_cancellation(fixture.identity).unwrap();
    assert_eq!(send.effect(), Effect::SendUserApc);
    fixture
        .table
        .request_cancellation(fixture.identity)
        .unwrap();
    fixture
        .table
        .record_cancellation(&mut send, Outcome::Completed(Receipt::UserApcReplySent))
        .unwrap();
    fixture.sent_replies += 1;
    fixture.record(Effect::RetireApcReplyCap, Outcome::NotEntered(REFUSED));
    assert!(!fixture.cap_reusable);
    fixture.record(
        Effect::RetireApcReplyCap,
        Outcome::Completed(Receipt::UserApcReplyCapRetired),
    );
    fixture.cap_reusable = true;
    fixture.table.finish_cancellation(fixture.identity).unwrap();
    assert_eq!((fixture.installed_frames, fixture.sent_replies), (1, 1));
    assert_eq!(fixture.pm.peek_user_apc(fixture.tid), Some(APC));
    fixture.close();
}
