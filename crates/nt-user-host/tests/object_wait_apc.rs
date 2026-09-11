//! Real object-wait/APC/File ownership composed with the AMD64 frame builder.
//! User-memory publication, TCB installation, Reply sends and cap recycling are host fixtures,
//! not native execution proof. File and completion-port reference transitions are real policy.

use nt_io_completion::{
    CompletionPortTable, FileCompletionBinding, FileCompletionTable, FileIoAcquireResult,
    FileReferenceRelease,
};
use nt_process::{ProcessManager, ThreadId, UserApc, UserApcClaim};
use nt_thread_start::amd64_context::{
    prepare_user_apc, PreparedUserApc, UserApcContinuation, UserApcPayload,
    LEGACY_FLOATING_POINT_BYTES,
};
use nt_user_host::object_wait::{
    ObjectWaitApcDisposition as Disposition, ObjectWaitApcEffect as Effect,
    ObjectWaitApcOutcome as Outcome, ObjectWaitApcPhase as Phase, ObjectWaiterIdentity,
    ObjectWaiterTable,
};

const FILE: u64 = 17;
const REFUSED: u32 = 13;
const APC: UserApc = UserApc {
    routine: 0x8014_0000,
    normal_context: 0x11,
    system_argument1: 0x22,
    system_argument2: 0x33,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Wait {
    tid: ThreadId,
    cap: u64,
}

struct Fixture {
    pm: ProcessManager,
    claim: UserApcClaim,
    table: ObjectWaiterTable<Wait>,
    id: ObjectWaiterIdentity,
    waiter: Wait,
    files: FileCompletionTable<1>,
    ports: CompletionPortTable<1, 1>,
    receipt: Option<FileReferenceRelease>,
    registers: [u64; 20],
    releases: usize,
    installs: usize,
    sends: usize,
    cap_reusable: bool,
}

impl Fixture {
    fn new() -> Self {
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("object-apc.exe", None, None);
        pm.create_thread(pid, 0x1000, 0, false).unwrap();
        let tid = pm.create_thread(pid, 0x2000, 0, false).unwrap();
        pm.queue_kernel_user_apc(tid, APC).unwrap();
        pm.queue_kernel_user_apc(tid, APC).unwrap();
        let claim = pm.claim_user_apc(tid).unwrap().unwrap();
        let waiter = Wait { tid, cap: 47 };
        let mut table = ObjectWaiterTable::new();
        let id = table.insert(waiter).unwrap();
        table.claim_apc(id, 2).unwrap();

        // WaitAny may retain the same object twice. Final-handle cleanup completes first;
        // the two exact wait references keep its body and IOCP binding alive afterward.
        let mut files = FileCompletionTable::new();
        files.insert_file(FILE, 7, false).unwrap();
        let mut ports = CompletionPortTable::new();
        let port = ports.create(1).unwrap();
        assert_eq!(port, 0);
        ports.retain(port).unwrap();
        files
            .associate(
                FILE,
                FileCompletionBinding {
                    port_id: port,
                    key_context: 9,
                },
            )
            .unwrap();
        ports.release(port).unwrap();
        files.retain_file(FILE).unwrap();
        files.retain_file(FILE).unwrap();
        assert!(files.release_handle(FILE).unwrap().cleanup_required);
        assert_eq!(files.begin_cleanup(FILE), Ok(FileIoAcquireResult::Bypassed));
        files.mark_cleanup_lifecycle_started(FILE).unwrap();
        assert!(
            !files
                .release_cleanup_reference(FILE)
                .unwrap()
                .close_required
        );
        let mut registers = core::array::from_fn(|index| 0x100 + index as u64);
        registers[0] = 0x8010_1234;
        registers[1] = 0x10_0000 - 168;
        registers[2] = 0x202;
        Self {
            pm,
            claim,
            table,
            id,
            waiter,
            files,
            ports,
            receipt: None,
            registers,
            releases: 0,
            installs: 0,
            sends: 0,
            cap_reusable: false,
        }
    }

    fn record(&mut self, effect: Effect, outcome: Outcome) {
        let mut attempt = self.table.begin_apc_step(self.id).unwrap();
        assert_eq!(attempt.effect(), effect);
        self.table.record_apc_step(&mut attempt, outcome).unwrap();
    }

    fn release(&mut self, index: usize) {
        assert!(self.receipt.is_none());
        let mut attempt = self.table.begin_apc_step(self.id).unwrap();
        assert_eq!(attempt.effect(), Effect::ReleaseReference { index });
        self.receipt = Some(self.files.release_file(FILE).unwrap());
        self.releases += 1;
        self.table
            .record_apc_step(
                &mut attempt,
                Outcome::Completed(Effect::ReleaseReference { index }),
            )
            .unwrap();
        assert_eq!(self.table.apc(self.id).unwrap().remaining_references, index);
    }

    fn followup(&mut self, index: usize, accepted: bool) {
        let mut attempt = self.table.begin_apc_step(self.id).unwrap();
        assert_eq!(attempt.effect(), Effect::ReferenceFollowup { index });
        let receipt = self.receipt.unwrap();
        let outcome = if accepted {
            if let Some(port) = receipt.port_id {
                self.ports.release(port).unwrap();
            }
            self.receipt = None;
            Outcome::Completed(attempt.effect())
        } else {
            // A controlled pre-call refusal: neither the port nor this saved receipt changed.
            Outcome::NotEntered(REFUSED)
        };
        self.table.record_apc_step(&mut attempt, outcome).unwrap();
    }

    fn release_all(&mut self) {
        for index in [1, 0] {
            self.release(index);
            self.followup(index, true);
        }
    }

    fn frame(&self) -> PreparedUserApc {
        let mut fp = [0; LEGACY_FLOATING_POINT_BYTES];
        fp[..2].copy_from_slice(&0x037fu16.to_le_bytes());
        fp[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        let apc = self.claim.apc();
        prepare_user_apc(
            &self.registers,
            &fp,
            UserApcContinuation::NativeCall,
            0x8012_3000,
            UserApcPayload {
                routine: apc.routine,
                normal_context: apc.normal_context,
                system_argument1: apc.system_argument1,
                system_argument2: apc.system_argument2,
            },
            0xc0,
            0x7fff_ffff_ffff,
        )
        .unwrap()
    }

    fn install(&mut self, frame: &PreparedUserApc) {
        assert!(self.pm.validate_user_apc_claim(&self.claim));
        // Acknowledged host fixture for frame publication and a non-resuming TCB write.
        for index in 0..20 {
            if frame.install.register_mask & (1 << index) != 0 {
                self.registers[index] = frame.install.registers[index];
            }
        }
        self.installs += 1;
        assert_eq!(self.pm.commit_user_apc_claim(&mut self.claim), Ok(APC));
    }

    fn stage(&mut self, accepted: bool) -> PreparedUserApc {
        let mut attempt = self.table.begin_apc_step(self.id).unwrap();
        assert_eq!(attempt.effect(), Effect::Stage);
        let frame = self.frame();
        let outcome = if accepted {
            self.install(&frame);
            Outcome::Completed(Effect::Stage)
        } else {
            Outcome::NotEntered(REFUSED)
        };
        self.table.record_apc_step(&mut attempt, outcome).unwrap();
        frame
    }

    fn finish(&mut self) {
        let view = self.table.apc(self.id).unwrap();
        assert_eq!(view.phase, Phase::Complete);
        assert_eq!(
            self.table
                .has_runtime_dependency_matching(|wait| wait.tid == self.waiter.tid),
            view.disposition == Disposition::UserApc
        );
        self.pm.release_user_apc_claim(&mut self.claim).unwrap();
        assert_eq!(self.table.finish_apc(self.id), Some(self.waiter));
        assert!(!self.table.has_runtime_dependency_matching(|_| true));
        assert!(self.table.is_empty());
        assert_eq!(self.releases, 2);
    }
}

fn word(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

#[test]
fn reference_followup_and_stage_retries_never_repeat_release_or_consume_duplicate_apc() {
    let mut f = Fixture::new();
    assert!(!f
        .table
        .update_exact(f.id, |_| panic!("claimed row mutated")));
    assert_eq!(f.table.take(f.id), None);
    assert!(f.table.is_claimed(f.id));
    f.release(1);
    assert!(!f.receipt.unwrap().close_required);
    f.followup(1, true);
    f.release(0);
    let receipt = f.receipt.unwrap();
    assert!(receipt.close_required);
    assert_eq!(receipt.port_id, Some(0));
    f.followup(0, false);
    assert_eq!(f.receipt, Some(receipt));
    assert_eq!(f.releases, 2);
    assert!(f.files.binding(FILE).is_none());
    assert_eq!(f.ports.depth(0), Ok(0));
    assert!(f.table.finish_apc(f.id).is_none());
    f.followup(0, true);
    assert!(f.ports.depth(0).is_err());
    let original = f.registers;
    let failed = f.stage(false);
    assert_eq!(f.registers, original);
    assert!(f.pm.validate_user_apc_claim(&f.claim));
    assert_eq!(f.pm.peek_user_apc(f.waiter.tid), None);
    assert_eq!(f.pm.take_user_apc(f.waiter.tid), None);
    assert!(f.pm.claim_user_apc(f.waiter.tid).is_err());
    let installed = f.stage(true);
    assert_eq!(failed, installed);
    assert_eq!(word(&installed.frame, 0xf8), original[0]);
    assert_eq!(word(&installed.frame, 0x98), original[1]);
    assert_eq!(word(&installed.frame, 0xa8), 1);
    assert_eq!(word(&installed.frame, 0xc8), 0xc0);
    assert_eq!(f.installs, 1);
    assert_eq!(f.pm.peek_user_apc(f.waiter.tid), Some(APC));
    f.record(Effect::Send, Outcome::NotEntered(REFUSED));
    f.record(Effect::Send, Outcome::Completed(Effect::Send));
    f.sends += 1;
    f.record(Effect::RetireSentReply, Outcome::NotEntered(REFUSED));
    assert!(!f.cap_reusable);
    assert!(f.table.finish_apc(f.id).is_none());
    f.record(
        Effect::RetireSentReply,
        Outcome::Completed(Effect::RetireSentReply),
    );
    f.cap_reusable = true;
    f.finish();
    assert_eq!((f.installs, f.sends), (1, 1));
    assert_eq!(f.pm.take_user_apc(f.waiter.tid), Some(APC));
    assert_eq!(f.pm.take_user_apc(f.waiter.tid), None);
    let replacement = f.table.insert(f.waiter).unwrap();
    assert_eq!(replacement.slot(), f.id.slot());
    assert!(!f.table.update_exact(f.id, |_| panic!("stale update")));
    assert_eq!(f.table.take(f.id), None);
    assert_eq!(f.table.take(replacement), Some(f.waiter));
}

#[test]
fn ambiguous_send_cannot_restart_staging_or_send_even_after_teardown() {
    let mut f = Fixture::new();
    f.release_all();
    f.stage(true);
    f.record(Effect::Send, Outcome::Indeterminate(REFUSED));
    f.table.request_teardown(f.id).unwrap();
    assert!(f.table.begin_apc_step(f.id).is_err());
    assert!(f.table.next_apc_after(None).is_none());
    assert!(f.table.finish_apc(f.id).is_none());
    assert!(f.table.has_runtime_dependency_matching(|_| true));
    assert_eq!(f.table.apc(f.id).unwrap().disposition, Disposition::UserApc);
    assert_eq!(f.installs, 1);
    assert!(!f.cap_reusable);
    assert_eq!(f.pm.peek_user_apc(f.waiter.tid), Some(APC));
    assert!(f.pm.commit_user_apc_claim(&mut f.claim).is_err());
}

#[test]
fn teardown_during_stage_retains_exact_claim_until_the_entered_effect_resolves() {
    for installed in [false, true] {
        let mut f = Fixture::new();
        f.release_all();
        let mut attempt = f.table.begin_apc_step(f.id).unwrap();
        assert_eq!(attempt.effect(), Effect::Stage);
        let frame = f.frame();
        if installed {
            f.install(&frame);
        }
        f.table.request_teardown(f.id).unwrap();
        assert!(f.table.begin_apc_step(f.id).is_err());
        f.pm.terminate_thread(f.waiter.tid, 0).unwrap();
        let outcome = if installed {
            Outcome::Completed(Effect::Stage)
        } else {
            Outcome::NotEntered(REFUSED)
        };
        f.table.record_apc_step(&mut attempt, outcome).unwrap();
        assert_eq!(
            f.table.apc(f.id).unwrap().disposition,
            Disposition::Teardown
        );
        assert!(!f.pm.validate_user_apc_claim(&f.claim));
        f.record(Effect::RevokeReply, Outcome::Completed(Effect::RevokeReply));
        f.record(Effect::RetypeReply, Outcome::NotEntered(REFUSED));
        assert!(!f.cap_reusable);
        f.record(Effect::RetypeReply, Outcome::Completed(Effect::RetypeReply));
        f.cap_reusable = true;
        f.finish();
        assert_eq!(f.installs, usize::from(installed));
        assert_eq!(f.sends, 0);
        assert!(!f.pm.has_user_apc(f.waiter.tid));
    }
}

#[test]
fn teardown_during_send_distinguishes_acknowledged_reply_from_definite_refusal() {
    for acknowledged in [false, true] {
        let mut f = Fixture::new();
        f.release_all();
        f.stage(true);
        let mut attempt = f.table.begin_apc_step(f.id).unwrap();
        assert_eq!(attempt.effect(), Effect::Send);
        f.table.request_teardown(f.id).unwrap();
        let outcome = if acknowledged {
            Outcome::Completed(Effect::Send)
        } else {
            Outcome::NotEntered(REFUSED)
        };
        f.table.record_apc_step(&mut attempt, outcome).unwrap();
        if acknowledged {
            f.sends += 1;
            assert_eq!(
                f.table.apc(f.id).unwrap().disposition,
                Disposition::Teardown
            );
            assert!(!f.table.has_runtime_dependency_matching(|_| true));
            f.record(
                Effect::RetireSentReply,
                Outcome::Completed(Effect::RetireSentReply),
            );
        } else {
            assert_eq!(
                f.table.apc(f.id).unwrap().disposition,
                Disposition::Teardown
            );
            f.record(Effect::RevokeReply, Outcome::Completed(Effect::RevokeReply));
            f.record(Effect::RetypeReply, Outcome::Completed(Effect::RetypeReply));
        }
        f.cap_reusable = true;
        f.finish();
        assert_eq!(f.sends, usize::from(acknowledged));
        assert_eq!(f.installs, 1);
        assert_eq!(f.pm.peek_user_apc(f.waiter.tid), Some(APC));
    }
}

#[test]
fn teardown_cleanup_outlives_old_queue_without_unclaiming_its_replacement() {
    for terminate_old in [false, true] {
        let mut f = Fixture::new();
        f.release(1);
        f.followup(1, true);
        f.release(0);
        let receipt = f.receipt;
        f.followup(0, false);
        f.table.request_teardown(f.id).unwrap();
        assert!(!f.table.has_runtime_dependency_matching(|_| true));
        assert!(f.table.is_claimed(f.id));
        assert_eq!(f.table.take(f.id), None);
        let replacement_tid = if terminate_old {
            f.pm.terminate_thread(f.waiter.tid, 0).unwrap();
            let pid = f.pm.create_process("replacement.exe", None, None);
            f.pm.create_thread(pid, 0x3000, 0, false).unwrap()
        } else {
            assert!(f.pm.clear_user_apcs(f.waiter.tid));
            f.waiter.tid
        };
        f.pm.queue_kernel_user_apc(replacement_tid, APC).unwrap();
        let mut replacement = f.pm.claim_user_apc(replacement_tid).unwrap().unwrap();
        assert!(!f.pm.validate_user_apc_claim(&f.claim));
        assert_eq!(f.receipt, receipt);
        f.followup(0, true);
        assert!(f.ports.depth(0).is_err());
        f.record(Effect::RevokeReply, Outcome::NotEntered(REFUSED));
        assert!(!f.table.has_runtime_dependency_matching(|_| true));
        f.record(Effect::RevokeReply, Outcome::Completed(Effect::RevokeReply));
        f.record(Effect::RetypeReply, Outcome::NotEntered(REFUSED));
        assert!(!f.cap_reusable);
        assert!(f.pm.validate_user_apc_claim(&replacement));
        f.record(Effect::RetypeReply, Outcome::Completed(Effect::RetypeReply));
        f.cap_reusable = true;
        f.finish();
        assert_eq!((f.installs, f.sends), (0, 0));
        assert!(f.pm.validate_user_apc_claim(&replacement));
        assert_eq!(f.pm.peek_user_apc(replacement_tid), None);
        assert_eq!(f.pm.commit_user_apc_claim(&mut replacement), Ok(APC));
        assert_eq!(f.pm.take_user_apc(replacement_tid), None);
    }
}
