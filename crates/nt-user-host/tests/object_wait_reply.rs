//! Ordinary wait ownership composed with real dispatcher, File/IOCP, and PM lifetimes.
//! Reply invocation, capability retirement, and physical runtime teardown are host fixtures.

use nt_io_completion::{
    CompletionPortTable, FileCompletionBinding, FileCompletionTable, FileIoAcquireResult,
    FileReferenceRelease,
};
use nt_kernel_exec::{
    poll_dispatchers, DispatcherObject, DispatcherWaitResult, EventKind, EventStore, MutantStore,
    SemaphoreStore,
};
use nt_process::{ProcessManager, UserApc};
use nt_user_host::object_wait::{
    ObjectWaitReplyDisposition as Disposition, ObjectWaitReplyEffect as Effect,
    ObjectWaitReplyOutcome as Outcome, ObjectWaitReplyPhase as Phase, ObjectWaiterIdentity,
    ObjectWaiterTable,
};
use nt_user_host::process_identity::{ProcessGeneration, ProcessIdentity};
use nt_user_host::provider_logical_caller::{ProviderCallerError, ProviderLogicalCaller};
use nt_user_host::thread_binding::ThreadBinding;

const FILE: u64 = 17;
const CAP: u64 = 47;
const REFUSED: u32 = 13;
const TIMEOUT: u64 = 0x102;
const APC: UserApc = UserApc {
    routine: 0x8014_0000,
    normal_context: 0x11,
    system_argument1: 0x22,
    system_argument2: 0x33,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Wait {
    caller: ProviderLogicalCaller,
    cap: u64,
    reference_followup: Option<(usize, FileReferenceRelease)>,
    sent: bool,
}

struct Fixture {
    pm: ProcessManager,
    binding: ThreadBinding<()>,
    table: ObjectWaiterTable<Wait>,
    id: ObjectWaiterIdentity,
    files: FileCompletionTable<1>,
    ports: CompletionPortTable<1, 1>,
    references: usize,
    released: usize,
    sends: usize,
    revokes: usize,
    retired: usize,
    close_followups: usize,
}

impl Fixture {
    fn new(references: usize) -> Self {
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("ordinary-wait.exe", None, None);
        pm.create_thread(pid, 0x1000, 0, false).unwrap();
        let tid = pm.create_thread(pid, 0x2000, 0, false).unwrap();
        let binding = ThreadBinding {
            pi: 0,
            process: ProcessIdentity {
                pid,
                generation: ProcessGeneration::Hosted(3),
            },
            tid: u64::from(tid),
            badge: 5,
            role: (),
            tcb: 8,
            reservations: None,
        };
        let caller =
            ProviderLogicalCaller::capture(binding, pm.thread_lifetime(tid).unwrap()).unwrap();
        let mut table = ObjectWaiterTable::new();
        let id = table
            .insert(Wait {
                caller,
                cap: CAP,
                reference_followup: None,
                sent: false,
            })
            .unwrap();
        let mut files = FileCompletionTable::new();
        let mut ports = CompletionPortTable::new();
        if references != 0 {
            files.insert_file(FILE, 7, false).unwrap();
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
            for _ in 0..references {
                files.retain_file(FILE).unwrap();
            }
            assert!(files.release_handle(FILE).unwrap().cleanup_required);
            assert_eq!(files.begin_cleanup(FILE), Ok(FileIoAcquireResult::Bypassed));
            files.mark_cleanup_lifecycle_started(FILE).unwrap();
            assert!(
                !files
                    .release_cleanup_reference(FILE)
                    .unwrap()
                    .close_required
            );
        }
        Self {
            pm,
            binding,
            table,
            id,
            files,
            ports,
            references,
            released: 0,
            sends: 0,
            revokes: 0,
            retired: 0,
            close_followups: 0,
        }
    }

    fn select(&mut self, status: u64) {
        self.table
            .claim_reply(self.id, self.references, status)
            .unwrap();
    }

    fn refused(&mut self, effect: Effect) {
        let mut attempt = self.table.begin_reply_step(self.id).unwrap();
        assert_eq!(attempt.effect(), effect);
        self.table
            .record_reply_step(&mut attempt, Outcome::NotEntered(REFUSED))
            .unwrap();
    }

    fn release(&mut self, index: usize) {
        let mut attempt = self.table.begin_reply_step(self.id).unwrap();
        assert_eq!(attempt.effect(), Effect::ReleaseReference { index });
        assert!(self
            .table
            .reply(self.id)
            .unwrap()
            .payload
            .reference_followup
            .is_none());
        let receipt = self.files.release_file(FILE).unwrap();
        self.released += 1;
        self.table
            .update_reply_payload(&attempt, |wait| {
                wait.reference_followup = Some((index, receipt));
            })
            .unwrap();
        self.table
            .record_reply_step(
                &mut attempt,
                Outcome::Completed(Effect::ReleaseReference { index }),
            )
            .unwrap();
        assert_eq!(
            self.table.reply(self.id).unwrap().remaining_references,
            index
        );
    }

    fn followup(&mut self, index: usize) {
        let mut attempt = self.table.begin_reply_step(self.id).unwrap();
        assert_eq!(attempt.effect(), Effect::ReferenceFollowup { index });
        let (receipt_index, receipt) = self
            .table
            .reply(self.id)
            .unwrap()
            .payload
            .reference_followup
            .unwrap();
        assert_eq!(receipt_index, index);
        if let Some(port) = receipt.port_id {
            self.ports.release(port).unwrap();
        }
        self.close_followups += usize::from(receipt.close_required);
        self.table
            .update_reply_payload(&attempt, |wait| wait.reference_followup = None)
            .unwrap();
        self.table
            .record_reply_step(
                &mut attempt,
                Outcome::Completed(Effect::ReferenceFollowup { index }),
            )
            .unwrap();
    }

    fn release_all(&mut self) {
        for index in (0..self.references).rev() {
            self.release(index);
            self.followup(index);
        }
    }

    fn send(&mut self) -> u64 {
        let mut attempt = self.table.begin_reply_step(self.id).unwrap();
        assert_eq!(attempt.effect(), Effect::Send);
        let wait = *self.table.reply(self.id).unwrap().payload;
        assert_eq!(
            wait.caller.validate(
                Some(self.binding),
                self.pm.thread_lifetime(self.binding.tid as u32)
            ),
            Ok(())
        );
        assert!(!wait.sent);
        assert_ne!(wait.cap, 0);
        self.sends += 1;
        self.table
            .update_reply_payload(&attempt, |wait| wait.sent = true)
            .unwrap();
        let status = attempt.status();
        self.table
            .record_reply_step(&mut attempt, Outcome::Completed(Effect::Send))
            .unwrap();
        status
    }

    fn cap_effect(&mut self, effect: Effect) {
        let mut attempt = self.table.begin_reply_step(self.id).unwrap();
        assert_eq!(attempt.effect(), effect);
        assert_ne!(self.table.reply(self.id).unwrap().payload.cap, 0);
        match effect {
            Effect::RevokeReply => self.revokes += 1,
            Effect::RetireSentReply | Effect::RetypeReply => {
                self.retired += 1;
                self.table
                    .update_reply_payload(&attempt, |wait| wait.cap = 0)
                    .unwrap();
            }
            _ => panic!("not a capability effect"),
        }
        self.table
            .record_reply_step(&mut attempt, Outcome::Completed(effect))
            .unwrap();
    }

    fn finish(&mut self) -> Wait {
        assert_eq!(self.table.reply(self.id).unwrap().phase, Phase::Complete);
        let removed = self.table.finish_reply(self.id).unwrap();
        assert_eq!(removed.cap, 0);
        assert!(removed.reference_followup.is_none());
        assert_eq!(self.released, self.references);
        assert_eq!(self.retired, 1);
        assert!(self.table.finish_reply(self.id).is_none());
        removed
    }
}

#[test]
fn selected_synchronization_event_result_survives_reply_retry_without_consuming_a_later_signal() {
    let mut f = Fixture::new(0);
    let mut events = EventStore::new();
    let mut semaphores = SemaphoreStore::new();
    let mut mutants = MutantStore::new();
    events.initialize(3, EventKind::Synchronization, true);
    assert_eq!(
        poll_dispatchers(
            &mut events,
            &mut semaphores,
            &mut mutants,
            &[DispatcherObject::Event(3)],
            false
        ),
        DispatcherWaitResult::Signaled(0)
    );
    // Native WaitAny remaps the selected typed-object slot to its original caller index.
    f.select(7);
    assert!(!events.read_state(3));
    f.refused(Effect::Send);
    events.set_existing(3).unwrap();
    assert!(f.table.claim_reply(f.id, 0, TIMEOUT).is_err());
    assert!(f.table.claim_apc(f.id, 0).is_err());
    assert_eq!(f.send(), 7);
    f.refused(Effect::RetireSentReply);
    assert_eq!(f.table.reply(f.id).unwrap().payload.cap, CAP);
    assert_eq!(f.sends, 1);
    f.cap_effect(Effect::RetireSentReply);
    f.finish();
    assert!(events.read_state(3));
}

#[test]
fn wait_all_abandonment_is_retained_after_both_tokens_are_consumed() {
    let mut f = Fixture::new(0);
    let mut events = EventStore::new();
    let mut semaphores = SemaphoreStore::new();
    let mut mutants = MutantStore::new();
    events.initialize(3, EventKind::Synchronization, true);
    mutants.initialize(4, Some(99));
    assert_eq!(mutants.abandon_thread(99), 1);
    let objects = [
        DispatcherObject::Event(3),
        DispatcherObject::Mutant {
            identity: 4,
            thread: f.binding.tid,
        },
    ];
    assert_eq!(
        poll_dispatchers(&mut events, &mut semaphores, &mut mutants, &objects, true),
        DispatcherWaitResult::Abandoned(0)
    );
    f.select(0x80);
    f.refused(Effect::Send);
    assert!(!events.read_state(3));
    assert!(!mutants.query(4, f.binding.tid).unwrap().abandoned);
    assert_eq!(f.send(), 0x80);
    f.cap_effect(Effect::RetireSentReply);
    f.finish();
}

#[test]
fn file_reference_prefix_and_iocp_followup_survive_refusal_and_reentrant_teardown() {
    let mut f = Fixture::new(2);
    f.select(TIMEOUT);
    f.refused(Effect::ReleaseReference { index: 1 });
    assert_eq!(f.released, 0);
    f.release(1);
    f.refused(Effect::ReferenceFollowup { index: 1 });
    assert_eq!(f.released, 1);
    assert!(f.table.take(f.id).is_none());
    f.followup(1);
    f.release(0);
    let receipt = f
        .table
        .reply(f.id)
        .unwrap()
        .payload
        .reference_followup
        .unwrap();
    assert!(receipt.1.close_required);
    assert_eq!(receipt.1.port_id, Some(0));
    let mut followup = f.table.begin_reply_step(f.id).unwrap();
    assert_eq!(followup.effect(), Effect::ReferenceFollowup { index: 0 });
    f.table.request_reply_teardown(f.id).unwrap();
    assert!(!f.table.has_reply_runtime_dependency_matching(|_| true));
    assert!(f.table.begin_reply_step(f.id).is_err());
    f.table
        .record_reply_step(&mut followup, Outcome::NotEntered(REFUSED))
        .unwrap();
    f.followup(0);
    assert_eq!(f.close_followups, 1);
    assert_eq!(f.released, 2);
    f.cap_effect(Effect::RevokeReply);
    f.refused(Effect::RetypeReply);
    assert_eq!(f.revokes, 1);
    assert_eq!(f.table.reply(f.id).unwrap().payload.cap, CAP);
    f.cap_effect(Effect::RetypeReply);
    f.finish();
    assert_eq!(f.sends, 0);
    assert!(f.ports.retain(0).is_err());
}

#[test]
fn timeout_does_not_consume_a_late_signal_or_an_unrelated_user_apc() {
    let mut f = Fixture::new(2);
    f.pm.queue_kernel_user_apc(f.binding.tid as u32, APC)
        .unwrap();
    f.select(TIMEOUT);
    let mut events = EventStore::new();
    events.initialize(3, EventKind::Synchronization, true);
    f.release_all();
    f.refused(Effect::Send);
    assert_eq!(f.send(), TIMEOUT);
    f.cap_effect(Effect::RetireSentReply);
    f.finish();
    assert_eq!(f.pm.take_user_apc(f.binding.tid as u32), Some(APC));
    assert!(events.read_state(3));
    assert_eq!(f.close_followups, 1);
}

#[test]
fn entered_and_indeterminate_send_pin_original_runtime_without_replay_or_cap_release() {
    for indeterminate in [false, true] {
        let mut f = Fixture::new(0);
        f.select(TIMEOUT);
        let mut send = f.table.begin_reply_step(f.id).unwrap();
        assert_eq!(send.effect(), Effect::Send);
        if indeterminate {
            f.table
                .record_reply_step(&mut send, Outcome::Indeterminate(REFUSED))
                .unwrap();
        }
        drop(send);
        f.table.request_reply_teardown(f.id).unwrap();
        assert_eq!(f.table.reply(f.id).unwrap().disposition, Disposition::Reply);
        assert!(f.table.has_reply_runtime_dependency_matching(|wait| wait
            .caller
            .thread()
            .thread_id()
            == f.binding.tid as u32));
        assert!(f.table.begin_reply_step(f.id).is_err());
        assert!(f.table.take(f.id).is_none());
        assert!(f.table.finish_reply(f.id).is_none());
        assert_eq!(f.table.reply(f.id).unwrap().payload.cap, CAP);
        assert_eq!(f.revokes, 0);
        assert_eq!(f.retired, 0);
    }
}

#[test]
fn teardown_during_send_uses_its_definite_receipt_and_never_replies_to_a_replacement_lifetime() {
    for accepted in [false, true] {
        let mut f = Fixture::new(0);
        f.select(0x80);
        let old = *f.table.reply(f.id).unwrap().payload;
        let mut send = f.table.begin_reply_step(f.id).unwrap();
        f.table.request_reply_teardown(f.id).unwrap();
        assert!(f.table.has_reply_runtime_dependency_matching(|_| true));
        let outcome = if accepted {
            f.sends += 1;
            f.table
                .update_reply_payload(&send, |wait| wait.sent = true)
                .unwrap();
            Outcome::Completed(Effect::Send)
        } else {
            Outcome::NotEntered(REFUSED)
        };
        f.table.record_reply_step(&mut send, outcome).unwrap();
        assert!(!f.table.has_reply_runtime_dependency_matching(|_| true));
        let tid = f.binding.tid as u32;
        f.pm.terminate_thread(tid, 0).unwrap();
        let activation =
            f.pm.prepare_thread_activation(tid, 0x3000, 0, false, 0x7000, 0, false)
                .unwrap();
        f.pm.commit_thread_activation(activation).unwrap();
        let replacement_lifetime = f.pm.thread_lifetime(tid).unwrap();
        assert_eq!(
            old.caller
                .validate(Some(f.binding), Some(replacement_lifetime)),
            Err(ProviderCallerError::LifetimeChanged)
        );
        if accepted {
            f.cap_effect(Effect::RetireSentReply);
        } else {
            f.cap_effect(Effect::RevokeReply);
            f.cap_effect(Effect::RetypeReply);
        }
        assert_eq!(f.table.reply(f.id).unwrap().phase, Phase::Complete);
        let replacement = Wait {
            caller: ProviderLogicalCaller::capture(f.binding, replacement_lifetime).unwrap(),
            ..old
        };
        let replacement_id = f.table.insert(replacement).unwrap();
        // Completed old metadata may be kept for physical reconciliation. Matching numeric
        // identities do not authorize deleting this newly activated runtime or taking its Reply.
        assert!(!old
            .caller
            .validate(Some(f.binding), Some(replacement_lifetime))
            .is_ok());
        f.finish();
        assert_eq!(f.table.get_exact(replacement_id), Some(&replacement));
        assert_eq!(f.sends, usize::from(accepted));
        assert_eq!(f.revokes, usize::from(!accepted));
    }
}
