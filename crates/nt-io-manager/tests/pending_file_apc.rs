//! Pending-IRP APC ownership composed with real File policy, PM claims, and AMD64 frame plans.
//! Provider terminal/cancel, user-memory/TCB, Reply, and capability outcomes are host fixtures.

use nt_io_completion::{FileCompletionTable, FileIoAcquireResult, FileIoMode};
use nt_io_manager::*;
use nt_process::{ProcessManager, UserApc, UserApcClaim};
use nt_thread_start::amd64_context::{
    prepare_user_apc, PreparedUserApc, UserApcContinuation, UserApcPayload,
    LEGACY_FLOATING_POINT_BYTES,
};
use nt_thread_start::CONTEXT_RAX_OFFSET;
use nt_user_host::process_identity::{ProcessGeneration, ProcessIdentity};
use nt_user_host::provider_logical_caller::{ProviderCallerError, ProviderLogicalCaller};
use nt_user_host::thread_binding::ThreadBinding;
use PendingFileApcEffect as Effect;
use PendingFileApcOutcome as Outcome;
use PendingFileApcPhase as Phase;
use PendingFileApcReceipt as Receipt;

const FILE: u64 = 17;
const IRP: u64 = 91;
const CAP: u64 = 47;
const REFUSED: u32 = 13;
const SUCCESS: u32 = 0;
const PENDING: u32 = 0x103;
const CANCELLED: u32 = 0xc000_0120;
const MODE: FileIoMode = FileIoMode::SynchronousAlertable;
const APC: UserApc = UserApc {
    routine: 0x8014_0000,
    normal_context: 0x11,
    system_argument1: 0x22,
    system_argument2: 0x33,
};

struct Fixture {
    pm: ProcessManager,
    binding: ThreadBinding<()>,
    caller: ProviderLogicalCaller,
    claim: UserApcClaim,
    files: FileCompletionTable<1>,
    table: PendingFileIoTable,
    id: PendingFileIoIdentity,
    registers: [u64; 20],
    installed: usize,
}

impl Fixture {
    fn new() -> Self {
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("pending-apc.exe", None, None);
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
        let caller =
            ProviderLogicalCaller::capture(binding, pm.thread_lifetime(tid).unwrap()).unwrap();
        pm.queue_kernel_user_apc(tid, APC).unwrap();
        pm.queue_kernel_user_apc(tid, APC).unwrap();
        let claim = pm.claim_user_apc(tid).unwrap().unwrap();
        let mut files = FileCompletionTable::new();
        files.insert_file_with_mode(FILE, 7, MODE).unwrap();
        assert_eq!(
            files.acquire_file_io(FILE, binding.tid),
            Ok(FileIoAcquireResult::Acquired)
        );
        files.set_signaled(FILE, false).unwrap();
        let mut table = PendingFileIoTable::new();
        let reservation = table.reserve().unwrap();
        let id = reservation.identity();
        table
            .park_reserved(
                reservation,
                PendingFileIo {
                    route: PendingFileRoute::Hosted(FILE),
                    irp_id: IRP,
                    major: nt_io_abi::major::IRP_MJ_READ,
                    pi: 0,
                    tid: binding.tid,
                    badge: binding.badge,
                    reply_cap: CAP,
                    reply_required: true,
                    native_call_transport: true,
                    iosb_va: 0x2000,
                    event_obj_idx: u64::MAX,
                    signal_file: true,
                    busy: Some(PendingFileBusy::new(FileIoBusyOwner {
                        key: FileIoWaitKey::Hosted(FILE),
                        tid: binding.tid,
                        mode: MODE,
                    })),
                    ..PendingFileIo::default()
                },
            )
            .unwrap();
        let mut registers = core::array::from_fn(|index| 0x100 + index as u64);
        registers[0] = 0x8010_1234;
        registers[1] = 0x10_0000 - 168;
        registers[2] = 0x202;
        Self {
            pm,
            binding,
            caller,
            claim,
            files,
            table,
            id,
            registers,
            installed: 0,
        }
    }

    fn request(&mut self) {
        assert!(self.pm.validate_user_apc_claim(&self.claim));
        self.table
            .request_user_apc_interruption(self.id, IRP)
            .unwrap();
    }

    fn frame(&self) -> PreparedUserApc {
        let apc = self.claim.apc();
        let terminal_status = self.table.apc(self.id).unwrap().terminal_status.unwrap();
        let mut floating = [0; LEGACY_FLOATING_POINT_BYTES];
        floating[..2].copy_from_slice(&0x037fu16.to_le_bytes());
        floating[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        prepare_user_apc(
            &self.registers,
            &floating,
            UserApcContinuation::NativeCall,
            0x8012_3000,
            UserApcPayload {
                routine: apc.routine,
                normal_context: apc.normal_context,
                system_argument1: apc.system_argument1,
                system_argument2: apc.system_argument2,
            },
            terminal_status,
            0x7fff_ffff_ffff,
        )
        .unwrap()
    }

    fn install(&mut self, frame: &PreparedUserApc) {
        assert_eq!(
            self.caller.validate(
                Some(self.binding),
                self.pm.thread_lifetime(self.binding.tid as u32)
            ),
            Ok(())
        );
        assert!(self.pm.validate_user_apc_claim(&self.claim));
        for index in 0..self.registers.len() {
            if frame.install.register_mask & (1 << index) != 0 {
                self.registers[index] = frame.install.registers[index];
            }
        }
        self.installed += 1;
        assert_eq!(self.pm.commit_user_apc_claim(&mut self.claim), Ok(APC));
    }

    fn record(&mut self, effect: Effect, outcome: Outcome) -> Phase {
        let mut attempt = self.table.begin_apc_step(self.id).unwrap();
        assert_eq!(attempt.effect(), effect);
        self.table.record_apc_step(&mut attempt, outcome).unwrap()
    }

    fn selected(&mut self) {
        self.request();
        assert_eq!(
            self.record(
                Effect::CancelSelect,
                Outcome::Completed(Receipt::CancelSelected)
            ),
            Phase::AwaitTerminal
        );
    }

    fn terminal_prefix(&mut self, status: u32) {
        let mut lease = self.table.begin_apc_delivery(self.id, IRP).unwrap();
        assert!(self.table.begin_apc_delivery(self.id, IRP).is_err());
        self.table
            .mark_delivery_exact(self.id.slot(), IRP, IO_DELIVERY_IOSB_PUBLISHED)
            .unwrap();
        self.files.set_signaled(FILE, true).unwrap();
        self.table
            .mark_delivery_exact(self.id.slot(), IRP, IO_DELIVERY_FILE_PUBLISHED)
            .unwrap();
        let mut release = self
            .table
            .begin_busy_release_exact(self.id.slot(), IRP)
            .unwrap();
        let released = self
            .files
            .release_io(FILE, self.binding.tid)
            .map(|result| result.waiters);
        self.table
            .record_busy_release(&mut release, released)
            .unwrap();
        self.table.finish_apc_delivery(&mut lease).unwrap();
        assert!(self.table.ready_apc_terminal(self.id, IRP, status).is_err());
        let mut wake = self
            .table
            .begin_busy_wake_exact(self.id.slot(), IRP)
            .unwrap();
        assert_eq!(wake.waiters(), 0);
        assert_eq!(self.files.io_lock_owner(FILE), Ok(None));
        assert_eq!(self.files.io_waiter_count(FILE), Ok(0));
        self.table.record_busy_wake(&mut wake, Ok(())).unwrap();
        self.table.ready_apc_terminal(self.id, IRP, status).unwrap();
    }

    fn stage(&mut self) {
        let mut attempt = self.table.begin_apc_step(self.id).unwrap();
        assert_eq!(attempt.effect(), Effect::Stage);
        let frame = self.frame();
        self.install(&frame);
        self.table
            .record_apc_step(&mut attempt, Outcome::Completed(Receipt::Staged))
            .unwrap();
    }

    fn release_claim(&mut self) {
        let mut attempt = self.table.begin_apc_step(self.id).unwrap();
        assert_eq!(attempt.effect(), Effect::ReleaseApcClaim);
        self.pm.release_user_apc_claim(&mut self.claim).unwrap();
        self.table
            .record_apc_step(&mut attempt, Outcome::Completed(Receipt::ApcClaimReleased))
            .unwrap();
    }

    fn finish_delivered(&mut self) {
        self.release_claim();
        assert_eq!(
            self.table.finish_apc(self.id).unwrap().phase,
            Phase::Complete
        );
        self.table
            .mark_backend_acked_exact(self.id.slot(), IRP)
            .unwrap();
        self.table.finish_owner_exact(self.id, IRP).unwrap();
        assert!(!self.files.release_file(FILE).unwrap().close_required);
        assert!(self.table.is_empty());
    }
}

#[test]
fn ordinary_prefix_defers_apc_admission_without_losing_the_exact_queued_selection() {
    let mut fixture = Fixture::new();
    let original = fixture.table.get_exact(fixture.id).unwrap();
    let mut lease = fixture.table.begin_apc_delivery(fixture.id, IRP).unwrap();
    assert!(fixture.table.apc(fixture.id).is_err());
    assert_eq!(
        fixture.table.request_user_apc_interruption(fixture.id, IRP),
        Err(PendingFileApcError::InvalidPhase)
    );
    fixture
        .pm
        .release_user_apc_claim(&mut fixture.claim)
        .unwrap();
    assert!(!fixture.pm.validate_user_apc_claim(&fixture.claim));
    assert_eq!(
        fixture.pm.peek_user_apc(fixture.binding.tid as u32),
        Some(APC)
    );
    assert!(fixture
        .table
        .user_apc_interrupt_candidate(fixture.binding.tid)
        .is_none());
    assert_eq!(fixture.table.get_exact(fixture.id), Some(original));

    // The controlled lookup found no terminal result. Returning the lease publishes no completion
    // surfaces, so the deferred scanner can reclaim the queued APC for the same pending owner.
    assert_eq!(fixture.table.finish_apc_delivery(&mut lease), Ok(None));
    assert!(fixture.table.finish_apc_delivery(&mut lease).is_err());
    assert_eq!(
        fixture
            .table
            .user_apc_interrupt_candidate(fixture.binding.tid),
        Some((fixture.id, original))
    );
    fixture.claim = fixture
        .pm
        .claim_user_apc(fixture.binding.tid as u32)
        .unwrap()
        .unwrap();
    fixture.request();
    assert!(fixture.pm.validate_user_apc_claim(&fixture.claim));
    fixture.record(
        Effect::CancelSelect,
        Outcome::Completed(Receipt::CancelNotSelected),
    );
    fixture.release_claim();
    fixture.table.finish_apc(fixture.id).unwrap();
    assert_eq!(fixture.installed, 0);
    assert_eq!(
        fixture.pm.take_user_apc(fixture.binding.tid as u32),
        Some(APC)
    );
    assert_eq!(
        fixture.pm.take_user_apc(fixture.binding.tid as u32),
        Some(APC)
    );
    assert_eq!(fixture.pm.take_user_apc(fixture.binding.tid as u32), None);
}

#[test]
fn terminal_winning_selection_releases_claim_without_staging_or_consuming_duplicate() {
    // The exact provider lookup is terminal before cancellation, or becomes terminal while its
    // entered selection runs. In both cases the provider reports NotSelected, never Cancelled.
    for terminal_before_request in [true, false] {
        let mut fixture = Fixture::new();
        let mut provider_terminal = terminal_before_request.then_some(SUCCESS);
        fixture.request();
        let mut cancel = fixture.table.begin_apc_step(fixture.id).unwrap();
        assert_eq!(cancel.effect(), Effect::CancelSelect);
        provider_terminal.get_or_insert(SUCCESS);
        assert!(fixture.table.begin_apc_delivery(fixture.id, IRP).is_err());
        fixture
            .table
            .record_apc_step(&mut cancel, Outcome::Completed(Receipt::CancelNotSelected))
            .unwrap();
        assert_eq!(provider_terminal, Some(SUCCESS));
        assert_eq!(fixture.table.apc(fixture.id).unwrap().selected, Some(false));
        fixture.release_claim();
        fixture.table.finish_apc(fixture.id).unwrap();
        assert_eq!(fixture.installed, 0);
        assert_eq!(
            fixture.pm.take_user_apc(fixture.binding.tid as u32),
            Some(APC)
        );
        assert_eq!(
            fixture.pm.take_user_apc(fixture.binding.tid as u32),
            Some(APC)
        );
        assert_eq!(
            fixture.files.io_lock_owner(FILE),
            Ok(Some(fixture.binding.tid))
        );
        assert!(fixture.table.get_exact(fixture.id).unwrap().reply_required);
    }
}

#[test]
fn selected_cancellation_waits_for_real_terminal_and_busy_wake_even_when_result_is_success() {
    for status in [SUCCESS, CANCELLED] {
        let mut fixture = Fixture::new();
        fixture.selected();
        assert_eq!(fixture.table.apc(fixture.id).unwrap().terminal_status, None);
        assert!(fixture
            .table
            .ready_apc_terminal(fixture.id, IRP, PENDING)
            .is_err());
        assert!(fixture
            .table
            .ready_apc_terminal(fixture.id, IRP, status)
            .is_err());
        assert!(fixture.table.begin_apc_step(fixture.id).is_err());
        assert!(fixture
            .table
            .claim_reply_cap_exact(fixture.id.slot(), IRP)
            .is_none());
        assert!(fixture
            .table
            .begin_busy_release_exact(fixture.id.slot(), IRP)
            .is_err());
        fixture.terminal_prefix(status);
        assert_eq!(
            fixture.table.apc(fixture.id).unwrap().terminal_status,
            Some(status)
        );
        let frame = fixture.frame();
        let rax_offset = CONTEXT_RAX_OFFSET as usize;
        assert_eq!(
            u64::from_le_bytes(frame.frame[rax_offset..rax_offset + 8].try_into().unwrap()),
            u64::from(status)
        );
        fixture.stage();
        fixture.record(Effect::Send, Outcome::Completed(Receipt::Sent));
        fixture.record(
            Effect::RetireSentReply,
            Outcome::Completed(Receipt::SentReplyRetired),
        );
        fixture.finish_delivered();
        assert_eq!(
            fixture.pm.take_user_apc(fixture.binding.tid as u32),
            Some(APC)
        );
        assert_eq!(fixture.pm.take_user_apc(fixture.binding.tid as u32), None);
    }
}

#[test]
fn cancellation_and_send_uncertainty_are_retained_without_repeating_entered_effects() {
    for effect in [Effect::CancelSelect, Effect::Send] {
        let mut fixture = Fixture::new();
        if effect == Effect::Send {
            fixture.selected();
            fixture.terminal_prefix(SUCCESS);
            fixture.stage();
        } else {
            fixture.request();
        }
        assert_eq!(
            fixture.record(effect, Outcome::Indeterminate(REFUSED)),
            Phase::Indeterminate {
                effect,
                status: REFUSED
            }
        );
        fixture.table.request_apc_teardown(fixture.id).unwrap();
        assert!(fixture.table.begin_apc_step(fixture.id).is_err());
        assert!(fixture.table.finish_apc(fixture.id).is_err());
        assert!(fixture
            .table
            .has_apc_runtime_dependency_matching(|pending| pending.tid == fixture.binding.tid));
        assert!(fixture.table.finish_owner_exact(fixture.id, IRP).is_none());
        assert_eq!(
            fixture.table.apc(fixture.id).unwrap().pending.reply_cap,
            CAP
        );
    }
}

#[test]
fn frame_refusal_preserves_exact_claim_and_sent_cap_retirement_never_restages() {
    let mut fixture = Fixture::new();
    fixture.selected();
    fixture.terminal_prefix(SUCCESS);
    let original = fixture.registers;
    let plan = fixture.frame();
    fixture.record(Effect::Stage, Outcome::NotEntered(REFUSED));
    assert_eq!(fixture.registers, original);
    assert!(fixture.pm.validate_user_apc_claim(&fixture.claim));
    assert!(fixture
        .pm
        .claim_user_apc(fixture.binding.tid as u32)
        .is_err());
    assert_eq!(fixture.pm.peek_user_apc(fixture.binding.tid as u32), None);
    assert_eq!(fixture.frame(), plan);
    fixture.stage();
    fixture.record(Effect::Send, Outcome::NotEntered(REFUSED));
    fixture.record(Effect::Send, Outcome::Completed(Receipt::Sent));
    fixture.record(Effect::RetireSentReply, Outcome::NotEntered(REFUSED));
    assert_eq!(fixture.installed, 1);
    assert_eq!(
        fixture.table.apc(fixture.id).unwrap().pending.reply_cap,
        CAP
    );
    assert!(fixture
        .table
        .mark_backend_acked_exact(fixture.id.slot(), IRP)
        .is_none());
    fixture.record(
        Effect::RetireSentReply,
        Outcome::Completed(Receipt::SentReplyRetired),
    );
    assert_eq!(fixture.table.apc(fixture.id).unwrap().pending.reply_cap, 0);
    fixture.finish_delivered();
}

#[test]
fn entered_terminal_prefix_is_a_teardown_barrier_until_its_exact_lease_returns() {
    let mut fixture = Fixture::new();
    fixture.selected();
    let mut lease = fixture.table.begin_apc_delivery(fixture.id, IRP).unwrap();
    fixture.table.request_apc_teardown(fixture.id).unwrap();
    assert!(fixture.table.has_apc_runtime_dependency_matching(|_| true));
    assert!(fixture.table.begin_apc_step(fixture.id).is_err());
    assert!(
        !fixture
            .table
            .get_exact(fixture.id)
            .unwrap()
            .consumer_abandoned
    );
    assert!(fixture
        .table
        .abandon_transfer_owner_exact(fixture.id, IRP)
        .is_none());
    fixture.table.finish_apc_delivery(&mut lease).unwrap();
    assert!(fixture.table.finish_apc_delivery(&mut lease).is_err());
    assert!(
        fixture
            .table
            .get_exact(fixture.id)
            .unwrap()
            .consumer_abandoned
    );
    assert!(!fixture.table.has_apc_runtime_dependency_matching(|_| true));
    fixture.record(
        Effect::RevokeReply,
        Outcome::Completed(Receipt::ReplyRevoked),
    );
    fixture.record(Effect::RetypeReply, Outcome::NotEntered(REFUSED));
    assert_eq!(
        fixture.files.io_lock_owner(FILE),
        Ok(Some(fixture.binding.tid))
    );
    fixture.record(
        Effect::RetypeReply,
        Outcome::Completed(Receipt::ReplyRetyped),
    );
    fixture.release_claim();
    fixture.table.finish_apc(fixture.id).unwrap();
    // APC teardown did not invent a terminal completion or release the live IRP's Busy/reference.
    assert!(fixture
        .table
        .get_exact(fixture.id)
        .unwrap()
        .busy
        .unwrap()
        .release_pending());
    assert!(fixture.table.finish_owner_exact(fixture.id, IRP).is_none());
}

#[test]
fn teardown_during_stage_or_send_defers_runtime_removal_until_definite_outcome() {
    for effect in [Effect::Stage, Effect::Send] {
        for accepted in [false, true] {
            let mut fixture = Fixture::new();
            fixture.selected();
            fixture.terminal_prefix(SUCCESS);
            if effect == Effect::Send {
                fixture.stage();
            }
            let mut attempt = fixture.table.begin_apc_step(fixture.id).unwrap();
            assert_eq!(attempt.effect(), effect);
            fixture.table.request_apc_teardown(fixture.id).unwrap();
            assert!(fixture.table.has_apc_runtime_dependency_matching(|_| true));
            if accepted && effect == Effect::Stage {
                let plan = fixture.frame();
                fixture.install(&plan);
            }
            let outcome = if accepted {
                Outcome::Completed(if effect == Effect::Stage {
                    Receipt::Staged
                } else {
                    Receipt::Sent
                })
            } else {
                Outcome::NotEntered(REFUSED)
            };
            fixture
                .table
                .record_apc_step(&mut attempt, outcome)
                .unwrap();
            assert!(!fixture.table.has_apc_runtime_dependency_matching(|_| true));

            // The old exact PM selection may outlive runtime teardown. Reusing the same TID,
            // binding values and duplicate payload cannot make its late release own the new APC.
            let tid = fixture.binding.tid as u32;
            fixture.pm.terminate_thread(tid, 0).unwrap();
            let plan = fixture
                .pm
                .prepare_thread_activation(tid, 0x3000, 0, false, 0x7000, 0, false)
                .unwrap();
            fixture.pm.commit_thread_activation(plan).unwrap();
            fixture.pm.queue_kernel_user_apc(tid, APC).unwrap();
            let mut replacement = fixture.pm.claim_user_apc(tid).unwrap().unwrap();
            assert_eq!(
                fixture
                    .caller
                    .validate(Some(fixture.binding), fixture.pm.thread_lifetime(tid)),
                Err(ProviderCallerError::LifetimeChanged)
            );
            if effect == Effect::Send && accepted {
                fixture.record(
                    Effect::RetireSentReply,
                    Outcome::Completed(Receipt::SentReplyRetired),
                );
            } else {
                fixture.record(
                    Effect::RevokeReply,
                    Outcome::Completed(Receipt::ReplyRevoked),
                );
                fixture.record(
                    Effect::RetypeReply,
                    Outcome::Completed(Receipt::ReplyRetyped),
                );
            }
            fixture.release_claim();
            assert!(fixture.pm.validate_user_apc_claim(&replacement));
            fixture.table.finish_apc(fixture.id).unwrap();
            assert_eq!(fixture.pm.commit_user_apc_claim(&mut replacement), Ok(APC));
            assert!(
                fixture
                    .table
                    .get_exact(fixture.id)
                    .unwrap()
                    .consumer_abandoned
            );
        }
    }
}

#[test]
fn local_zero_routes_require_their_own_terminal_receipt_and_preserve_exact_peers() {
    let mut fixture = Fixture::new();
    let mut locals = Vec::new();
    for (offset, file) in [
        LocalFileObject::ReadonlyFile(0),
        LocalFileObject::Overlay(0),
    ]
    .into_iter()
    .enumerate()
    {
        let irp = IRP + 1 + offset as u64;
        let slot = fixture
            .table
            .park(PendingFileIo {
                route: PendingFileRoute::Local(file),
                irp_id: irp,
                major: nt_io_abi::major::IRP_MJ_LOCK_CONTROL,
                operation: PendingFileIoOperation::LocalByteLock(PendingLocalByteLock {
                    wait_id: irp,
                    status: PENDING,
                    alertable: true,
                }),
                tid: fixture.binding.tid,
                reply_cap: CAP + irp,
                reply_required: true,
                iosb_va: 0x3000,
                event_obj_idx: u64::MAX,
                ..PendingFileIo::default()
            })
            .unwrap();
        locals.push((fixture.table.identity(slot).unwrap(), irp));
    }
    let (id, irp) = locals[0];
    fixture
        .table
        .request_user_apc_interruption(id, irp)
        .unwrap();
    let mut cancel = fixture.table.begin_apc_step(id).unwrap();
    fixture
        .table
        .record_apc_step(&mut cancel, Outcome::Completed(Receipt::CancelSelected))
        .unwrap();
    let mut lease = fixture.table.begin_apc_delivery(id, irp).unwrap();
    assert!(fixture
        .table
        .complete_local_byte_lock_exact(irp, irp, SUCCESS));
    fixture
        .table
        .mark_delivery_exact(id.slot(), irp, IO_DELIVERY_IOSB_PUBLISHED)
        .unwrap();
    fixture.table.finish_apc_delivery(&mut lease).unwrap();
    assert!(fixture
        .table
        .ready_apc_terminal(id, irp, CANCELLED)
        .is_err());
    fixture.table.ready_apc_terminal(id, irp, SUCCESS).unwrap();
    assert_eq!(
        fixture
            .table
            .get_exact(locals[1].0)
            .unwrap()
            .local_terminal_result(),
        None
    );
    assert!(fixture.table.apc(locals[1].0).is_err());
    assert!(fixture.table.apc(fixture.id).is_err());
    assert_eq!(
        fixture.files.io_lock_owner(FILE),
        Ok(Some(fixture.binding.tid))
    );
}
