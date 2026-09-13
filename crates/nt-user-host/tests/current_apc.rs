//! Current-thread APC ownership with real PM selection, caller lifetime, and AMD64 frame codec.
//! Main-Reply handoff, user-memory/context installation, and capability effects are host fixtures.

use nt_process::{ProcessManager, UserApc, UserApcClaim};
use nt_thread_start::amd64_context::{
    prepare_user_apc, CapturedAmd64Context, PreparedUserApc, UserApcContinuation, UserApcPayload,
    LEGACY_FLOATING_POINT_BYTES,
};
use nt_thread_start::{
    CONTEXT_R10_OFFSET, CONTEXT_RAX_OFFSET, CONTEXT_RIP_OFFSET, CONTEXT_RSI_OFFSET,
    CONTEXT_RSP_OFFSET,
};
use nt_user_host::current_apc::{
    CurrentApcEffect as Effect, CurrentApcIdentity, CurrentApcOutcome as Outcome,
    CurrentApcPhase as Phase, CurrentApcTable,
};
use nt_user_host::process_identity::{ProcessGeneration, ProcessIdentity};
use nt_user_host::provider_logical_caller::{ProviderCallerError, ProviderLogicalCaller};
use nt_user_host::thread_binding::ThreadBinding;

const CAP: u64 = 47;
const REFUSED: u32 = 13;
const SUCCESS: u32 = 0;
const USER_APC: u32 = 0xc0;
const APC: UserApc = UserApc {
    routine: 0x8014_0000,
    normal_context: 0x11,
    system_argument1: 0x22,
    system_argument2: 0x33,
};

#[derive(Clone, Copy)]
struct Payload {
    caller: ProviderLogicalCaller,
    continuation: UserApcContinuation,
    status: u32,
}

struct Fixture {
    pm: ProcessManager,
    binding: ThreadBinding<()>,
    claim: UserApcClaim,
    table: CurrentApcTable<Payload>,
    id: CurrentApcIdentity,
    registers: [u64; 20],
    floating: [u8; LEGACY_FLOATING_POINT_BYTES],
    main_reply: u64,
    installs: usize,
    sends: usize,
    retired_caps: usize,
}

impl Fixture {
    fn new(continuation: UserApcContinuation, status: u32) -> Self {
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("current-apc.exe", None, None);
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
        let mut table = CurrentApcTable::new();
        let reservation = table.reserve().unwrap();
        let claim = pm.claim_user_apc(tid).unwrap().unwrap();
        let mut main_reply = CAP;
        let held_reply = core::mem::replace(&mut main_reply, CAP + 1);
        let id = table
            .publish(
                reservation,
                Payload {
                    caller,
                    continuation,
                    status,
                },
                held_reply,
            )
            .unwrap();
        let mut registers = core::array::from_fn(|index| 0x100 + index as u64);
        registers[0] = 0x8010_1234;
        registers[1] = 0x10_0000 - 168;
        registers[2] = 0x202;
        let mut floating = [0; LEGACY_FLOATING_POINT_BYTES];
        floating[..2].copy_from_slice(&0x037fu16.to_le_bytes());
        floating[24..28].copy_from_slice(&0x1f80u32.to_le_bytes());
        floating[32..160].fill(0x5a);
        floating[160..416].fill(0xa5);
        Self {
            pm,
            binding,
            claim,
            table,
            id,
            registers,
            floating,
            main_reply,
            installs: 0,
            sends: 0,
            retired_caps: 0,
        }
    }

    fn frame(&self) -> PreparedUserApc {
        let payload = self.table.get(self.id).unwrap().payload;
        let apc = self.claim.apc();
        prepare_user_apc(
            &self.registers,
            &self.floating,
            payload.continuation,
            0x8012_3000,
            UserApcPayload {
                routine: apc.routine,
                normal_context: apc.normal_context,
                system_argument1: apc.system_argument1,
                system_argument2: apc.system_argument2,
            },
            payload.status,
            0x7fff_ffff_ffff,
        )
        .unwrap()
    }

    fn install(&mut self, frame: &PreparedUserApc) {
        let payload = self.table.get(self.id).unwrap().payload;
        assert_eq!(
            payload.caller.validate(
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
        self.installs += 1;
        assert_eq!(self.pm.commit_user_apc_claim(&mut self.claim), Ok(APC));
    }

    fn record(&mut self, effect: Effect, outcome: Outcome) -> Phase {
        let mut attempt = self.table.begin_step(self.id).unwrap();
        assert_eq!(attempt.effect(), effect);
        self.table.record_step(&mut attempt, outcome).unwrap()
    }

    fn stage(&mut self) -> PreparedUserApc {
        let mut attempt = self.table.begin_step(self.id).unwrap();
        assert_eq!(attempt.effect(), Effect::Stage);
        let frame = self.frame();
        self.install(&frame);
        self.table
            .record_step(&mut attempt, Outcome::Completed(Effect::Stage))
            .unwrap();
        frame
    }

    fn send(&mut self) {
        let mut attempt = self.table.begin_step(self.id).unwrap();
        assert_eq!(attempt.effect(), Effect::Send);
        self.sends += 1;
        self.table
            .record_step(&mut attempt, Outcome::Completed(Effect::Send))
            .unwrap();
    }

    fn retire(&mut self, effect: Effect) {
        let mut attempt = self.table.begin_step(self.id).unwrap();
        assert_eq!(attempt.effect(), effect);
        self.retired_caps += 1;
        self.table
            .record_step(&mut attempt, Outcome::Completed(effect))
            .unwrap();
    }

    fn finish(&mut self) {
        let mut attempt = self.table.begin_step(self.id).unwrap();
        assert_eq!(attempt.effect(), Effect::ReleaseClaim);
        self.pm.release_user_apc_claim(&mut self.claim).unwrap();
        self.table
            .record_step(&mut attempt, Outcome::Completed(Effect::ReleaseClaim))
            .unwrap();
        assert_eq!(self.table.get(self.id).unwrap().phase, Phase::Complete);
        assert!(self.table.finish(self.id).is_some());
        assert!(self.table.get(self.id).is_err());
        assert_eq!(self.main_reply, CAP + 1);
    }
}

fn word(frame: &PreparedUserApc, offset: u64) -> u64 {
    let offset = offset as usize;
    u64::from_le_bytes(frame.frame[offset..offset + 8].try_into().unwrap())
}

#[test]
fn admission_owns_reply_and_queue_but_cannot_stage_until_all_postactions_release_tail() {
    let mut fixture = Fixture::new(UserApcContinuation::NativeCall, USER_APC);
    let registers = fixture.registers;
    assert_eq!(
        fixture.table.get(fixture.id).unwrap().phase,
        Phase::AwaitTail
    );
    assert_eq!(fixture.table.get(fixture.id).unwrap().reply_cap, CAP);
    assert_eq!(fixture.main_reply, CAP + 1);
    assert!(fixture.table.begin_step(fixture.id).is_err());
    assert!(fixture.table.finish(fixture.id).is_none());
    assert!(fixture.table.has_runtime_dependency_matching(
        |payload| payload.caller == fixture.table.get(fixture.id).unwrap().payload.caller
    ));
    assert_eq!(fixture.pm.peek_user_apc(fixture.binding.tid as u32), None);
    assert_eq!(fixture.pm.take_user_apc(fixture.binding.tid as u32), None);
    assert!(fixture.pm.validate_user_apc_claim(&fixture.claim));
    assert_eq!(fixture.registers, registers);
    fixture.table.release_tail(fixture.id).unwrap();
    assert!(fixture.table.release_tail(fixture.id).is_err());
    fixture.stage();
    fixture.send();
    fixture.retire(Effect::RetireSentReply);
    fixture.finish();
    assert_eq!(
        fixture.pm.take_user_apc(fixture.binding.tid as u32),
        Some(APC)
    );
    assert_eq!(fixture.pm.take_user_apc(fixture.binding.tid as u32), None);
}

#[test]
fn teardown_before_tail_keeps_active_syscall_pinned_then_retires_without_staging() {
    let mut fixture = Fixture::new(UserApcContinuation::NativeCall, SUCCESS);
    fixture.table.request_teardown(fixture.id).unwrap();
    let view = fixture.table.get(fixture.id).unwrap();
    assert_eq!(view.phase, Phase::AwaitTail);
    assert!(view.teardown_requested);
    assert_eq!(view.reply_cap, CAP);
    assert!(fixture.table.has_runtime_dependency_matching(|_| true));
    assert!(fixture.table.begin_step(fixture.id).is_err());
    assert!(fixture.table.finish(fixture.id).is_none());
    assert!(fixture.pm.validate_user_apc_claim(&fixture.claim));
    fixture.table.release_tail(fixture.id).unwrap();
    assert!(!fixture.table.has_runtime_dependency_matching(|_| true));
    fixture.record(Effect::RevokeReply, Outcome::NotEntered(REFUSED));
    assert_eq!(fixture.retired_caps, 0);
    assert_eq!(fixture.table.get(fixture.id).unwrap().reply_cap, CAP);
    fixture.record(Effect::RevokeReply, Outcome::Completed(Effect::RevokeReply));
    fixture.retire(Effect::RetypeReply);
    fixture.finish();
    assert_eq!(fixture.installs, 0);
    assert_eq!(fixture.sends, 0);
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
fn native_and_fault_saved_contexts_keep_syscall_status_and_live_floating_point() {
    for continuation in [
        UserApcContinuation::NativeCall,
        UserApcContinuation::Fault {
            resume_ip: 0x8020_0020,
            resume_sp: 0x20_0000,
            resume_flags: 0x246,
        },
    ] {
        // APC-only NtTestAlert keeps SUCCESS; an interrupted alertable wait keeps USER_APC.
        for status in [SUCCESS, USER_APC] {
            let mut fixture = Fixture::new(continuation, status);
            let original = fixture.registers;
            fixture.table.release_tail(fixture.id).unwrap();
            let frame = fixture.stage();
            assert_eq!(word(&frame, CONTEXT_RAX_OFFSET), u64::from(status));
            match continuation {
                UserApcContinuation::NativeCall => {
                    assert_eq!(word(&frame, CONTEXT_RIP_OFFSET), original[0]);
                    assert_eq!(word(&frame, CONTEXT_RSP_OFFSET), original[1]);
                    assert_eq!(word(&frame, CONTEXT_RSI_OFFSET), 1);
                    assert_eq!(word(&frame, CONTEXT_R10_OFFSET), u64::from(status));
                }
                UserApcContinuation::Fault {
                    resume_ip,
                    resume_sp,
                    ..
                } => {
                    assert_eq!(word(&frame, CONTEXT_RIP_OFFSET), resume_ip);
                    assert_eq!(word(&frame, CONTEXT_RSP_OFFSET), resume_sp);
                    assert_eq!(word(&frame, CONTEXT_RSI_OFFSET), original[7]);
                    assert_eq!(word(&frame, CONTEXT_R10_OFFSET), original[12]);
                }
            }
            let context = CapturedAmd64Context::capture(
                |address, output| {
                    let offset = (address - frame.frame_va) as usize;
                    output.copy_from_slice(&frame.frame[offset..offset + output.len()]);
                    Ok(())
                },
                frame.frame_va,
            )
            .unwrap();
            let fp = context.extract_legacy_floating_point().unwrap().unwrap();
            assert_eq!(&fp[32..416], &fixture.floating[32..416]);
            assert_eq!(&fp[24..28], &fixture.floating[24..28]);
            assert!(frame.install.floating_point.is_none());
            fixture.send();
            fixture.retire(Effect::RetireSentReply);
            fixture.finish();
        }
    }
}

#[test]
fn rejected_context_install_and_cap_retirement_retry_only_their_own_effects() {
    let mut fixture = Fixture::new(UserApcContinuation::NativeCall, SUCCESS);
    fixture.table.release_tail(fixture.id).unwrap();
    let frame = fixture.frame();
    let registers = fixture.registers;
    fixture.record(Effect::Stage, Outcome::NotEntered(REFUSED));
    assert_eq!(fixture.registers, registers);
    assert!(fixture.pm.validate_user_apc_claim(&fixture.claim));
    assert!(fixture
        .pm
        .claim_user_apc(fixture.binding.tid as u32)
        .is_err());
    assert_eq!(fixture.stage(), frame);
    fixture.record(Effect::Send, Outcome::NotEntered(REFUSED));
    fixture.send();
    fixture.record(Effect::RetireSentReply, Outcome::NotEntered(REFUSED));
    assert_eq!(fixture.table.get(fixture.id).unwrap().reply_cap, CAP);
    assert_eq!(fixture.installs, 1);
    assert_eq!(fixture.sends, 1);
    assert_eq!(fixture.retired_caps, 0);
    fixture.retire(Effect::RetireSentReply);
    fixture.finish();
    assert_eq!(fixture.retired_caps, 1);
}

#[test]
fn entered_or_uncertain_context_and_send_effects_cannot_replay_or_drop_runtime_barrier() {
    for effect in [Effect::Stage, Effect::Send] {
        for uncertain in [false, true] {
            let mut fixture = Fixture::new(UserApcContinuation::NativeCall, USER_APC);
            fixture.table.release_tail(fixture.id).unwrap();
            if effect == Effect::Send {
                fixture.stage();
            }
            let mut attempt = fixture.table.begin_step(fixture.id).unwrap();
            assert_eq!(attempt.effect(), effect);
            if uncertain {
                fixture
                    .table
                    .record_step(&mut attempt, Outcome::Indeterminate(REFUSED))
                    .unwrap();
            }
            drop(attempt);
            fixture.table.request_teardown(fixture.id).unwrap();
            assert!(fixture.table.begin_step(fixture.id).is_err());
            assert!(fixture.table.finish(fixture.id).is_none());
            assert!(fixture.table.has_runtime_dependency_matching(|_| true));
            assert_eq!(fixture.table.get(fixture.id).unwrap().reply_cap, CAP);
            assert_eq!(fixture.retired_caps, 0);
        }
    }
}

#[test]
fn completed_teardown_retains_exact_identity_without_authority_over_reused_runtime() {
    let mut fixture = Fixture::new(UserApcContinuation::NativeCall, SUCCESS);
    fixture.table.request_teardown(fixture.id).unwrap();
    fixture.table.release_tail(fixture.id).unwrap();
    fixture.record(Effect::RevokeReply, Outcome::Completed(Effect::RevokeReply));
    fixture.retire(Effect::RetypeReply);
    let mut release = fixture.table.begin_step(fixture.id).unwrap();
    assert_eq!(release.effect(), Effect::ReleaseClaim);
    fixture
        .pm
        .release_user_apc_claim(&mut fixture.claim)
        .unwrap();
    fixture
        .table
        .record_step(&mut release, Outcome::Completed(Effect::ReleaseClaim))
        .unwrap();
    let old = fixture.table.get(fixture.id).unwrap();
    assert_eq!(old.phase, Phase::Complete);
    assert!(old.teardown_requested);
    assert_eq!(old.reply_cap, 0);
    assert!(fixture
        .table
        .has_owned_matching(|payload| payload.caller == old.payload.caller));
    assert!(!fixture
        .table
        .has_runtime_dependency_matching(|payload| payload.caller == old.payload.caller));
    assert!(fixture.table.begin_step(fixture.id).is_err());

    let tid = fixture.binding.tid as u32;
    fixture.pm.terminate_thread(tid, 0).unwrap();
    let plan = fixture
        .pm
        .prepare_thread_activation(tid, 0x3000, 0, false, 0x7000, 0, false)
        .unwrap();
    fixture.pm.commit_thread_activation(plan).unwrap();
    let lifetime = fixture.pm.thread_lifetime(tid).unwrap();
    let replacement_caller = ProviderLogicalCaller::capture(fixture.binding, lifetime).unwrap();
    assert_eq!(replacement_caller.process(), old.payload.caller.process());
    assert_eq!(
        replacement_caller.thread().thread_id(),
        old.payload.caller.thread().thread_id()
    );
    fixture.pm.queue_kernel_user_apc(tid, APC).unwrap();
    let mut replacement_claim = fixture.pm.claim_user_apc(tid).unwrap().unwrap();
    let reservation = fixture.table.reserve().unwrap();
    let replacement = fixture
        .table
        .publish(
            reservation,
            Payload {
                caller: replacement_caller,
                ..old.payload
            },
            CAP,
        )
        .unwrap();

    // The host reconciliation fixture applies the same full caller/lifetime guard before a
    // physical teardown effect. Matching PI, PID, TID, badge and TCB alone cannot authorize it.
    let physical_teardown_authorized = old
        .payload
        .caller
        .validate(Some(fixture.binding), Some(lifetime))
        .is_ok();
    assert!(!physical_teardown_authorized);
    assert!(fixture.table.finish(fixture.id).is_some());
    assert!(fixture.table.finish(fixture.id).is_none());
    assert_eq!(
        fixture.table.get(replacement).unwrap().payload.caller,
        replacement_caller
    );
    assert_eq!(fixture.table.get(replacement).unwrap().reply_cap, CAP);
    fixture
        .pm
        .release_user_apc_claim(&mut fixture.claim)
        .unwrap();
    assert!(fixture.pm.validate_user_apc_claim(&replacement_claim));
    assert_eq!(
        fixture.pm.commit_user_apc_claim(&mut replacement_claim),
        Ok(APC)
    );
}

#[test]
fn teardown_during_entered_stage_or_send_protects_new_thread_lifetime_from_late_cleanup() {
    for effect in [Effect::Stage, Effect::Send] {
        for accepted in [false, true] {
            let mut fixture = Fixture::new(UserApcContinuation::NativeCall, USER_APC);
            fixture.table.release_tail(fixture.id).unwrap();
            if effect == Effect::Send {
                fixture.stage();
            }
            let mut attempt = fixture.table.begin_step(fixture.id).unwrap();
            assert_eq!(attempt.effect(), effect);
            fixture.table.request_teardown(fixture.id).unwrap();
            assert!(fixture.table.has_runtime_dependency_matching(|_| true));
            if effect == Effect::Stage && accepted {
                let frame = fixture.frame();
                fixture.install(&frame);
            }
            fixture
                .table
                .record_step(
                    &mut attempt,
                    if accepted {
                        Outcome::Completed(effect)
                    } else {
                        Outcome::NotEntered(REFUSED)
                    },
                )
                .unwrap();
            assert!(!fixture.table.has_runtime_dependency_matching(|_| true));
            let tid = fixture.binding.tid as u32;
            let caller = fixture.table.get(fixture.id).unwrap().payload.caller;
            fixture.pm.terminate_thread(tid, 0).unwrap();
            let plan = fixture
                .pm
                .prepare_thread_activation(tid, 0x3000, 0, false, 0x7000, 0, false)
                .unwrap();
            fixture.pm.commit_thread_activation(plan).unwrap();
            fixture.pm.queue_kernel_user_apc(tid, APC).unwrap();
            let mut replacement = fixture.pm.claim_user_apc(tid).unwrap().unwrap();
            assert_eq!(
                caller.validate(Some(fixture.binding), fixture.pm.thread_lifetime(tid)),
                Err(ProviderCallerError::LifetimeChanged)
            );
            if effect == Effect::Send && accepted {
                fixture.retire(Effect::RetireSentReply);
            } else {
                fixture.record(Effect::RevokeReply, Outcome::Completed(Effect::RevokeReply));
                fixture.retire(Effect::RetypeReply);
            }
            fixture.finish();
            assert!(fixture.pm.validate_user_apc_claim(&replacement));
            assert_eq!(fixture.pm.commit_user_apc_claim(&mut replacement), Ok(APC));
        }
    }
}
