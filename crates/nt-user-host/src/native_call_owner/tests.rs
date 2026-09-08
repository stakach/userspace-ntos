use super::*;
use crate::process_identity::{ProcessGeneration, ProcessIdentity};

fn setup() -> (ProcessManager, ThreadBinding<()>, NativeCallOwner<()>) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("test", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let binding = ThreadBinding {
        pi: 3,
        process: ProcessIdentity {
            pid,
            generation: ProcessGeneration::Hosted(7),
        },
        tid: u64::from(tid),
        badge: 55,
        role: (),
        tcb: 99,
        reservations: None,
    };
    let owner = NativeCallOwner::new(binding, pm.thread_lifetime(tid).unwrap(), &pm).unwrap();
    (pm, binding, owner)
}

fn capture() -> NativeCallContinuation {
    let mut registers = [0; 18];
    for (index, value) in registers.iter_mut().enumerate() {
        *value = 0x1000 + index as u64;
    }
    registers[1] = 0x8008;
    registers[2] = 0x246;
    NativeCallContinuation::new(27, 0x8000, registers, 0x7fff_ffff_ffff).unwrap()
}

fn envelope(ssn: u64) -> u64 {
    (nt_syscall_abi::NT_NATIVE_CONTEXT_SYSCALL_LABEL << 12)
        | (2 + u64::from(exact_native_context_argc(ssn).unwrap()))
}

#[test]
fn exact_argument_snapshot_survives_user_changes_and_retry_without_recapture() {
    let (pm, binding, mut owner) = setup();
    let original =
        NativeCallContinuation::new(39, 0x8000, *capture().registers(), 0x7fff_ffff_ffff).unwrap();
    let count = usize::from(exact_native_context_argc(39).unwrap());
    assert!(count > 4);
    let mut args = [0u64; NATIVE_CONTEXT_MAX_ARGS as usize];
    for (index, word) in args.iter_mut().enumerate() {
        *word = 0x4000 + index as u64;
    }
    for invalid in [&args[..count - 1], &args[..count + 1]] {
        assert_eq!(
            owner.admit(binding, &pm, original, invalid, None),
            Err(NativeCallError::InvalidArguments)
        );
        assert!(owner.is_empty());
        assert_eq!(owner.last_call, 0);
    }
    let expected = args;
    let epoch = owner
        .admit(binding, &pm, original, &args[..count], None)
        .unwrap();
    args.fill(u64::MAX);
    assert_eq!(
        owner.arguments(binding, &pm, epoch).unwrap(),
        &expected[..count]
    );
    owner.mark_waiting(binding, &pm, epoch).unwrap();
    owner.retry_ready(binding, &pm, epoch).unwrap();
    let mut retry = owner.begin_retry(binding, &pm, epoch).unwrap();
    let NativeCallWork::Retry {
        original: retained,
        arguments,
    } = retry.work()
    else {
        panic!()
    };
    assert_eq!(*retained, original);
    assert_eq!(arguments.as_slice(), &expected[..count]);
    owner
        .record(binding, &pm, &mut retry, NativeCallOutcome::Acknowledged)
        .unwrap();
    owner
        .admit_retry(binding, &pm, epoch, envelope(39), 39)
        .unwrap();
    assert_eq!(
        owner.arguments(binding, &pm, epoch).unwrap(),
        &expected[..count]
    );
    assert_eq!(owner.frames[0].original, original);
}

#[test]
fn logical_get_refuses_frames_no_longer_currently_blocked_in_native_call() {
    let (pm, binding, mut owner) = setup();
    let epoch = owner.admit(binding, &pm, capture(), &[7], None).unwrap();
    for phase in [
        NativeCallPhase::CallbackSuspended(callback(binding, 1)),
        NativeCallPhase::AwaitingRetry,
        NativeCallPhase::Accepted(0),
        NativeCallPhase::InFlight(NativeCallOperation::Complete),
        NativeCallPhase::Indeterminate(NativeCallOperation::Retry, 7),
    ] {
        owner.frames[0].phase = phase;
        assert_eq!(
            owner.logical_registers(binding, &pm, epoch),
            Err(NativeCallError::InvalidPhase)
        );
    }
    for phase in [
        NativeCallPhase::Active,
        NativeCallPhase::Waiting,
        NativeCallPhase::Ready(0),
        NativeCallPhase::RetryReady,
    ] {
        owner.frames[0].phase = phase;
        assert_eq!(
            owner.logical_registers(binding, &pm, epoch),
            Ok(*capture().registers())
        );
    }
}

fn callback(binding: ThreadBinding<()>, index: u32) -> CallbackCorrelation {
    CallbackCorrelation {
        dispatch_id: 0x1000 + u64::from(index),
        callback_id: index,
        client_pi: binding.pi as u32,
        client_tid: binding.tid,
        client_badge: binding.badge,
    }
}

fn accepted_completion(
    owner: &mut NativeCallOwner<()>,
    binding: ThreadBinding<()>,
    pm: &ProcessManager,
    epoch: u64,
    status: u32,
) {
    owner.ready(binding, pm, epoch, status).unwrap();
    let mut token = owner.begin_completion(binding, pm, epoch).unwrap();
    owner
        .record(binding, pm, &mut token, NativeCallOutcome::Acknowledged)
        .unwrap();
}

#[test]
fn full_base_is_preserved_and_status_only_changes_completion_image() {
    let (pm, binding, mut owner) = setup();
    let original = capture();
    let epoch = owner
        .admit(binding, &pm, original, &[0x1234], None)
        .unwrap();
    assert_eq!(
        owner.logical_registers(binding, &pm, epoch),
        Ok(*original.registers())
    );
    owner.ready(binding, &pm, epoch, 0xc000_0001).unwrap();
    let mut ticket = owner.begin_completion(binding, &pm, epoch).unwrap();
    let NativeCallWork::Complete {
        registers,
        status,
        edited,
    } = *ticket.work()
    else {
        panic!()
    };
    let mut expected = *original.registers();
    expected[3] = 0xc000_0001;
    assert_eq!(registers, expected);
    assert_eq!(status, 0xc000_0001);
    assert!(!edited);
    assert_eq!(owner.frames[0].logical, *original.registers());
    owner
        .record(binding, &pm, &mut ticket, NativeCallOutcome::Acknowledged)
        .unwrap();
    assert_eq!(
        owner.phase(epoch),
        Ok(NativeCallPhase::Accepted(0xc000_0001))
    );
    assert_eq!(
        owner.begin_completion(binding, &pm, epoch).unwrap_err(),
        NativeCallError::InvalidPhase
    );
    assert!(
        !owner.is_empty(),
        "local cleanup has not acknowledged retirement"
    );
    owner.acknowledge_retirement(binding, &pm, epoch).unwrap();
    assert!(owner.is_empty());
}

#[test]
fn edit_commits_only_selected_words_after_ack_and_keeps_original_for_retry() {
    let (pm, binding, mut owner) = setup();
    let original = capture();
    let epoch = owner
        .admit(binding, &pm, original, &[0x1234], None)
        .unwrap();
    owner.mark_waiting(binding, &pm, epoch).unwrap();
    let mask = (1 << 0) | (1 << 4) | (1 << 17);
    let mut ticket = owner
        .begin_edit(binding, &pm, epoch, [0xbeef; 18], mask)
        .unwrap();
    assert_eq!(owner.frames[0].logical, *original.registers());
    assert_eq!(
        owner.logical_registers(binding, &pm, epoch),
        Err(NativeCallError::InvalidPhase)
    );
    owner
        .record(binding, &pm, &mut ticket, NativeCallOutcome::Acknowledged)
        .unwrap();
    let mut expected = *original.registers();
    for index in [0, 4, 17] {
        expected[index] = 0xbeef;
    }
    assert_eq!(owner.logical_registers(binding, &pm, epoch), Ok(expected));
    assert_eq!(owner.phase(epoch), Ok(NativeCallPhase::Waiting));
    assert_eq!(owner.frames[0].original, original);
    owner.retry_ready(binding, &pm, epoch).unwrap();
    let mut retry = owner.begin_retry(binding, &pm, epoch).unwrap();
    assert_eq!(
        retry.work(),
        &NativeCallWork::Retry {
            original,
            arguments: NativeCallArguments::capture(27, &[0x1234]).unwrap(),
        }
    );
    owner
        .record(binding, &pm, &mut retry, NativeCallOutcome::Acknowledged)
        .unwrap();
    owner
        .admit_retry(binding, &pm, epoch, envelope(27), 27)
        .unwrap();
    assert_eq!(owner.logical_registers(binding, &pm, epoch), Ok(expected));
}

#[test]
fn no_effect_outcomes_preserve_ready_status_and_allow_new_exact_attempt() {
    let (pm, binding, mut owner) = setup();
    let epoch = owner
        .admit(binding, &pm, capture(), &[0x1234], None)
        .unwrap();
    owner.ready(binding, &pm, epoch, 0xc000_0022).unwrap();
    for outcome in [
        NativeCallOutcome::NotEntered(4),
        NativeCallOutcome::RejectedNoEffects(5),
    ] {
        let mut ticket = owner.begin_completion(binding, &pm, epoch).unwrap();
        owner.record(binding, &pm, &mut ticket, outcome).unwrap();
        assert_eq!(owner.phase(epoch), Ok(NativeCallPhase::Ready(0xc000_0022)));
        assert_eq!(owner.last_failure(epoch), Ok(Some(outcome)));
        assert_eq!(
            owner.record(binding, &pm, &mut ticket, outcome),
            Err(NativeCallError::WrongAttempt)
        );
    }
    accepted_completion(&mut owner, binding, &pm, epoch, 0xc000_0022);
}

#[test]
fn rejected_edit_never_modifies_logical_context() {
    let (pm, binding, mut owner) = setup();
    let epoch = owner
        .admit(binding, &pm, capture(), &[0x1234], None)
        .unwrap();
    let mut ticket = owner
        .begin_edit(binding, &pm, epoch, [77; 18], REGISTER_MASK)
        .unwrap();
    owner
        .record(
            binding,
            &pm,
            &mut ticket,
            NativeCallOutcome::RejectedNoEffects(12),
        )
        .unwrap();
    assert_eq!(
        owner.logical_registers(binding, &pm, epoch),
        Ok(*capture().registers())
    );
    assert_eq!(owner.frames[0].edited, 0);
}

#[test]
fn every_ambiguous_operation_retains_proposal_and_forbids_replay() {
    for operation in [
        NativeCallOperation::Edit,
        NativeCallOperation::Retry,
        NativeCallOperation::Complete,
        NativeCallOperation::Callback,
    ] {
        let (pm, binding, mut owner) = setup();
        let epoch = owner
            .admit(binding, &pm, capture(), &[0x1234], None)
            .unwrap();
        let mut ticket = match operation {
            NativeCallOperation::Edit => owner.begin_edit(binding, &pm, epoch, [9; 18], 1).unwrap(),
            NativeCallOperation::Retry => {
                owner.mark_waiting(binding, &pm, epoch).unwrap();
                owner.retry_ready(binding, &pm, epoch).unwrap();
                owner.begin_retry(binding, &pm, epoch).unwrap()
            }
            NativeCallOperation::Complete => {
                owner.ready(binding, &pm, epoch, 0xc000_0001).unwrap();
                owner.begin_completion(binding, &pm, epoch).unwrap()
            }
            NativeCallOperation::Callback => owner
                .begin_callback(binding, &pm, epoch, callback(binding, 1))
                .unwrap(),
        };
        let work = *ticket.work();
        owner
            .record(
                binding,
                &pm,
                &mut ticket,
                NativeCallOutcome::Indeterminate(123),
            )
            .unwrap();
        assert_eq!(
            owner.phase(epoch),
            Ok(NativeCallPhase::Indeterminate(operation, 123))
        );
        assert_eq!(owner.pending_work(epoch).unwrap(), Some(&work));
        assert!(owner.begin_completion(binding, &pm, epoch).is_err());
        assert!(owner.begin_retry(binding, &pm, epoch).is_err());
        assert!(owner.begin_edit(binding, &pm, epoch, [0; 18], 0).is_err());
        assert!(owner
            .begin_callback(binding, &pm, epoch, callback(binding, 2))
            .is_err());
        assert!(owner.acknowledge_retirement(binding, &pm, epoch).is_err());
        assert!(owner
            .admit(binding, &pm, capture(), &[0x1234], None)
            .is_err());
        assert_eq!(owner.depth(), 1);
    }
}

#[test]
fn dropped_ticket_leaves_inflight_owner_and_no_implicit_rollback() {
    let (pm, binding, mut owner) = setup();
    let epoch = owner
        .admit(binding, &pm, capture(), &[0x1234], None)
        .unwrap();
    drop(owner.begin_edit(binding, &pm, epoch, [1; 18], 1).unwrap());
    assert_eq!(
        owner.phase(epoch),
        Ok(NativeCallPhase::InFlight(NativeCallOperation::Edit))
    );
    assert!(owner.pending_work(epoch).unwrap().is_some());
    assert!(owner.begin_edit(binding, &pm, epoch, [2; 18], 1).is_err());
    assert!(owner.ready(binding, &pm, epoch, 0).is_err());
}

#[test]
fn wrong_owner_ticket_cannot_mutate_colliding_call_epoch() {
    let (pm, binding, mut first) = setup();
    let mut second = NativeCallOwner::new(binding, first.lifetime, &pm).unwrap();
    let first_epoch = first
        .admit(binding, &pm, capture(), &[0x1234], None)
        .unwrap();
    let second_epoch = second
        .admit(binding, &pm, capture(), &[0x1234], None)
        .unwrap();
    assert_eq!(first_epoch, second_epoch);
    let mut ticket = first
        .begin_edit(binding, &pm, first_epoch, [1; 18], 1)
        .unwrap();
    let mut second_ticket = second
        .begin_edit(binding, &pm, second_epoch, [2; 18], 2)
        .unwrap();
    assert_eq!(
        second.record(binding, &pm, &mut ticket, NativeCallOutcome::Acknowledged),
        Err(NativeCallError::WrongAttempt)
    );
    first
        .record(binding, &pm, &mut ticket, NativeCallOutcome::Acknowledged)
        .unwrap();
    second
        .record(
            binding,
            &pm,
            &mut second_ticket,
            NativeCallOutcome::Acknowledged,
        )
        .unwrap();
    assert_eq!(first.frames[0].logical[0], 1);
    assert_eq!(second.frames[0].logical[1], 2);
}

#[test]
fn binding_and_activation_replacement_are_rejected_without_losing_ticket() {
    let (mut pm, binding, mut owner) = setup();
    let epoch = owner
        .admit(binding, &pm, capture(), &[0x1234], None)
        .unwrap();
    let mut ticket = owner.begin_edit(binding, &pm, epoch, [1; 18], 1).unwrap();
    for changed in [
        ThreadBinding {
            tcb: 100,
            ..binding
        },
        ThreadBinding {
            badge: 56,
            ..binding
        },
        ThreadBinding {
            tid: binding.tid + 1,
            ..binding
        },
        ThreadBinding {
            process: ProcessIdentity {
                generation: ProcessGeneration::Hosted(8),
                ..binding.process
            },
            ..binding
        },
    ] {
        assert_eq!(
            owner.record(changed, &pm, &mut ticket, NativeCallOutcome::Acknowledged),
            Err(NativeCallError::BindingChanged)
        );
    }
    owner
        .record(binding, &pm, &mut ticket, NativeCallOutcome::Acknowledged)
        .unwrap();
    let dormant = pm.create_dormant_thread(binding.process.pid).unwrap();
    let dormant_binding = ThreadBinding {
        tid: u64::from(dormant),
        tcb: 101,
        badge: 57,
        ..binding
    };
    let mut old =
        NativeCallOwner::new(dormant_binding, pm.thread_lifetime(dormant).unwrap(), &pm).unwrap();
    assert_eq!(
        old.admit(dormant_binding, &pm, capture(), &[0x1234], None),
        Err(NativeCallError::InvalidPhase)
    );
    let plan = pm
        .prepare_thread_activation(dormant, 0x1000, 0, false, 0x9000, 1, false)
        .unwrap();
    pm.commit_thread_activation(plan).unwrap();
    assert_eq!(
        old.admit(dormant_binding, &pm, capture(), &[0x1234], None),
        Err(NativeCallError::LifetimeChanged)
    );
}

#[test]
fn suspended_ready_is_retained_and_edit_does_not_wake_thread() {
    let (mut pm, binding, mut owner) = setup();
    let epoch = owner
        .admit(binding, &pm, capture(), &[0x1234], None)
        .unwrap();
    owner.mark_waiting(binding, &pm, epoch).unwrap();
    pm.suspend_thread(binding.tid as u32).unwrap();
    pm.suspend_thread(binding.tid as u32).unwrap();
    owner.ready(binding, &pm, epoch, 0).unwrap();
    let mut edit = owner.begin_edit(binding, &pm, epoch, [9; 18], 2).unwrap();
    owner
        .record(binding, &pm, &mut edit, NativeCallOutcome::Acknowledged)
        .unwrap();
    assert_eq!(pm.thread(binding.tid as u32).unwrap().suspend_count, 2);
    assert_eq!(
        owner.begin_completion(binding, &pm, epoch).unwrap_err(),
        NativeCallError::Suspended
    );
    pm.resume_thread(binding.tid as u32).unwrap();
    assert_eq!(
        owner.begin_completion(binding, &pm, epoch).unwrap_err(),
        NativeCallError::Suspended
    );
    assert_eq!(owner.phase(epoch), Ok(NativeCallPhase::Ready(0)));
    pm.resume_thread(binding.tid as u32).unwrap();
    let completion = owner.begin_completion(binding, &pm, epoch).unwrap();
    assert!(matches!(
        completion.work(),
        NativeCallWork::Complete { edited: true, .. }
    ));
}

#[test]
fn retry_envelope_must_match_without_recapturing_or_overwriting_call_epoch() {
    let (pm, binding, mut owner) = setup();
    let epoch = owner
        .admit(binding, &pm, capture(), &[0x1234], None)
        .unwrap();
    owner.mark_waiting(binding, &pm, epoch).unwrap();
    owner.retry_ready(binding, &pm, epoch).unwrap();
    let mut ticket = owner.begin_retry(binding, &pm, epoch).unwrap();
    owner
        .record(binding, &pm, &mut ticket, NativeCallOutcome::Acknowledged)
        .unwrap();
    assert_eq!(
        owner.admit_retry(binding, &pm, epoch, envelope(27) | (1 << 7), 27),
        Err(NativeCallError::InvalidEnvelope)
    );
    assert_eq!(
        owner.admit_retry(binding, &pm, epoch, envelope(39), 39),
        Err(NativeCallError::ServiceChanged)
    );
    assert!(owner
        .admit(binding, &pm, capture(), &[0x1234], None)
        .is_err());
    owner
        .admit_retry(binding, &pm, epoch, envelope(27), 27)
        .unwrap();
    assert_eq!(owner.current_epoch(), Some(epoch));
    accepted_completion(&mut owner, binding, &pm, epoch, 0);
    owner.acknowledge_retirement(binding, &pm, epoch).unwrap();
    let next = owner
        .admit(binding, &pm, capture(), &[0x1234], None)
        .unwrap();
    assert_ne!(
        next, epoch,
        "same callsite/SSN/stack after terminal retirement is a new call"
    );
}

#[test]
fn nested_callbacks_keep_outer_state_and_enforce_exact_return_order() {
    let (pm, binding, mut owner) = setup();
    let outer = owner
        .admit(binding, &pm, capture(), &[0x1234], None)
        .unwrap();
    let first = callback(binding, 1);
    let mut ticket = owner.begin_callback(binding, &pm, outer, first).unwrap();
    assert!(owner
        .admit(binding, &pm, capture(), &[0x1234], Some(first))
        .is_err());
    owner
        .record(binding, &pm, &mut ticket, NativeCallOutcome::Acknowledged)
        .unwrap();
    assert!(owner
        .admit(
            binding,
            &pm,
            capture(),
            &[0x1234],
            Some(callback(binding, 2))
        )
        .is_err());
    let nested = owner
        .admit(binding, &pm, capture(), &[0x1234], Some(first))
        .unwrap();
    let second = callback(binding, 2);
    let mut ticket = owner.begin_callback(binding, &pm, nested, second).unwrap();
    owner
        .record(binding, &pm, &mut ticket, NativeCallOutcome::Acknowledged)
        .unwrap();
    let inner = owner
        .admit(binding, &pm, capture(), &[0x1234], Some(second))
        .unwrap();
    assert_eq!(
        owner.resume_callback(binding, &pm, outer, first),
        Err(NativeCallError::WrongCall)
    );
    accepted_completion(&mut owner, binding, &pm, inner, 0);
    owner.acknowledge_retirement(binding, &pm, inner).unwrap();
    assert_eq!(
        owner.resume_callback(binding, &pm, nested, first),
        Err(NativeCallError::CallbackChanged)
    );
    owner.resume_callback(binding, &pm, nested, second).unwrap();
    accepted_completion(&mut owner, binding, &pm, nested, 0);
    owner.acknowledge_retirement(binding, &pm, nested).unwrap();
    owner.resume_callback(binding, &pm, outer, first).unwrap();
    assert_eq!(
        owner.logical_registers(binding, &pm, outer),
        Ok(*capture().registers())
    );
}

#[test]
fn callback_depth_and_client_correlation_fail_before_redirect() {
    let (pm, binding, mut owner) = setup();
    let mut epoch = owner
        .admit(binding, &pm, capture(), &[0x1234], None)
        .unwrap();
    let mut wrong = callback(binding, 1);
    wrong.client_tid += 1;
    assert_eq!(
        owner
            .begin_callback(binding, &pm, epoch, wrong)
            .unwrap_err(),
        NativeCallError::CallbackChanged
    );
    for index in 1..MAX_DEPTH {
        let correlation = callback(binding, index as u32);
        let mut ticket = owner
            .begin_callback(binding, &pm, epoch, correlation)
            .unwrap();
        let capacity = owner.frames.capacity();
        owner
            .record(binding, &pm, &mut ticket, NativeCallOutcome::Acknowledged)
            .unwrap();
        epoch = owner
            .admit(binding, &pm, capture(), &[0x1234], Some(correlation))
            .unwrap();
        assert_eq!(
            owner.frames.capacity(),
            capacity,
            "nested admission must not allocate after redirect"
        );
    }
    assert_eq!(owner.depth(), MAX_DEPTH);
    assert_eq!(
        owner
            .begin_callback(binding, &pm, epoch, callback(binding, 99))
            .unwrap_err(),
        NativeCallError::DepthLimit
    );
    assert_eq!(owner.phase(epoch), Ok(NativeCallPhase::Active));
}

#[test]
fn all_epoch_allocators_fail_closed_without_wrapping() {
    let counter = AtomicU64::new(u64::MAX - 1);
    assert_eq!(issue_owner(&counter), Ok(u64::MAX));
    assert_eq!(issue_owner(&counter), Err(NativeCallError::Exhausted));
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    let (pm, binding, mut owner) = setup();
    owner.last_call = u64::MAX;
    assert_eq!(
        owner.admit(binding, &pm, capture(), &[0x1234], None),
        Err(NativeCallError::Exhausted)
    );
    assert!(owner.is_empty());
    owner.last_call = u64::MAX - 1;
    let epoch = owner
        .admit(binding, &pm, capture(), &[0x1234], None)
        .unwrap();
    assert_eq!(epoch, u64::MAX);
    assert_eq!(
        owner
            .begin_callback(binding, &pm, epoch, callback(binding, 1))
            .unwrap_err(),
        NativeCallError::Exhausted
    );
    owner.last_attempt = u64::MAX;
    assert_eq!(
        owner
            .begin_edit(binding, &pm, epoch, [0; 18], 1)
            .unwrap_err(),
        NativeCallError::Exhausted
    );
    assert_eq!(owner.phase(epoch), Ok(NativeCallPhase::Active));
    assert!(owner.pending_work(epoch).unwrap().is_none());
}

#[test]
fn ready_replay_requires_exact_status_and_unready_completion_is_refused() {
    let (pm, binding, mut owner) = setup();
    let epoch = owner
        .admit(binding, &pm, capture(), &[0x1234], None)
        .unwrap();
    assert_eq!(
        owner.begin_completion(binding, &pm, epoch).unwrap_err(),
        NativeCallError::InvalidPhase
    );
    owner.ready(binding, &pm, epoch, 1).unwrap();
    owner.ready(binding, &pm, epoch, 1).unwrap();
    assert_eq!(
        owner.ready(binding, &pm, epoch, 2),
        Err(NativeCallError::StatusChanged)
    );
    assert_eq!(owner.phase(epoch), Ok(NativeCallPhase::Ready(1)));
    assert_eq!(
        owner
            .begin_edit(binding, &pm, epoch, [0; 18], 1 << 18)
            .unwrap_err(),
        NativeCallError::InvalidMask
    );
}

#[test]
fn terminated_runtime_cannot_start_new_effects_but_can_record_exact_late_ack() {
    let (mut pm, binding, mut owner) = setup();
    let epoch = owner
        .admit(binding, &pm, capture(), &[0x1234], None)
        .unwrap();
    owner.ready(binding, &pm, epoch, 0).unwrap();
    let mut ticket = owner.begin_completion(binding, &pm, epoch).unwrap();
    pm.exit_thread_at(binding.tid as u32, 0, 1).unwrap();
    owner
        .record(binding, &pm, &mut ticket, NativeCallOutcome::Acknowledged)
        .unwrap();
    owner.acknowledge_retirement(binding, &pm, epoch).unwrap();
    assert_eq!(
        owner.admit(binding, &pm, capture(), &[0x1234], None),
        Err(NativeCallError::Terminated)
    );
}
