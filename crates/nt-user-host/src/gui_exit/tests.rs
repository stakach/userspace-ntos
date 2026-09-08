use super::*;
use crate::process_identity::ProcessGeneration;

fn context(final_mechanism: bool) -> GuiExitContext {
    let mut pm = nt_process::ProcessManager::new();
    let pid = pm.create_process("host.exe", None, None);
    let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
    GuiExitContext {
        pi: 2,
        process: ProcessIdentity {
            pid,
            generation: ProcessGeneration::Hosted(7),
        },
        thread: pm.thread_lifetime(tid).unwrap(),
        eprocess: 0x10000,
        ethread: 0x20000,
        win32_thread: Some(0x30000),
        win32_process: final_mechanism.then_some(0x40000),
        job: final_mechanism.then_some(5),
        final_mechanism,
    }
}

fn accept(owner: &mut GuiExitOwner, stage: GuiExitStage) {
    let call = owner.begin().unwrap();
    assert_eq!(call.stage(), stage);
    owner
        .record(call, ProviderFinalizationResult::Returned(0))
        .unwrap();
}

fn ack(owner: &mut GuiExitOwner, action: GuiExitAcknowledgment) {
    assert_eq!(owner.phase(), GuiExitPhase::Local(action));
    let expected = owner.context();
    owner.acknowledge(expected, action, Ok(())).unwrap();
}

#[test]
fn complete_final_thread_flow_observes_each_required_local_boundary() {
    let ctx = context(true);
    let mut owner = GuiExitOwner::new(ctx).unwrap();
    let call = owner.begin().unwrap();
    assert_eq!(call.context(), ctx);
    assert_eq!(call.expected_pointer(), 0x30000);
    assert!(call.retain_thread_context());
    assert_eq!(
        owner.phase(),
        GuiExitPhase::ThreadExit(ProviderFinalizationPhase::Invoking)
    );
    assert!(matches!(owner.begin(), Err(GuiExitError::WrongPhase)));
    owner
        .record(call, ProviderFinalizationResult::Returned(0))
        .unwrap();
    ack(&mut owner, GuiExitAcknowledgment::ThreadClear);
    let call = owner.begin().unwrap();
    assert_eq!(call.stage(), GuiExitStage::JobRemoval);
    assert_eq!(call.context().job, Some(5));
    assert_eq!(call.expected_pointer(), 0x40000);
    assert!(!call.retain_thread_context());
    owner
        .record(call, ProviderFinalizationResult::Returned(0))
        .unwrap();
    let call = owner.begin().unwrap();
    assert_eq!(call.stage(), GuiExitStage::Process);
    assert_eq!(call.expected_pointer(), 0x40000);
    assert!(!call.retain_thread_context());
    owner
        .record(call, ProviderFinalizationResult::Returned(0))
        .unwrap();
    ack(&mut owner, GuiExitAcknowledgment::ProcessClear);
    ack(&mut owner, GuiExitAcknowledgment::CallbackRetirement);
    assert!(owner.ready());
    assert!(matches!(owner.begin(), Err(GuiExitError::WrongPhase)));
}

#[test]
fn nonfinal_thread_does_not_request_process_or_callback_retirement() {
    let mut owner = GuiExitOwner::new(context(false)).unwrap();
    let call = owner.begin().unwrap();
    assert!(!call.retain_thread_context());
    owner
        .record(call, ProviderFinalizationResult::Returned(0))
        .unwrap();
    ack(&mut owner, GuiExitAcknowledgment::ThreadClear);
    assert!(owner.ready());
}

#[test]
fn absent_provider_objects_skip_only_their_own_obligations() {
    let mut ctx = context(false);
    ctx.win32_thread = None;
    ctx.eprocess = 0;
    ctx.ethread = 0;
    assert!(GuiExitOwner::new(ctx).unwrap().ready());
    ctx.final_mechanism = true;
    let mut owner = GuiExitOwner::new(ctx).unwrap();
    assert!(!owner.ready());
    ack(&mut owner, GuiExitAcknowledgment::CallbackRetirement);
    assert!(owner.ready());

    ctx.eprocess = 0x10000;
    ctx.win32_process = Some(0x40000);
    let mut owner = GuiExitOwner::new(ctx).unwrap();
    // Actual absence of job membership skips its provider IPC.
    accept(&mut owner, GuiExitStage::Process);
    ack(&mut owner, GuiExitAcknowledgment::ProcessClear);
    ack(&mut owner, GuiExitAcknowledgment::CallbackRetirement);
    assert!(owner.ready());
}

#[test]
fn only_proven_not_entered_outcomes_allow_retry_with_a_new_attempt() {
    for status in [0, 1, 0x103, 0x8000_0001, 0xc000_0001] {
        let mut owner = GuiExitOwner::new(context(false)).unwrap();
        let call = owner.begin().unwrap();
        let epoch = call.epoch;
        owner
            .record(call, ProviderFinalizationResult::NotEntered(status))
            .unwrap();
        assert_eq!(
            owner.phase(),
            GuiExitPhase::ThreadExit(ProviderFinalizationPhase::Pending)
        );
        let retry = owner.begin().unwrap();
        assert!(retry.epoch > epoch);
        owner
            .record(retry, ProviderFinalizationResult::Returned(0))
            .unwrap();
        ack(&mut owner, GuiExitAcknowledgment::ThreadClear);
        assert!(owner.ready());
    }
}

#[test]
fn every_entered_failure_is_nonreplayable_for_thread_and_process() {
    for process in [false, true] {
        for result in [
            ProviderFinalizationResult::Returned(1),
            ProviderFinalizationResult::Returned(0x103),
            ProviderFinalizationResult::Returned(0xc000_0001),
            ProviderFinalizationResult::Indeterminate(0),
            ProviderFinalizationResult::Indeterminate(0x103),
            ProviderFinalizationResult::Indeterminate(0xc000_0001),
        ] {
            let status = match result {
                ProviderFinalizationResult::Returned(status)
                | ProviderFinalizationResult::Indeterminate(status) => status,
                _ => unreachable!(),
            };
            let mut owner = GuiExitOwner::new(context(process)).unwrap();
            if process {
                accept(&mut owner, GuiExitStage::Thread);
                ack(&mut owner, GuiExitAcknowledgment::ThreadClear);
                accept(&mut owner, GuiExitStage::JobRemoval);
            }
            let call = owner.begin().unwrap();
            owner.record(call, result).unwrap();
            let expected = if process {
                GuiExitPhase::ProcessExit(ProviderFinalizationPhase::Indeterminate(status))
            } else {
                GuiExitPhase::ThreadExit(ProviderFinalizationPhase::Indeterminate(status))
            };
            assert_eq!(owner.phase(), expected);
            assert!(matches!(owner.begin(), Err(GuiExitError::WrongPhase)));
            assert!(!owner.ready());
            assert_eq!(owner.phase(), expected);
        }
    }
}

#[test]
fn local_failures_preserve_acceptance_and_never_replay_provider() {
    let mut owner = GuiExitOwner::new(context(true)).unwrap();
    accept(&mut owner, GuiExitStage::Thread);
    for action in [
        GuiExitAcknowledgment::ThreadClear,
        GuiExitAcknowledgment::ProcessClear,
        GuiExitAcknowledgment::CallbackRetirement,
    ] {
        if action == GuiExitAcknowledgment::ProcessClear {
            accept(&mut owner, GuiExitStage::JobRemoval);
            accept(&mut owner, GuiExitStage::Process);
        }
        let before = owner.phase();
        for _ in 0..3 {
            assert_eq!(
                owner.acknowledge(owner.context(), action, Err(0xc000_0001)),
                Err(GuiExitError::LocalFailure(0xc000_0001))
            );
            assert_eq!(owner.phase(), before);
            assert!(matches!(owner.begin(), Err(GuiExitError::WrongPhase)));
        }
        ack(&mut owner, action);
    }
    assert!(owner.ready());
}

#[test]
fn colliding_owners_cannot_consume_each_others_tokens_and_original_can_recover() {
    let ctx = context(false);
    let mut first = GuiExitOwner::new(ctx).unwrap();
    let mut second = GuiExitOwner::new(ctx).unwrap();
    let a = first.begin().unwrap();
    let b = second.begin().unwrap();
    let (error, a) = second
        .record(a, ProviderFinalizationResult::Returned(0))
        .unwrap_err();
    assert_eq!(error, GuiExitError::WrongInvocation);
    assert_eq!(
        second.phase(),
        GuiExitPhase::ThreadExit(ProviderFinalizationPhase::Invoking)
    );
    first
        .record(a, ProviderFinalizationResult::Returned(0))
        .unwrap();
    second
        .record(b, ProviderFinalizationResult::NotEntered(1))
        .unwrap();
    ack(&mut first, GuiExitAcknowledgment::ThreadClear);
    assert!(first.ready());
}

#[test]
fn moved_owner_accepts_its_token_but_dropped_token_never_reopens_admission() {
    let mut owner = GuiExitOwner::new(context(false)).unwrap();
    let call = owner.begin().unwrap();
    let mut moved = owner;
    moved
        .record(call, ProviderFinalizationResult::Returned(0))
        .unwrap();
    ack(&mut moved, GuiExitAcknowledgment::ThreadClear);
    assert!(moved.ready());
    let mut owner = GuiExitOwner::new(context(false)).unwrap();
    drop(owner.begin().unwrap());
    assert_eq!(
        owner.phase(),
        GuiExitPhase::ThreadExit(ProviderFinalizationPhase::Invoking)
    );
    assert!(matches!(owner.begin(), Err(GuiExitError::WrongPhase)));
}

#[test]
fn wrong_local_identity_or_stage_never_changes_progress() {
    let ctx = context(true);
    let mut owner = GuiExitOwner::new(ctx).unwrap();
    assert_eq!(
        owner.acknowledge(ctx, GuiExitAcknowledgment::ThreadClear, Ok(())),
        Err(GuiExitError::WrongPhase)
    );
    accept(&mut owner, GuiExitStage::Thread);
    for changed in [
        GuiExitContext {
            pi: ctx.pi + 1,
            ..ctx
        },
        GuiExitContext {
            process: ProcessIdentity {
                generation: ProcessGeneration::Hosted(8),
                ..ctx.process
            },
            ..ctx
        },
        GuiExitContext {
            eprocess: 0x50000,
            ..ctx
        },
        GuiExitContext {
            ethread: 0x60000,
            ..ctx
        },
        GuiExitContext {
            win32_thread: Some(0x70000),
            ..ctx
        },
        GuiExitContext {
            win32_process: Some(0x80000),
            ..ctx
        },
        GuiExitContext {
            final_mechanism: false,
            ..ctx
        },
    ] {
        assert_eq!(
            owner.acknowledge(changed, GuiExitAcknowledgment::ThreadClear, Ok(())),
            Err(GuiExitError::InvalidContext)
        );
        assert_eq!(
            owner.phase(),
            GuiExitPhase::Local(GuiExitAcknowledgment::ThreadClear)
        );
    }
    for action in [
        GuiExitAcknowledgment::ProcessClear,
        GuiExitAcknowledgment::CallbackRetirement,
    ] {
        assert_eq!(
            owner.acknowledge(ctx, action, Ok(())),
            Err(GuiExitError::WrongPhase)
        );
    }
    ack(&mut owner, GuiExitAcknowledgment::ThreadClear);
    assert_eq!(
        owner.acknowledge(ctx, GuiExitAcknowledgment::ThreadClear, Ok(())),
        Err(GuiExitError::WrongPhase)
    );
}

#[test]
fn invalid_contexts_are_rejected_before_consuming_owner_identity() {
    let ctx = context(true);
    let counter = AtomicU64::new(1);
    for bad in [
        GuiExitContext {
            process: ProcessIdentity::empty(),
            ..ctx
        },
        GuiExitContext {
            process: ProcessIdentity {
                pid: ctx.process.pid + 1,
                ..ctx.process
            },
            ..ctx
        },
        GuiExitContext {
            win32_thread: Some(0),
            ..ctx
        },
        GuiExitContext {
            win32_process: Some(0),
            ..ctx
        },
        GuiExitContext { eprocess: 0, ..ctx },
        GuiExitContext { ethread: 0, ..ctx },
        GuiExitContext {
            ethread: ctx.eprocess,
            ..ctx
        },
        GuiExitContext {
            final_mechanism: false,
            ..ctx
        },
    ] {
        assert!(matches!(
            GuiExitOwner::with_counter(bad, &counter),
            Err(GuiExitError::InvalidContext)
        ));
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }
}

#[test]
fn checked_owner_and_attempt_exhaustion_never_mutate_live_progress() {
    let counter = AtomicU64::new(u64::MAX);
    assert!(matches!(
        GuiExitOwner::with_counter(context(false), &counter),
        Err(GuiExitError::Exhausted)
    ));
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    let mut owner = GuiExitOwner::new(context(false)).unwrap();
    owner.epoch = u64::MAX;
    assert!(matches!(owner.begin(), Err(GuiExitError::Exhausted)));
    assert_eq!(
        owner.phase(),
        GuiExitPhase::ThreadExit(ProviderFinalizationPhase::Pending)
    );
}

#[test]
fn job_removal_is_a_retained_exact_invocation_not_a_local_acknowledgment() {
    for result in [
        ProviderFinalizationResult::NotEntered(0xc000_00a3),
        ProviderFinalizationResult::Returned(0),
        ProviderFinalizationResult::Returned(0xc000_0001),
        ProviderFinalizationResult::Indeterminate(0x103),
    ] {
        let ctx = context(true);
        let mut owner = GuiExitOwner::new(ctx).unwrap();
        accept(&mut owner, GuiExitStage::Thread);
        ack(&mut owner, GuiExitAcknowledgment::ThreadClear);
        let call = owner.begin().unwrap();
        let identity = owner.dispatch_identity(&call).unwrap();
        assert_eq!(identity.stage(), GuiExitStage::JobRemoval);
        assert_eq!(identity.context().job, Some(5));
        assert_eq!(
            owner.phase(),
            GuiExitPhase::JobRemoval(ProviderFinalizationPhase::Invoking)
        );
        assert!(matches!(owner.begin(), Err(GuiExitError::WrongPhase)));
        assert_eq!(
            owner.acknowledge(ctx, GuiExitAcknowledgment::ProcessClear, Ok(())),
            Err(GuiExitError::WrongPhase)
        );
        owner.record(call, result).unwrap();
        assert!(!owner.matches_dispatch_identity(identity));
        match result {
            ProviderFinalizationResult::NotEntered(_) => {
                accept(&mut owner, GuiExitStage::JobRemoval);
                assert_eq!(
                    owner.phase(),
                    GuiExitPhase::ProcessExit(ProviderFinalizationPhase::Pending)
                );
            }
            ProviderFinalizationResult::Returned(0) => {
                assert_eq!(
                    owner.phase(),
                    GuiExitPhase::ProcessExit(ProviderFinalizationPhase::Pending)
                );
            }
            ProviderFinalizationResult::Returned(status)
            | ProviderFinalizationResult::Indeterminate(status) => {
                assert_eq!(
                    owner.phase(),
                    GuiExitPhase::JobRemoval(ProviderFinalizationPhase::Indeterminate(status))
                );
                assert!(matches!(owner.begin(), Err(GuiExitError::WrongPhase)));
            }
        }
    }
    let ctx = context(true);
    assert!(matches!(
        GuiExitOwner::new(GuiExitContext {
            job: Some(0),
            ..ctx
        }),
        Err(GuiExitError::InvalidContext)
    ));
    assert!(matches!(
        GuiExitOwner::new(GuiExitContext {
            win32_process: None,
            ..ctx
        }),
        Err(GuiExitError::InvalidContext)
    ));
}

#[test]
fn dispatch_evidence_is_exact_and_expires_on_every_recorded_outcome() {
    for result in [
        ProviderFinalizationResult::NotEntered(1),
        ProviderFinalizationResult::Returned(0),
        ProviderFinalizationResult::Returned(0xc000_0001),
        ProviderFinalizationResult::Indeterminate(0),
    ] {
        let ctx = context(false);
        let mut owner = GuiExitOwner::new(ctx).unwrap();
        let mut foreign = GuiExitOwner::new(ctx).unwrap();
        let call = owner.begin().unwrap();
        let other = foreign.begin().unwrap();
        let identity = owner.dispatch_identity(&call).unwrap();
        assert_eq!(identity.context(), ctx);
        assert_eq!(identity.stage(), GuiExitStage::Thread);
        assert!(owner.matches_dispatch_identity(identity));
        assert!(!foreign.matches_dispatch_identity(identity));
        assert_eq!(
            foreign.dispatch_identity(&call),
            Err(GuiExitError::WrongInvocation)
        );
        assert_eq!(
            owner.dispatch_identity(&other),
            Err(GuiExitError::WrongInvocation)
        );
        owner.record(call, result).unwrap();
        assert!(!owner.matches_dispatch_identity(identity));
        if matches!(result, ProviderFinalizationResult::NotEntered(_)) {
            let retry = owner.begin().unwrap();
            assert!(!owner.matches_dispatch_identity(identity));
            assert_ne!(owner.dispatch_identity(&retry).unwrap(), identity);
        }
    }
}
