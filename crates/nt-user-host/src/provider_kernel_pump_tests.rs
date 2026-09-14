use super::*;

const CAP: u64 = 42;

fn facts(mask: u8) -> KernelProviderPumpFacts {
    KernelProviderPumpFacts {
        reply_cap: CAP,
        completed: mask & 1 != 0,
        callback_suspended: mask & 2 != 0,
        provider_wait_suspended: mask & 4 != 0,
        lpc_wait_suspended: mask & 8 != 0,
        scheduler_yielded: mask & 16 != 0,
    }
}

fn observe_once(
    facts: KernelProviderPumpFacts,
    status: Option<u32>,
) -> KernelProviderPumpDisposition {
    let mut progress = KernelProviderPumpProgress::new(CAP).unwrap();
    assert_eq!(progress.disposition(), None);
    let mut attempt = progress.begin_initial().unwrap();
    assert_eq!(progress.disposition(), None);
    let observed = progress.observe(&mut attempt, facts, status).unwrap();
    assert_eq!(progress.disposition(), Some(observed));
    assert_eq!(
        progress.begin_initial().unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(
        progress.observe(&mut attempt, facts, status),
        Err(PumpProgressError::WrongAttempt)
    );
    observed
}

#[test]
fn rejects_zero_cap_and_qualifies_only_exact_unambiguous_return() {
    assert!(matches!(
        KernelProviderPumpProgress::new(0),
        Err(PumpProgressError::InvalidReplyCap)
    ));
    for mask in 0..32 {
        assert_eq!(facts(mask).is_return(CAP), mask == 1);
        assert!(!facts(mask).is_return(CAP + 1));
        assert!(!facts(mask).is_return(0));
    }
    let mut invalid = facts(1);
    invalid.reply_cap = 0;
    assert!(!invalid.is_return(0));
}

#[test]
fn retains_success_pending_and_failure_as_actual_return_status() {
    for status in [0, 0x103, 0xc000_0001, u32::MAX] {
        assert_eq!(
            observe_once(facts(1), Some(status)),
            KernelProviderPumpDisposition::Returned(status)
        );
    }
}

#[test]
fn keeps_each_stop_reason_distinct_and_sealed() {
    use KernelProviderPumpDisposition::*;
    for (mask, expected) in [
        (0, Walled),
        (2, CallbackSuspended),
        (4, ProviderWaitSuspended),
        (8, LpcWaitSuspended),
        (16, SchedulerYielded),
    ] {
        assert_eq!(observe_once(facts(mask), None), expected);
    }
}

#[test]
fn all_conflicting_flags_caps_and_status_shapes_seal_invalid_observation() {
    for mask in 0u8..32 {
        if mask.count_ones() > 1 {
            assert_eq!(
                observe_once(facts(mask), None),
                KernelProviderPumpDisposition::Invalid
            );
            assert_eq!(
                observe_once(facts(mask), Some(0)),
                KernelProviderPumpDisposition::Invalid
            );
        }
        for reply_cap in [0, CAP + 1] {
            let mut wrong_cap = facts(mask);
            wrong_cap.reply_cap = reply_cap;
            assert_eq!(
                observe_once(wrong_cap, if mask == 1 { Some(0) } else { None }),
                KernelProviderPumpDisposition::Invalid
            );
        }
        if mask != 1 {
            assert_eq!(
                observe_once(facts(mask), Some(0)),
                KernelProviderPumpDisposition::Invalid
            );
        }
    }
    assert_eq!(
        observe_once(facts(1), None),
        KernelProviderPumpDisposition::Invalid
    );
}

#[test]
fn duplicate_begin_and_dropped_ticket_never_reopen_execution() {
    let mut progress = KernelProviderPumpProgress::new(CAP).unwrap();
    let attempt = progress.begin_initial().unwrap();
    assert_eq!(
        progress.begin_initial().unwrap_err(),
        PumpProgressError::NotReady
    );
    drop(attempt);
    assert_eq!(progress.disposition(), None);
    assert_eq!(
        progress.begin_initial().unwrap_err(),
        PumpProgressError::NotReady
    );
}

#[test]
fn foreign_ticket_cannot_observe_ready_or_entered_owner() {
    let mut first = KernelProviderPumpProgress::new(CAP).unwrap();
    let mut second = KernelProviderPumpProgress::new(CAP).unwrap();
    let mut first_attempt = first.begin_initial().unwrap();
    assert_eq!(
        second.observe(&mut first_attempt, facts(1), Some(0)),
        Err(PumpProgressError::WrongAttempt)
    );
    assert_eq!(second.progress, Progress::Ready);
    assert!(!first_attempt.consumed);
    let mut second_attempt = second.begin_initial().unwrap();
    let second_before = second.progress;
    assert_eq!(
        second.observe(&mut first_attempt, facts(1), Some(0)),
        Err(PumpProgressError::WrongAttempt)
    );
    assert_eq!(second.progress, second_before);
    assert!(!first_attempt.consumed);
    assert_eq!(
        first.observe(&mut first_attempt, facts(1), Some(0xc000_0001)),
        Ok(KernelProviderPumpDisposition::Returned(0xc000_0001))
    );
    assert_eq!(
        second.observe(&mut first_attempt, facts(1), Some(0)),
        Err(PumpProgressError::WrongAttempt)
    );
    assert_eq!(
        second.observe(&mut second_attempt, facts(1), Some(0)),
        Ok(KernelProviderPumpDisposition::Returned(0))
    );
}

#[test]
fn replacement_with_same_cap_rejects_consumed_ticket() {
    let mut first = KernelProviderPumpProgress::new(CAP).unwrap();
    let mut stale = first.begin_initial().unwrap();
    first.observe(&mut stale, facts(0), None).unwrap();
    let mut replacement = KernelProviderPumpProgress::new(CAP).unwrap();
    let mut current = replacement.begin_initial().unwrap();
    assert_eq!(
        replacement.observe(&mut stale, facts(1), Some(0)),
        Err(PumpProgressError::WrongAttempt)
    );
    assert_eq!(replacement.disposition(), None);
    replacement
        .observe(&mut current, facts(1), Some(0))
        .unwrap();
}

#[test]
fn attempt_counter_never_wraps_and_failed_reservation_preserves_ready() {
    for initial in [0, u64::MAX] {
        let counter = AtomicU64::new(initial);
        let mut progress = KernelProviderPumpProgress::new(CAP).unwrap();
        assert_eq!(
            progress.begin_entry(Progress::Ready, &counter).unwrap_err(),
            PumpProgressError::IdentityExhausted
        );
        assert_eq!(progress.progress, Progress::Ready);
        assert_eq!(counter.load(Ordering::Relaxed), initial);
    }
    let counter = AtomicU64::new(u64::MAX - 1);
    let mut first = KernelProviderPumpProgress::new(CAP).unwrap();
    let mut ticket = first.begin_entry(Progress::Ready, &counter).unwrap();
    let mut second = KernelProviderPumpProgress::new(CAP).unwrap();
    assert_eq!(
        second.begin_entry(Progress::Ready, &counter).unwrap_err(),
        PumpProgressError::IdentityExhausted
    );
    assert_eq!(second.progress, Progress::Ready);
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    first.observe(&mut ticket, facts(1), Some(0)).unwrap();
}

fn yielded_progress() -> (KernelProviderPumpProgress, KernelProviderPumpAttempt) {
    let mut progress = KernelProviderPumpProgress::new(CAP).unwrap();
    let mut first = progress.begin_initial().unwrap();
    progress.observe(&mut first, facts(16), None).unwrap();
    (progress, first)
}

#[test]
fn consecutive_scheduler_yields_each_require_a_fresh_receive_entry() {
    let (mut progress, mut previous) = yielded_progress();
    for _ in 0..4 {
        assert_eq!(
            progress.begin_initial().unwrap_err(),
            PumpProgressError::NotReady
        );
        let mut current = progress.begin_receive_after_yield().unwrap();
        assert_ne!(current.nonce, previous.nonce);
        assert_eq!(
            progress.begin_receive_after_yield().unwrap_err(),
            PumpProgressError::NotReady
        );
        assert_eq!(
            progress.observe(&mut previous, facts(1), Some(0)),
            Err(PumpProgressError::WrongAttempt)
        );
        assert_eq!(progress.disposition(), None);
        assert_eq!(
            progress.observe(&mut current, facts(16), None),
            Ok(KernelProviderPumpDisposition::SchedulerYielded)
        );
        previous = current;
    }
    let mut final_receive = progress.begin_receive_after_yield().unwrap();
    assert_eq!(
        progress.observe(&mut final_receive, facts(1), Some(0xc000_0001)),
        Ok(KernelProviderPumpDisposition::Returned(0xc000_0001))
    );
    assert_eq!(
        progress.begin_receive_after_yield().unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(
        progress.disposition(),
        Some(KernelProviderPumpDisposition::Returned(0xc000_0001))
    );
}

#[test]
fn receive_after_yield_rejects_every_other_observed_or_unentered_state() {
    let mut fresh = KernelProviderPumpProgress::new(CAP).unwrap();
    assert_eq!(
        fresh.begin_receive_after_yield().unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(fresh.progress, Progress::Ready);
    for mask in 0..32 {
        if mask == 16 {
            continue;
        }
        let (mut progress, _) = yielded_progress();
        let mut attempt = progress.begin_receive_after_yield().unwrap();
        let status = if mask == 1 { Some(0) } else { None };
        let disposition = progress.observe(&mut attempt, facts(mask), status).unwrap();
        assert_ne!(disposition, KernelProviderPumpDisposition::SchedulerYielded);
        assert_eq!(
            progress.begin_receive_after_yield().unwrap_err(),
            PumpProgressError::NotReady
        );
        assert_eq!(progress.disposition(), Some(disposition));
    }
    let (mut progress, _) = yielded_progress();
    let mut attempt = progress.begin_receive_after_yield().unwrap();
    let mut wrong_cap = facts(16);
    wrong_cap.reply_cap += 1;
    assert_eq!(
        progress.observe(&mut attempt, wrong_cap, None),
        Ok(KernelProviderPumpDisposition::Invalid)
    );
    assert_eq!(
        progress.begin_receive_after_yield().unwrap_err(),
        PumpProgressError::NotReady
    );
}

#[test]
fn dropped_receive_ticket_does_not_restore_yield_or_permit_replay() {
    let (mut progress, mut first) = yielded_progress();
    let receive = progress.begin_receive_after_yield().unwrap();
    let entered = progress.progress;
    drop(receive);
    assert_eq!(
        progress.begin_receive_after_yield().unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(
        progress.begin_initial().unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(
        progress.observe(&mut first, facts(16), None),
        Err(PumpProgressError::WrongAttempt)
    );
    assert_eq!(progress.progress, entered);
    assert_eq!(progress.disposition(), None);
}

#[test]
fn receive_tickets_cannot_cross_same_cap_recipients_or_replay_into_later_receive() {
    let (mut first, _) = yielded_progress();
    let (mut second, _) = yielded_progress();
    let mut first_receive = first.begin_receive_after_yield().unwrap();
    let mut second_receive = second.begin_receive_after_yield().unwrap();
    let second_entered = second.progress;
    assert_eq!(
        second.observe(&mut first_receive, facts(16), None),
        Err(PumpProgressError::WrongAttempt)
    );
    assert!(!first_receive.consumed);
    assert_eq!(second.progress, second_entered);
    first.observe(&mut first_receive, facts(16), None).unwrap();
    let mut next_receive = first.begin_receive_after_yield().unwrap();
    assert_eq!(
        first.observe(&mut first_receive, facts(1), Some(0)),
        Err(PumpProgressError::WrongAttempt)
    );
    first.observe(&mut next_receive, facts(1), Some(0)).unwrap();
    second
        .observe(&mut second_receive, facts(1), Some(0))
        .unwrap();
}

#[test]
fn receive_nonce_exhaustion_preserves_exact_observed_yield() {
    for initial in [0, u64::MAX] {
        let counter = AtomicU64::new(initial);
        let (mut progress, _) = yielded_progress();
        let expected = progress.progress;
        assert_eq!(
            progress.begin_entry(expected, &counter).unwrap_err(),
            PumpProgressError::IdentityExhausted
        );
        assert_eq!(progress.progress, expected);
        assert_eq!(counter.load(Ordering::Relaxed), initial);
    }
    let counter = AtomicU64::new(u64::MAX - 1);
    let (mut progress, _) = yielded_progress();
    let expected = progress.progress;
    let mut last = progress.begin_entry(expected, &counter).unwrap();
    progress.observe(&mut last, facts(16), None).unwrap();
    let expected = progress.progress;
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    assert_eq!(
        progress.begin_entry(expected, &counter).unwrap_err(),
        PumpProgressError::IdentityExhausted
    );
    assert_eq!(progress.progress, expected);
}

fn provider_wait_progress() -> (KernelProviderPumpProgress, KernelProviderPumpObservation) {
    let mut progress = KernelProviderPumpProgress::new(CAP).unwrap();
    let mut first = progress.begin_initial().unwrap();
    progress.observe(&mut first, facts(4), None).unwrap();
    let observation = progress.provider_wait_observation(CAP).unwrap();
    (progress, observation)
}

#[test]
fn only_exact_provider_wait_has_an_observation_epoch() {
    let mut progress = KernelProviderPumpProgress::new(CAP).unwrap();
    assert_eq!(progress.provider_wait_observation(CAP), None);
    let mut initial = progress.begin_initial().unwrap();
    assert_eq!(progress.provider_wait_observation(CAP), None);
    progress.observe(&mut initial, facts(4), None).unwrap();
    assert!(progress.observed_provider_wait(CAP));
    assert_eq!(progress.provider_wait_observation(0), None);
    assert_eq!(progress.provider_wait_observation(CAP + 1), None);
    for mask in 0..32 {
        if mask == 4 {
            continue;
        }
        let mut progress = KernelProviderPumpProgress::new(CAP).unwrap();
        let mut initial = progress.begin_initial().unwrap();
        progress
            .observe(
                &mut initial,
                facts(mask),
                if mask == 1 { Some(0) } else { None },
            )
            .unwrap();
        assert_eq!(progress.provider_wait_observation(CAP), None);
        assert!(!progress.observed_provider_wait(CAP));
    }
}

#[test]
fn prepare_is_not_entry_and_dropped_reservation_preserves_observation() {
    let (mut progress, observation) = provider_wait_progress();
    let expected = progress.progress;
    let mut prepared = progress.prepare_provider_wait_resume(observation).unwrap();
    assert_eq!(progress.progress, expected);
    assert_eq!(
        progress.observe(&mut prepared, facts(1), Some(0)),
        Err(PumpProgressError::WrongAttempt)
    );
    assert!(!prepared.consumed);
    let discarded_nonce = prepared.nonce;
    drop(prepared);
    assert_eq!(progress.progress, expected);
    let mut entered = progress.prepare_provider_wait_resume(observation).unwrap();
    assert_ne!(entered.nonce, discarded_nonce);
    progress.commit_provider_wait_resume(observation, &entered);
    assert_eq!(progress.provider_wait_observation(CAP), None);
    assert_eq!(
        progress
            .prepare_provider_wait_resume(observation)
            .unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(
        progress.observe(&mut entered, facts(1), Some(0)),
        Ok(KernelProviderPumpDisposition::Returned(0))
    );
}

#[test]
fn repark_and_same_cap_replacement_reject_stale_observation() {
    let (mut progress, first) = provider_wait_progress();
    let mut resume = progress.prepare_provider_wait_resume(first).unwrap();
    progress.commit_provider_wait_resume(first, &resume);
    progress.observe(&mut resume, facts(4), None).unwrap();
    let second = progress.provider_wait_observation(CAP).unwrap();
    assert_ne!(first, second);
    let expected = progress.progress;
    assert_eq!(
        progress.prepare_provider_wait_resume(first).unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(progress.progress, expected);
    let (replacement, replacement_observation) = provider_wait_progress();
    assert_ne!(replacement_observation, second);
    assert_eq!(
        replacement
            .prepare_provider_wait_resume(second)
            .unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(
        replacement.provider_wait_observation(CAP),
        Some(replacement_observation)
    );
}

#[test]
fn wrong_observation_cap_or_nonce_does_not_change_progress_or_allocate() {
    let (progress, observation) = provider_wait_progress();
    let expected = progress.progress;
    let counter = AtomicU64::new(80);
    for wrong in [
        KernelProviderPumpObservation {
            reply_cap: 0,
            ..observation
        },
        KernelProviderPumpObservation {
            reply_cap: CAP + 1,
            ..observation
        },
        KernelProviderPumpObservation {
            nonce: observation.nonce + 1,
            ..observation
        },
    ] {
        assert_eq!(
            progress
                .prepare_provider_wait_resume_with_counter(wrong, &counter)
                .unwrap_err(),
            PumpProgressError::NotReady
        );
        assert_eq!(progress.progress, expected);
        assert_eq!(counter.load(Ordering::Relaxed), 80);
    }
}

#[test]
fn dropped_entered_wait_resume_never_permits_replay() {
    let (mut progress, observation) = provider_wait_progress();
    let attempt = progress.prepare_provider_wait_resume(observation).unwrap();
    progress.commit_provider_wait_resume(observation, &attempt);
    let entered = progress.progress;
    drop(attempt);
    assert_eq!(progress.provider_wait_observation(CAP), None);
    assert_eq!(
        progress.begin_initial().unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(
        progress.begin_receive_after_yield().unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(
        progress
            .prepare_provider_wait_resume(observation)
            .unwrap_err(),
        PumpProgressError::NotReady
    );
    assert_eq!(progress.progress, entered);
}

#[test]
fn wait_resume_identity_exhaustion_preserves_exact_observation() {
    for initial in [0, u64::MAX] {
        let (progress, observation) = provider_wait_progress();
        let expected = progress.progress;
        let counter = AtomicU64::new(initial);
        assert_eq!(
            progress
                .prepare_provider_wait_resume_with_counter(observation, &counter)
                .unwrap_err(),
            PumpProgressError::IdentityExhausted
        );
        assert_eq!(progress.progress, expected);
        assert_eq!(counter.load(Ordering::Relaxed), initial);
    }
    let (mut progress, observation) = provider_wait_progress();
    let counter = AtomicU64::new(u64::MAX - 1);
    let mut last = progress
        .prepare_provider_wait_resume_with_counter(observation, &counter)
        .unwrap();
    progress.commit_provider_wait_resume(observation, &last);
    progress.observe(&mut last, facts(4), None).unwrap();
    let observation = progress.provider_wait_observation(CAP).unwrap();
    let expected = progress.progress;
    assert_eq!(
        progress
            .prepare_provider_wait_resume_with_counter(observation, &counter)
            .unwrap_err(),
        PumpProgressError::IdentityExhausted
    );
    assert_eq!(progress.progress, expected);
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
}

#[test]
#[should_panic]
fn duplicate_commit_cannot_reenter_a_claimed_wait() {
    let (mut progress, observation) = provider_wait_progress();
    let attempt = progress.prepare_provider_wait_resume(observation).unwrap();
    progress.commit_provider_wait_resume(observation, &attempt);
    progress.commit_provider_wait_resume(observation, &attempt);
}

#[test]
#[should_panic]
fn same_cap_foreign_reservation_cannot_commit() {
    let (first, first_observation) = provider_wait_progress();
    let (mut second, second_observation) = provider_wait_progress();
    let attempt = first
        .prepare_provider_wait_resume(first_observation)
        .unwrap();
    second.commit_provider_wait_resume(second_observation, &attempt);
}

#[test]
#[should_panic]
fn stale_prepared_reservation_cannot_commit_after_repark() {
    let (mut progress, observation) = provider_wait_progress();
    let stale = progress.prepare_provider_wait_resume(observation).unwrap();
    let mut attempt = progress.prepare_provider_wait_resume(observation).unwrap();
    progress.commit_provider_wait_resume(observation, &attempt);
    progress.observe(&mut attempt, facts(4), None).unwrap();
    let current = progress.provider_wait_observation(CAP).unwrap();
    progress.commit_provider_wait_resume(current, &stale);
}
