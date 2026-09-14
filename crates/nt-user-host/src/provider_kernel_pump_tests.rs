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
            progress.begin_initial_with_counter(&counter).unwrap_err(),
            PumpProgressError::IdentityExhausted
        );
        assert_eq!(progress.progress, Progress::Ready);
        assert_eq!(counter.load(Ordering::Relaxed), initial);
    }
    let counter = AtomicU64::new(u64::MAX - 1);
    let mut first = KernelProviderPumpProgress::new(CAP).unwrap();
    let mut ticket = first.begin_initial_with_counter(&counter).unwrap();
    let mut second = KernelProviderPumpProgress::new(CAP).unwrap();
    assert_eq!(
        second.begin_initial_with_counter(&counter).unwrap_err(),
        PumpProgressError::IdentityExhausted
    );
    assert_eq!(second.progress, Progress::Ready);
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    first.observe(&mut ticket, facts(1), Some(0)).unwrap();
}
