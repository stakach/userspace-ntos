use crate::yield_handoff::*;
use alloc::vec::Vec;

fn fenced(plan: &HandoffPlan) -> Vec<(YieldKind, u64, HandoffViolation)> {
    plan.fenced()
        .map(|fenced| (fenced.record.kind, fenced.record.dispatch_id, fenced.violation))
        .collect()
}

#[test]
fn a_completed_dispatch_with_nothing_pending_hands_off_nothing() {
    let plan = plan(HandoffObservation::new(Some(7), false));
    assert_eq!(plan.admit, None);
    assert!(!plan.callback && !plan.current_fenced);
    assert!(fenced(&plan).is_empty());
}

#[test]
fn a_dispatch_admits_its_own_single_yield_record() {
    for kind in YieldKind::ALL {
        let plan = plan(HandoffObservation::new(Some(7), false).with(kind, 7));
        assert_eq!(plan.admit, Some(kind));
        assert!(!plan.callback && !plan.current_fenced);
        assert!(fenced(&plan).is_empty());
    }
}

/// Issue #398: Winlogon's callback-return GDI flush (dispatch 3171) left a service-wait
/// record that no handoff consumed. The next handoff belonged to spoolsv's first GUI
/// syscall (dispatch 3200), which had issued a user callback. The foreign record must not
/// park spoolsv's Reply, and spoolsv's callback must still be delivered.
#[test]
fn a_record_left_by_another_dispatch_is_fenced_and_the_callback_is_delivered() {
    let plan = plan(
        HandoffObservation::new(Some(3200), true).with(YieldKind::ServiceWait, 3171),
    );
    assert_eq!(plan.admit, None);
    assert!(plan.callback);
    assert!(!plan.current_fenced);
    assert_eq!(
        fenced(&plan),
        [(YieldKind::ServiceWait, 3171, HandoffViolation::ForeignRecord)],
    );
}

#[test]
fn a_foreign_record_never_parks_a_completed_dispatch() {
    let plan = plan(
        HandoffObservation::new(Some(3200), false).with(YieldKind::ProviderWait, 3171),
    );
    assert_eq!(plan.admit, None);
    assert!(!plan.callback && !plan.current_fenced);
    assert_eq!(
        fenced(&plan),
        [(YieldKind::ProviderWait, 3171, HandoffViolation::ForeignRecord)],
    );
}

#[test]
fn a_foreign_record_does_not_displace_the_dispatch_s_own_record() {
    let plan = plan(
        HandoffObservation::new(Some(9), false)
            .with(YieldKind::ServiceWait, 4)
            .with(YieldKind::LpcWait, 9),
    );
    assert_eq!(plan.admit, Some(YieldKind::LpcWait));
    assert!(!plan.current_fenced);
    assert_eq!(fenced(&plan), [(YieldKind::ServiceWait, 4, HandoffViolation::ForeignRecord)]);
}

#[test]
fn a_dispatch_claiming_a_callback_and_a_wait_gets_neither() {
    let plan = plan(
        HandoffObservation::new(Some(9), true).with(YieldKind::ProviderWait, 9),
    );
    assert_eq!(plan.admit, None);
    assert!(!plan.callback);
    assert!(plan.current_fenced);
    assert_eq!(
        fenced(&plan),
        [(YieldKind::ProviderWait, 9, HandoffViolation::DoubleSuspension)],
    );
}

#[test]
fn a_dispatch_claiming_two_yield_records_gets_neither() {
    let plan = plan(
        HandoffObservation::new(Some(9), false)
            .with(YieldKind::Receive, 9)
            .with(YieldKind::ServiceWait, 9),
    );
    assert_eq!(plan.admit, None);
    assert!(plan.current_fenced);
    assert_eq!(
        fenced(&plan),
        [
            (YieldKind::Receive, 9, HandoffViolation::DoubleSuspension),
            (YieldKind::ServiceWait, 9, HandoffViolation::DoubleSuspension),
        ],
    );
}

/// A provider callout's dispatch is not nameable by its caller, so a lone record is taken
/// to be its own. Two suspensions are still never both acted on.
#[test]
fn an_unnamed_dispatch_admits_a_lone_record_and_refuses_a_second_suspension() {
    let lone = plan(HandoffObservation::new(None, false).with(YieldKind::ProviderWait, 5));
    assert_eq!(lone.admit, Some(YieldKind::ProviderWait));
    assert!(!lone.current_fenced);

    let both = plan(HandoffObservation::new(None, true).with(YieldKind::ProviderWait, 5));
    assert_eq!(both.admit, None);
    assert!(!both.callback && both.current_fenced);
    assert_eq!(
        fenced(&both),
        [(YieldKind::ProviderWait, 5, HandoffViolation::DoubleSuspension)],
    );
}

#[test]
fn every_pending_record_is_admitted_or_fenced() {
    for current in [None, Some(1), Some(2)] {
        for callback in [false, true] {
            for mask in 0u32..16 {
                let mut observation = HandoffObservation::new(current, callback);
                let mut pending = 0;
                for (bit, kind) in YieldKind::ALL.into_iter().enumerate() {
                    if mask & (1 << bit) != 0 {
                        observation = observation.with(kind, 1 + (bit as u64 % 2));
                        pending += 1;
                    }
                }
                let plan = plan(observation);
                let settled = plan.fenced().count() + usize::from(plan.admit.is_some());
                assert_eq!(settled, pending);
                assert!(!(plan.admit.is_some() && plan.callback));
                assert!(!plan.current_fenced || (plan.admit.is_none() && !plan.callback));
            }
        }
    }
}
