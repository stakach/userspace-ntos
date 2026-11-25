//! A retained connection must resume after every irreversible retirement effect.

#[path = "../../../components/ntos-executive/src/hosted_irq_retirement_progress.rs"]
mod native_progress;

use native_progress::{RetirementProgress, RetirementTailAction};

#[test]
fn lease_release_is_not_replayed_when_lock_unregistration_needs_retry() {
    assert_eq!(
        native_progress::next_tail_action(RetirementProgress {
            physical_lease_released: true,
            actual_lock_unregistered: false,
        }),
        RetirementTailAction::UnregisterActualLock,
    );
}

#[test]
fn completed_canonical_effects_reach_projection_tombstone_without_replay() {
    assert_eq!(
        native_progress::next_tail_action(RetirementProgress {
            physical_lease_released: true,
            actual_lock_unregistered: true,
        }),
        RetirementTailAction::Finish,
    );
}

#[test]
fn fresh_retirement_starts_with_physical_lease_release() {
    assert_eq!(
        native_progress::next_tail_action(RetirementProgress::default()),
        RetirementTailAction::ReleasePhysicalLease,
    );
}

#[test]
fn native_retirement_retains_steps_until_projection_tombstone() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let connection = source
        .split_once("struct HostedIrqConnection {")
        .expect("native connection type")
        .1
        .split_once("\n}")
        .unwrap()
        .0;
    assert!(connection.contains("physical_line:"));
    assert!(connection.contains("retirement:"));

    let retirement = source
        .split_once("unsafe fn retire_hosted_irq_connection(")
        .expect("native retirement")
        .1
        .split_once("\nunsafe fn retire_hosted_irq_connections_for_binding(")
        .unwrap()
        .0;
    assert!(retirement.contains("connection.physical_line"));
    assert!(retirement.contains("next_tail_action("));
    assert!(retirement.contains("retirement.physical_lease_released = true"));
    assert!(retirement.contains("retirement.actual_lock_unregistered = true"));
    let mark = retirement
        .find("mark_interrupt_projection_canonical_retired(")
        .unwrap();
    let remove = retirement
        .find("hosted_irq_connections_mut().remove(connection_index)")
        .unwrap();
    assert!(
        mark < remove,
        "the exact row must survive any fallible tombstone step"
    );
}
