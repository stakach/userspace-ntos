use nt_memory_manager::local_pagein_drive::{DriveDecision, DriveStep, LocalDriveBudget};

#[test]
fn ready_fault_phases_advance_in_one_bounded_pass() {
    let mut budget = LocalDriveBudget::new(16);
    for _ in 0..7 {
        assert_eq!(budget.observe(DriveStep::LocalProgress), DriveDecision::Continue);
    }
    assert_eq!(budget.observe(DriveStep::ReplyEntered), DriveDecision::RetryLater);
}

#[test]
fn pending_or_uncertain_effect_yields_without_consuming_another_step() {
    let mut budget = LocalDriveBudget::new(16);
    assert_eq!(budget.observe(DriveStep::LocalProgress), DriveDecision::Continue);
    assert_eq!(budget.observe(DriveStep::AwaitExternal), DriveDecision::RetryLater);
    assert_eq!(budget.observe(DriveStep::ReplyEntered), DriveDecision::RetryLater);
}

#[test]
fn exhausted_budget_schedules_the_remaining_local_work_immediately() {
    let mut budget = LocalDriveBudget::new(2);
    assert_eq!(budget.observe(DriveStep::LocalProgress), DriveDecision::Continue);
    assert_eq!(budget.observe(DriveStep::LocalProgress), DriveDecision::RetryNow);
    assert_eq!(budget.observe(DriveStep::LocalProgress), DriveDecision::RetryNow);
    assert_eq!(budget.observe(DriveStep::Done), DriveDecision::Complete);
}
