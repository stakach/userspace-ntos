use nt_memory_manager::local_pagein_drive::{
    classify_drive_step, DriveBoundary, DriveDecision, DriveStep, LocalDriveBudget,
};

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

#[test]
fn section_copy_fragments_and_ready_phases_drive_before_one_reply_boundary() {
    // One completed 8-page read yields several bounded local copies, an ACK,
    // publication and an entered Reply. None needs a 100 ms provider wakeup.
    let mut steps = [
        DriveStep::LocalProgress, DriveStep::LocalProgress,
        DriveStep::LocalProgress, DriveStep::LocalProgress,
        DriveStep::LocalProgress, DriveStep::LocalProgress,
        DriveStep::LocalProgress, DriveStep::ReplyEntered,
    ].into_iter();
    let mut calls = 0;
    let decision = LocalDriveBudget::new(16).drive_while_local(|| {
        calls += 1;
        steps.next().expect("drive must stop at the entered Reply")
    });
    assert_eq!(decision, DriveDecision::RetryLater);
    assert_eq!(calls, 8);
}

#[test]
fn section_drive_stops_at_pending_or_uncertain_effect_and_retries_bounded_local_work() {
    let mut calls = 0;
    let decision = LocalDriveBudget::new(16).drive_while_local(|| {
        calls += 1;
        if calls == 1 { DriveStep::LocalProgress } else { DriveStep::AwaitExternal }
    });
    assert_eq!(decision, DriveDecision::RetryLater);
    assert_eq!(calls, 2);

    let mut calls = 0;
    let decision = LocalDriveBudget::new(2).drive_while_local(|| {
        calls += 1;
        DriveStep::LocalProgress
    });
    assert_eq!(decision, DriveDecision::RetryNow);
    assert_eq!(calls, 2);
}

#[test]
fn section_phase_classifier_requires_proven_copy_progress_and_honors_effect_boundaries() {
    assert_eq!(classify_drive_step(false, DriveBoundary::Local, true),
        DriveStep::LocalProgress); // another completed copy fragment
    assert_eq!(classify_drive_step(false, DriveBoundary::Local, false),
        DriveStep::AwaitExternal); // unchanged copy offset
    assert_eq!(classify_drive_step(false, DriveBoundary::External, true),
        DriveStep::AwaitExternal); // Dispatch entered Pending
    assert_eq!(classify_drive_step(false, DriveBoundary::Uncertain, true),
        DriveStep::AwaitExternal); // ACK entered Indeterminate
    assert_eq!(classify_drive_step(false, DriveBoundary::ReplyEntered, true),
        DriveStep::ReplyEntered); // Reply may have been sent
    assert_eq!(classify_drive_step(true, DriveBoundary::Local, false), DriveStep::Done);
}
