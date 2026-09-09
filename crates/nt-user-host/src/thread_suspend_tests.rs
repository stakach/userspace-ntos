use super::*;
use crate::process_identity::{ProcessGeneration, ProcessIdentity};
use nt_process::ThreadState;

struct Fixture {
    pm: ProcessManager,
    binding: ThreadBinding<()>,
    lifetime: ThreadLifetime,
    owner: ThreadSuspendOwner<()>,
}

impl Fixture {
    fn new(dormant: bool) -> Self {
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("suspend", None, None);
        let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
        let lifetime = pm.thread_lifetime(tid).unwrap();
        let binding = ThreadBinding {
            pi: 2,
            process: ProcessIdentity {
                pid,
                generation: ProcessGeneration::Hosted(7),
            },
            tid: u64::from(tid),
            badge: 8,
            role: (),
            tcb: 32,
            reservations: None,
        };
        let owner = if dormant {
            unsafe { ThreadSuspendOwner::dormant(binding, lifetime).unwrap() }
        } else {
            ThreadSuspendOwner::running(binding, lifetime).unwrap()
        };
        Self {
            pm,
            binding,
            lifetime,
            owner,
        }
    }

    fn prepare(&mut self, op: ThreadSuspendOperation) -> ThreadSuspendPhase {
        self.owner
            .prepare(&mut self.pm, self.binding, self.lifetime, op)
            .unwrap()
    }

    fn finish(&mut self) -> ThreadSuspendCompletion {
        self.owner
            .finish(&mut self.pm, self.binding, self.lifetime)
            .unwrap()
    }

    fn count(&self) -> u32 {
        self.pm
            .thread(self.lifetime.thread_id())
            .unwrap()
            .suspend_count
    }

    fn acquire(&mut self, generation: u64) {
        assert_eq!(
            self.prepare(ThreadSuspendOperation::Suspend),
            ThreadSuspendPhase::Prepared
        );
        let invocation = self.owner.begin().unwrap();
        assert_eq!(
            invocation.action(),
            ThreadSuspendAction::Acquire {
                tcb: self.binding.tcb
            }
        );
        self.owner
            .record(
                invocation,
                ThreadSuspendOutcome::Acknowledged {
                    generation: Some(generation),
                },
            )
            .unwrap();
        assert_eq!(self.finish().count, 1);
    }
}

// Deliberately counterfeit a duplicate inside the private test module; production cannot clone
// or construct this capability. This exercises the retained phase/PM revision checks as well.
fn duplicate(inv: &ThreadSuspendInvocation<()>) -> ThreadSuspendInvocation<()> {
    ThreadSuspendInvocation {
        identity: inv.identity,
        binding: inv.binding,
        lifetime: inv.lifetime,
        action: inv.action,
    }
}

#[test]
fn deleted_tcb_consumes_settled_running_dormant_and_held_owners() {
    for state in 0..3 {
        let mut f = Fixture::new(state == 1);
        if state == 2 {
            f.acquire(47);
        }
        let before_count = f.count();
        let binding = f.binding;
        assert!(unsafe { f.owner.retire_deleted_tcb(binding) }.is_ok());
        // Physical destruction consumes the hold without issuing Release or changing Ps counts.
        assert_eq!(
            f.pm.thread(f.lifetime.thread_id()).unwrap().suspend_count,
            before_count
        );
    }
}

#[test]
fn deleted_tcb_wrong_binding_returns_the_exact_held_owner() {
    let mut f = Fixture::new(false);
    f.acquire(53);
    let mut replacement = f.binding;
    replacement.tcb += 1;
    let (error, owner) = unsafe { f.owner.retire_deleted_tcb(replacement) }.unwrap_err();
    assert_eq!(error, ThreadSuspendError::OwnerChanged);
    assert_eq!(
        owner.execution_state(),
        ThreadExecutionState::Held { generation: 53 }
    );
    assert_eq!(owner.phase(), ThreadSuspendPhase::Idle);
    assert!(unsafe { owner.retire_deleted_tcb(f.binding) }.is_ok());
}

#[test]
fn deleted_tcb_cannot_discard_any_unfinished_control_phase() {
    for phase in 0..6 {
        let mut f = Fixture::new(false);
        f.prepare(ThreadSuspendOperation::Suspend);
        if phase != 0 {
            let invocation = f.owner.begin().unwrap();
            if phase > 1 {
                let outcome = match phase {
                    2 => ThreadSuspendOutcome::Acknowledged {
                        generation: Some(59),
                    },
                    3 => ThreadSuspendOutcome::Rejected { status: 123 },
                    4 => ThreadSuspendOutcome::Indeterminate { status: 124 },
                    _ => ThreadSuspendOutcome::Acknowledged { generation: None },
                };
                f.owner.record(invocation, outcome).unwrap();
            }
        }
        let before = f.owner.phase();
        let (error, owner) = unsafe { f.owner.retire_deleted_tcb(f.binding) }.unwrap_err();
        assert_eq!(error, ThreadSuspendError::Busy);
        assert_eq!(owner.phase(), before);
        assert_eq!(owner.execution_state(), ThreadExecutionState::Running);
        assert!(f.pm.has_thread_suspend_control(f.lifetime.thread_id()));
        assert_eq!(
            f.pm.thread(f.lifetime.thread_id()).unwrap().suspend_count,
            0
        );
    }
}

#[test]
fn acquire_and_exact_release_commit_only_after_ack() {
    let mut f = Fixture::new(false);
    assert_eq!(
        f.prepare(ThreadSuspendOperation::Suspend),
        ThreadSuspendPhase::Prepared
    );
    assert_eq!(f.count(), 0);
    assert!(f.pm.has_thread_suspend_control(f.lifetime.thread_id()));
    assert!(!f.owner.can_retire());
    let invocation = f.owner.begin().unwrap();
    assert_eq!(invocation.binding(), f.binding);
    assert_eq!(invocation.lifetime(), f.lifetime);
    assert!(matches!(
        f.owner.begin(),
        Err(ThreadSuspendError::WrongPhase)
    ));
    f.owner
        .record(
            invocation,
            ThreadSuspendOutcome::Acknowledged {
                generation: Some(42),
            },
        )
        .unwrap();
    assert_eq!(f.count(), 0);
    assert_eq!(
        f.finish(),
        ThreadSuspendCompletion {
            previous_count: 0,
            count: 1,
            rejection: None
        }
    );
    assert_eq!(
        f.owner.execution_state(),
        ThreadExecutionState::Held { generation: 42 }
    );
    assert!(f.owner.can_retire());
    assert_eq!(
        f.prepare(ThreadSuspendOperation::Resume),
        ThreadSuspendPhase::Prepared
    );
    let invocation = f.owner.begin().unwrap();
    assert_eq!(
        invocation.action(),
        ThreadSuspendAction::Release {
            tcb: f.binding.tcb,
            generation: 42
        }
    );
    f.owner
        .record(
            invocation,
            ThreadSuspendOutcome::Acknowledged { generation: None },
        )
        .unwrap();
    assert_eq!(f.count(), 1);
    assert_eq!(f.finish().previous_count, 1);
    assert_eq!(f.owner.execution_state(), ThreadExecutionState::Running);
}

#[test]
fn nested_counts_and_zero_resume_never_issue_native_invocations() {
    let mut f = Fixture::new(false);
    assert_eq!(
        f.prepare(ThreadSuspendOperation::Resume),
        ThreadSuspendPhase::Local
    );
    assert!(f.owner.begin().is_err());
    assert_eq!(f.finish().count, 0);
    f.acquire(3);
    for (operation, previous, count) in [
        (ThreadSuspendOperation::Suspend, 1, 2),
        (ThreadSuspendOperation::Suspend, 2, 3),
        (ThreadSuspendOperation::Resume, 3, 2),
        (ThreadSuspendOperation::Resume, 2, 1),
    ] {
        assert_eq!(f.prepare(operation), ThreadSuspendPhase::Local);
        assert!(f.owner.begin().is_err());
        assert_eq!(
            f.finish(),
            ThreadSuspendCompletion {
                previous_count: previous,
                count,
                rejection: None
            }
        );
        assert_eq!(
            f.owner.execution_state(),
            ThreadExecutionState::Held { generation: 3 }
        );
    }
}

#[test]
fn dormant_zero_count_and_nested_counts_only_start_on_final_resume() {
    let mut f = Fixture::new(true);
    assert_eq!(
        f.prepare(ThreadSuspendOperation::Resume),
        ThreadSuspendPhase::Local
    );
    assert_eq!(f.finish().count, 0);
    assert_eq!(f.owner.execution_state(), ThreadExecutionState::Dormant);
    for _ in 0..2 {
        assert_eq!(
            f.prepare(ThreadSuspendOperation::Suspend),
            ThreadSuspendPhase::Local
        );
        assert!(f.owner.begin().is_err());
        f.finish();
    }
    assert_eq!(
        f.prepare(ThreadSuspendOperation::Resume),
        ThreadSuspendPhase::Local
    );
    f.finish();
    assert_eq!(
        f.prepare(ThreadSuspendOperation::Resume),
        ThreadSuspendPhase::Prepared
    );
    let invocation = f.owner.begin().unwrap();
    assert_eq!(invocation.action(), ThreadSuspendAction::Start { tcb: 32 });
    f.owner
        .record(
            invocation,
            ThreadSuspendOutcome::Acknowledged { generation: None },
        )
        .unwrap();
    f.finish();
    assert_eq!(f.owner.execution_state(), ThreadExecutionState::Running);
}

#[test]
fn initial_start_requires_exact_dormant_zero_count_and_no_reservation() {
    let mut f = Fixture::new(true);
    let mut wrong = f.binding;
    wrong.tcb += 1;
    assert_eq!(
        f.owner.prepare_initial_start(&mut f.pm, wrong, f.lifetime),
        Err(ThreadSuspendError::OwnerChanged)
    );
    f.prepare(ThreadSuspendOperation::Suspend);
    assert_eq!(
        f.owner
            .prepare_initial_start(&mut f.pm, f.binding, f.lifetime),
        Err(ThreadSuspendError::Busy)
    );
    f.finish();
    assert_eq!(
        f.owner
            .prepare_initial_start(&mut f.pm, f.binding, f.lifetime),
        Err(ThreadSuspendError::InconsistentState)
    );
    let mut f = Fixture::new(true);
    assert_eq!(
        f.owner
            .prepare_initial_start(&mut f.pm, f.binding, f.lifetime),
        Ok(ThreadSuspendPhase::Prepared)
    );
    assert_eq!(f.count(), 0);
    assert_eq!(f.owner.execution_state(), ThreadExecutionState::Dormant);
    assert!(f.pm.has_thread_suspend_control(f.lifetime.thread_id()));
    assert_eq!(
        f.owner.finish(&mut f.pm, f.binding, f.lifetime),
        Err(ThreadSuspendError::WrongPhase)
    );
    let invocation = f.owner.begin().unwrap();
    assert_eq!(
        invocation.action(),
        ThreadSuspendAction::Start { tcb: f.binding.tcb }
    );
    f.owner
        .record(
            invocation,
            ThreadSuspendOutcome::Acknowledged { generation: None },
        )
        .unwrap();
    assert_eq!(f.owner.execution_state(), ThreadExecutionState::Dormant);
    assert_eq!(
        f.finish(),
        ThreadSuspendCompletion {
            previous_count: 0,
            count: 0,
            rejection: None
        }
    );
    assert_eq!(f.owner.execution_state(), ThreadExecutionState::Running);
    assert_eq!(
        f.owner
            .prepare_initial_start(&mut f.pm, f.binding, f.lifetime),
        Err(ThreadSuspendError::InconsistentState)
    );
}

#[test]
fn initial_start_rejection_releases_exact_reservation_and_allows_retry() {
    let mut f = Fixture::new(true);
    f.owner
        .prepare_initial_start(&mut f.pm, f.binding, f.lifetime)
        .unwrap();
    let rejected = f.owner.begin().unwrap();
    let stale = duplicate(&rejected);
    f.owner
        .record(rejected, ThreadSuspendOutcome::Rejected { status: 2 })
        .unwrap();
    assert!(f.pm.has_thread_suspend_control(f.lifetime.thread_id()));
    assert_eq!(
        f.finish(),
        ThreadSuspendCompletion {
            previous_count: 0,
            count: 0,
            rejection: Some(2)
        }
    );
    assert_eq!(f.owner.execution_state(), ThreadExecutionState::Dormant);
    assert!(!f.pm.has_thread_suspend_control(f.lifetime.thread_id()));
    f.owner
        .prepare_initial_start(&mut f.pm, f.binding, f.lifetime)
        .unwrap();
    let retried = f.owner.begin().unwrap();
    assert_eq!(
        f.owner
            .record(
                stale,
                ThreadSuspendOutcome::Acknowledged { generation: None }
            )
            .unwrap_err()
            .0,
        ThreadSuspendError::WrongInvocation
    );
    assert_eq!(f.owner.phase(), ThreadSuspendPhase::Invoking);
    f.owner
        .record(
            retried,
            ThreadSuspendOutcome::Acknowledged { generation: None },
        )
        .unwrap();
    assert_eq!(f.finish().count, 0);
    assert_eq!(f.owner.execution_state(), ThreadExecutionState::Running);
}

#[test]
fn malformed_or_lost_initial_start_retains_zero_count_admission() {
    for outcome in [
        ThreadSuspendOutcome::Acknowledged {
            generation: Some(9),
        },
        ThreadSuspendOutcome::Rejected { status: 0 },
        ThreadSuspendOutcome::Indeterminate { status: 3 },
    ] {
        let mut f = Fixture::new(true);
        f.owner
            .prepare_initial_start(&mut f.pm, f.binding, f.lifetime)
            .unwrap();
        let invocation = f.owner.begin().unwrap();
        assert!(matches!(
            f.owner.record(invocation, outcome),
            Ok(ThreadSuspendPhase::Indeterminate(_))
        ));
        assert_eq!(f.count(), 0);
        assert_eq!(f.owner.execution_state(), ThreadExecutionState::Dormant);
        assert!(f.pm.has_thread_suspend_control(f.lifetime.thread_id()));
        assert!(!f.owner.can_retire());
        assert!(f.owner.finish(&mut f.pm, f.binding, f.lifetime).is_err());
        assert!(f.owner.begin().is_err());
        assert_eq!(
            f.owner
                .prepare_initial_start(&mut f.pm, f.binding, f.lifetime),
            Err(ThreadSuspendError::Busy)
        );
        assert_eq!(
            f.pm.terminate_process(f.lifetime.process_id(), 1),
            Err(nt_process::STATUS_DEVICE_BUSY)
        );
    }
    let mut f = Fixture::new(true);
    f.owner
        .prepare_initial_start(&mut f.pm, f.binding, f.lifetime)
        .unwrap();
    drop(f.owner.begin().unwrap());
    assert_eq!(f.owner.phase(), ThreadSuspendPhase::Invoking);
    assert!(f.pm.has_thread_suspend_control(f.lifetime.thread_id()));
    assert_eq!(f.count(), 0);
}

#[test]
fn external_pm_reservation_rejects_initial_start_without_publishing_owner_work() {
    let mut f = Fixture::new(true);
    let reserved =
        f.pm.prepare_thread_suspend_control(f.lifetime, ThreadSuspendOperation::Resume)
            .unwrap();
    assert_eq!(
        f.owner
            .prepare_initial_start(&mut f.pm, f.binding, f.lifetime),
        Err(ThreadSuspendError::Process(nt_process::STATUS_DEVICE_BUSY))
    );
    assert_eq!(f.owner.phase(), ThreadSuspendPhase::Idle);
    assert_eq!(f.owner.execution_state(), ThreadExecutionState::Dormant);
    assert_eq!(f.count(), 0);
    f.pm.cancel_thread_suspend_control(&reserved).unwrap();
    assert_eq!(
        f.owner
            .prepare_initial_start(&mut f.pm, f.binding, f.lifetime),
        Ok(ThreadSuspendPhase::Prepared)
    );
}

#[test]
fn failed_initial_start_local_commit_retains_start_ack_without_reinvocation() {
    let mut f = Fixture::new(true);
    f.owner
        .prepare_initial_start(&mut f.pm, f.binding, f.lifetime)
        .unwrap();
    let invocation = f.owner.begin().unwrap();
    f.owner
        .record(
            invocation,
            ThreadSuspendOutcome::Acknowledged { generation: None },
        )
        .unwrap();
    let mut foreign = Fixture::new(true);
    assert!(f
        .owner
        .finish(&mut foreign.pm, f.binding, f.lifetime)
        .is_err());
    assert_eq!(f.owner.phase(), ThreadSuspendPhase::Acknowledged);
    assert!(f.owner.begin().is_err());
    assert_eq!(f.owner.execution_state(), ThreadExecutionState::Dormant);
    assert!(f.pm.has_thread_suspend_control(f.lifetime.thread_id()));
    assert_eq!(f.finish().count, 0);
    assert_eq!(f.owner.execution_state(), ThreadExecutionState::Running);
}

#[test]
fn rejected_acquire_cancels_only_its_reservation_and_preserves_wait() {
    let mut f = Fixture::new(false);
    f.pm.set_thread_state(f.lifetime.thread_id(), ThreadState::Waiting)
        .unwrap();
    f.prepare(ThreadSuspendOperation::Suspend);
    let invocation = f.owner.begin().unwrap();
    f.owner
        .record(invocation, ThreadSuspendOutcome::Rejected { status: 5 })
        .unwrap();
    assert_eq!(
        f.finish(),
        ThreadSuspendCompletion {
            previous_count: 0,
            count: 0,
            rejection: Some(5)
        }
    );
    assert_eq!(f.owner.execution_state(), ThreadExecutionState::Running);
    assert_eq!(
        f.pm.thread(f.lifetime.thread_id()).unwrap().state,
        ThreadState::Waiting
    );
    assert!(!f.pm.has_thread_suspend_control(f.lifetime.thread_id()));
    f.acquire(6);
}

#[test]
fn rejected_release_and_start_preserve_original_physical_state() {
    for dormant in [false, true] {
        let mut f = Fixture::new(dormant);
        if dormant {
            f.prepare(ThreadSuspendOperation::Suspend);
            f.finish();
        } else {
            f.acquire(9);
        }
        let original = f.owner.execution_state();
        f.prepare(ThreadSuspendOperation::Resume);
        let invocation = f.owner.begin().unwrap();
        f.owner
            .record(invocation, ThreadSuspendOutcome::Rejected { status: 2 })
            .unwrap();
        assert_eq!(f.finish().count, 1);
        assert_eq!(f.owner.execution_state(), original);
    }
}

#[test]
fn lost_invocation_retains_busy_reservation_and_cannot_be_replayed() {
    let mut f = Fixture::new(false);
    f.prepare(ThreadSuspendOperation::Suspend);
    drop(f.owner.begin().unwrap());
    assert_eq!(f.owner.phase(), ThreadSuspendPhase::Invoking);
    assert!(f.owner.begin().is_err());
    assert_eq!(
        f.owner.finish(&mut f.pm, f.binding, f.lifetime),
        Err(ThreadSuspendError::WrongPhase)
    );
    assert_eq!(
        f.owner.prepare(
            &mut f.pm,
            f.binding,
            f.lifetime,
            ThreadSuspendOperation::Resume
        ),
        Err(ThreadSuspendError::Busy)
    );
    assert!(f.pm.has_thread_suspend_control(f.lifetime.thread_id()));
    assert_eq!(f.count(), 0);
    assert!(!f.owner.can_retire());
}

#[test]
fn malformed_and_unknown_acquire_receipts_remain_indeterminate() {
    for outcome in [
        ThreadSuspendOutcome::Acknowledged { generation: None },
        ThreadSuspendOutcome::Acknowledged {
            generation: Some(0),
        },
        ThreadSuspendOutcome::Rejected { status: 0 },
        ThreadSuspendOutcome::Indeterminate { status: 99 },
    ] {
        let mut f = Fixture::new(false);
        f.prepare(ThreadSuspendOperation::Suspend);
        let invocation = f.owner.begin().unwrap();
        assert!(matches!(
            f.owner.record(invocation, outcome),
            Ok(ThreadSuspendPhase::Indeterminate(_))
        ));
        assert!(f.owner.finish(&mut f.pm, f.binding, f.lifetime).is_err());
        assert!(f.owner.begin().is_err());
        assert!(f.pm.has_thread_suspend_control(f.lifetime.thread_id()));
        assert_eq!(f.count(), 0);
        assert!(!f.owner.can_retire());
    }
}

#[test]
fn generation_bearing_release_or_start_ack_is_not_accepted() {
    for dormant in [false, true] {
        let mut f = Fixture::new(dormant);
        if dormant {
            f.prepare(ThreadSuspendOperation::Suspend);
            f.finish();
        } else {
            f.acquire(9);
        }
        f.prepare(ThreadSuspendOperation::Resume);
        let invocation = f.owner.begin().unwrap();
        assert_eq!(
            f.owner
                .record(
                    invocation,
                    ThreadSuspendOutcome::Acknowledged {
                        generation: Some(9)
                    }
                )
                .unwrap(),
            ThreadSuspendPhase::Indeterminate(ThreadSuspendError::MalformedAcknowledgment)
        );
        assert_eq!(f.count(), 1);
        assert!(f.owner.finish(&mut f.pm, f.binding, f.lifetime).is_err());
    }
}

#[test]
fn wrong_binding_and_lifetime_rejected_before_reservation() {
    let mut f = Fixture::new(false);
    let other =
        f.pm.create_thread(f.binding.process.pid, 0x2000, 0, false)
            .unwrap();
    let other_lifetime = f.pm.thread_lifetime(other).unwrap();
    assert_eq!(
        f.owner.prepare(
            &mut f.pm,
            f.binding,
            other_lifetime,
            ThreadSuspendOperation::Suspend
        ),
        Err(ThreadSuspendError::OwnerChanged)
    );
    for selector in 0..5 {
        let mut binding = f.binding;
        match selector {
            0 => binding.tcb += 1,
            1 => binding.pi += 1,
            2 => binding.badge += 1,
            3 => binding.process.generation = ProcessGeneration::Hosted(8),
            _ => binding.tid += 1,
        }
        assert_eq!(
            f.owner.prepare(
                &mut f.pm,
                binding,
                f.lifetime,
                ThreadSuspendOperation::Suspend
            ),
            Err(ThreadSuspendError::OwnerChanged)
        );
    }
    assert!(!f.pm.has_thread_suspend_control(f.lifetime.thread_id()));
    assert_eq!(f.owner.phase(), ThreadSuspendPhase::Idle);
}

#[test]
fn accepted_receipt_survives_wrong_manager_and_binding_finish() {
    let mut f = Fixture::new(false);
    f.prepare(ThreadSuspendOperation::Suspend);
    let invocation = f.owner.begin().unwrap();
    f.owner
        .record(
            invocation,
            ThreadSuspendOutcome::Acknowledged {
                generation: Some(12),
            },
        )
        .unwrap();
    let mut other = Fixture::new(false);
    assert!(f
        .owner
        .finish(&mut other.pm, f.binding, f.lifetime)
        .is_err());
    let mut wrong = f.binding;
    wrong.tcb += 1;
    assert_eq!(
        f.owner.finish(&mut f.pm, wrong, f.lifetime),
        Err(ThreadSuspendError::OwnerChanged)
    );
    assert_eq!(f.owner.phase(), ThreadSuspendPhase::Acknowledged);
    assert!(f.owner.begin().is_err());
    assert_eq!(f.finish().count, 1);
    assert_eq!(
        f.owner.execution_state(),
        ThreadExecutionState::Held { generation: 12 }
    );
}

#[test]
fn duplicate_ack_and_old_revision_cannot_complete_another_attempt() {
    let mut f = Fixture::new(false);
    f.prepare(ThreadSuspendOperation::Suspend);
    let invocation = f.owner.begin().unwrap();
    let duplicate1 = duplicate(&invocation);
    let duplicate2 = duplicate(&invocation);
    f.owner
        .record(invocation, ThreadSuspendOutcome::Rejected { status: 1 })
        .unwrap();
    assert!(matches!(
        f.owner.record(
            duplicate1,
            ThreadSuspendOutcome::Acknowledged {
                generation: Some(9)
            }
        ),
        Err((ThreadSuspendError::WrongPhase, _))
    ));
    f.finish();
    f.prepare(ThreadSuspendOperation::Suspend);
    let current = f.owner.begin().unwrap();
    assert!(matches!(
        f.owner.record(
            duplicate2,
            ThreadSuspendOutcome::Acknowledged {
                generation: Some(9)
            }
        ),
        Err((ThreadSuspendError::WrongInvocation, _))
    ));
    assert_eq!(f.owner.phase(), ThreadSuspendPhase::Invoking);
    f.owner
        .record(
            current,
            ThreadSuspendOutcome::Acknowledged {
                generation: Some(10),
            },
        )
        .unwrap();
    f.finish();
}

#[test]
fn wait_completion_during_acquire_and_release_is_not_replaced_by_old_state() {
    for completion in [ThreadState::Waiting, ThreadState::Ready] {
        let mut f = Fixture::new(false);
        f.pm.set_thread_state(f.lifetime.thread_id(), ThreadState::Waiting)
            .unwrap();
        f.prepare(ThreadSuspendOperation::Suspend);
        let invocation = f.owner.begin().unwrap();
        f.pm.set_thread_state(f.lifetime.thread_id(), completion)
            .unwrap();
        f.owner
            .record(
                invocation,
                ThreadSuspendOutcome::Acknowledged {
                    generation: Some(11),
                },
            )
            .unwrap();
        f.finish();
        assert_eq!(
            f.pm.thread(f.lifetime.thread_id()).unwrap().state,
            ThreadState::Suspended
        );
        f.prepare(ThreadSuspendOperation::Resume);
        let invocation = f.owner.begin().unwrap();
        f.pm.set_thread_state(f.lifetime.thread_id(), completion)
            .unwrap();
        f.owner
            .record(
                invocation,
                ThreadSuspendOutcome::Acknowledged { generation: None },
            )
            .unwrap();
        f.finish();
        assert_eq!(
            f.pm.thread(f.lifetime.thread_id()).unwrap().state,
            completion
        );
    }
}

#[test]
fn mismatched_physical_count_never_reserves_or_guesses_a_hold() {
    let mut f = Fixture::new(false);
    f.pm.suspend_thread(f.lifetime.thread_id()).unwrap();
    assert_eq!(
        f.owner.prepare(
            &mut f.pm,
            f.binding,
            f.lifetime,
            ThreadSuspendOperation::Resume
        ),
        Err(ThreadSuspendError::InconsistentState)
    );
    assert!(!f.pm.has_thread_suspend_control(f.lifetime.thread_id()));
    assert_eq!(f.owner.execution_state(), ThreadExecutionState::Running);
}

#[test]
fn invalid_constructor_geometry_and_cross_thread_binding_are_refused() {
    let f = Fixture::new(false);
    for cap in [0, 1] {
        let mut binding = f.binding;
        binding.tcb = cap;
        assert!(matches!(
            ThreadSuspendOwner::running(binding, f.lifetime),
            Err(ThreadSuspendError::InvalidBinding)
        ));
    }
    let mut binding = f.binding;
    binding.process.pid += 1;
    assert!(matches!(
        ThreadSuspendOwner::running(binding, f.lifetime),
        Err(ThreadSuspendError::InvalidBinding)
    ));
}
