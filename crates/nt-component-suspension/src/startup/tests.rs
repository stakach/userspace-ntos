use super::*;
use crate::{ComponentIngress, IngressError, LaneBinding};

type Lanes = ComponentSuspensionLanes<(), (), ()>;

fn binding(index: u64) -> LaneBinding {
    LaneBinding {
        executor_id: 10 + index,
        receive_endpoint: 20 + index,
        reply_object: 30 + index,
    }
}

fn free(executor: u64, reply: u64) -> Result<ReplyBindingObservation, u8> {
    assert_eq!((executor, reply), (10, 30));
    Ok(ReplyBindingObservation::Free)
}

fn bound(executor: u64, reply: u64) -> Result<ReplyBindingObservation, u8> {
    assert_eq!((executor, reply), (10, 30));
    Ok(ReplyBindingObservation::BoundToTarget)
}

#[test]
fn staged_reserves_binding_and_capacity_without_dispatch_or_release() {
    let mut lanes = Lanes::new(1, 2);
    let staged = lanes.allocate_staged(binding(0)).unwrap();
    assert_eq!(lanes.phase(staged), Ok(LanePhase::Staged));
    assert_eq!(lanes.binding(staged), Ok(binding(0)));
    assert_eq!(lanes.next_idle(), None);
    assert!(!lanes.needs_idle_lane());
    assert_eq!(
        lanes.begin_dispatch(staged, 30),
        Err(LaneError::InvalidPhase)
    );
    assert_eq!(lanes.release(staged, 30), Err(LaneError::Busy));
    assert_eq!(
        lanes.allocate_staged(binding(0)),
        Err(LaneError::DuplicateBinding)
    );
    assert_eq!(lanes.allocate(binding(0)), Err(LaneError::DuplicateBinding));
    assert_eq!(
        lanes.allocate_staged(binding(1)),
        Err(LaneError::NoCapacity)
    );
    for duplicate in [
        LaneBinding {
            executor_id: 10,
            ..binding(1)
        },
        LaneBinding {
            receive_endpoint: 20,
            ..binding(1)
        },
        LaneBinding {
            reply_object: 30,
            ..binding(1)
        },
    ] {
        assert_eq!(
            lanes.allocate_staged(duplicate),
            Err(LaneError::DuplicateBinding)
        );
    }
    let mut ingress = ComponentIngress::<()>::new(20, 30).unwrap();
    assert_eq!(
        lanes.begin_ingress_receive(&mut ingress).err(),
        Some(IngressError::ReplyInUse)
    );
}

#[test]
fn begin_refuses_busy_wrong_reply_and_non_staged_without_querying() {
    let mut lanes = Lanes::new(2, 2);
    let staged = lanes.allocate_staged(binding(0)).unwrap();
    let other = lanes.allocate(binding(1)).unwrap();
    assert_eq!(
        lanes.begin_startup(staged, 99, |_, _| -> Result<_, u8> {
            panic!("wrong Reply query")
        }),
        Err(StartupError::Lane(LaneError::WrongBinding))
    );
    assert_eq!(
        lanes.begin_startup(other, 31, |_, _| -> Result<_, u8> {
            panic!("idle lane query")
        }),
        Err(StartupError::Lane(LaneError::InvalidPhase))
    );
    lanes.begin_dispatch(other, 31).unwrap();
    assert_eq!(
        lanes.begin_startup(staged, 30, |_, _| -> Result<_, u8> {
            panic!("busy lane query")
        }),
        Err(StartupError::Lane(LaneError::Busy))
    );
    assert_eq!(lanes.phase(staged), Ok(LanePhase::Staged));
    assert_eq!(lanes.running(), Some(other));
}

#[test]
fn begin_query_errors_and_nonfree_observations_preserve_staging() {
    let mut lanes = Lanes::new(1, 2);
    let staged = lanes.allocate_staged(binding(0)).unwrap();
    assert_eq!(
        lanes.begin_startup(staged, 30, |_, _| Err(7u8)),
        Err(StartupError::Query(7))
    );
    for observation in [
        ReplyBindingObservation::Offered,
        ReplyBindingObservation::BoundToTarget,
        ReplyBindingObservation::BoundElsewhere,
    ] {
        assert_eq!(
            lanes.begin_startup(staged, 30, |executor, reply| {
                assert_eq!((executor, reply), (10, 30));
                Ok::<_, u8>(observation)
            }),
            Err(StartupError::BindingMismatch)
        );
        assert_eq!(lanes.phase(staged), Ok(LanePhase::Staged));
        assert_eq!(lanes.running(), None);
        assert_eq!(lanes.binding(staged), Ok(binding(0)));
    }
}

#[test]
fn startup_fences_other_dispatch_resume_and_ingress_until_completion() {
    let mut lanes = Lanes::new(3, 2);
    let staged = lanes.allocate_staged(binding(0)).unwrap();
    let other = lanes.allocate(binding(1)).unwrap();
    lanes.begin_dispatch(other, 31).unwrap();
    lanes.suspend_running(other, 31, 7).unwrap();
    lanes.begin_startup(staged, 30, free).unwrap();
    assert_eq!(lanes.phase(staged), Ok(LanePhase::Starting));
    assert_eq!(lanes.running(), Some(staged));
    assert!(lanes.execution_busy());
    assert_eq!(lanes.next_idle(), None);
    assert!(!lanes.needs_idle_lane());
    assert_eq!(lanes.begin_dispatch(other, 31), Err(LaneError::Busy));
    assert_eq!(lanes.resume_external(other, 31, 7), Err(LaneError::Busy));
    assert!(lanes.finish_dispatch(staged, 30).is_err());
    assert_eq!(lanes.release(staged, 30), Err(LaneError::Busy));
    let mut ingress = ComponentIngress::<()>::new(20, 50).unwrap();
    assert_eq!(
        lanes.begin_ingress_receive(&mut ingress).err(),
        Some(IngressError::ExecutionBusy)
    );
    assert_eq!(lanes.running(), Some(staged));
    lanes.complete_startup(staged, 30, bound).unwrap();
    lanes.resume_external(other, 31, 7).unwrap();
}

#[test]
fn completion_rejects_wrong_identity_and_bad_evidence_without_releasing_fence() {
    let mut lanes = Lanes::new(2, 2);
    let staged = lanes.allocate_staged(binding(0)).unwrap();
    let other = lanes.allocate_staged(binding(1)).unwrap();
    assert_eq!(
        lanes.complete_startup(staged, 30, bound),
        Err(StartupError::Lane(LaneError::InvalidPhase))
    );
    lanes.begin_startup(staged, 30, free).unwrap();
    assert_eq!(
        lanes.complete_startup(staged, 31, |_, _| -> Result<_, u8> {
            panic!("wrong Reply query")
        }),
        Err(StartupError::Lane(LaneError::WrongBinding))
    );
    assert_eq!(
        lanes.complete_startup(other, 31, |_, _| -> Result<_, u8> {
            panic!("wrong lane query")
        }),
        Err(StartupError::Lane(LaneError::InvalidPhase))
    );
    assert_eq!(
        lanes.complete_startup(staged, 30, |_, _| Err(8u8)),
        Err(StartupError::Query(8))
    );
    for observation in [
        ReplyBindingObservation::Free,
        ReplyBindingObservation::Offered,
        ReplyBindingObservation::BoundElsewhere,
    ] {
        assert_eq!(
            lanes.complete_startup(staged, 30, |_, _| Ok::<_, u8>(observation)),
            Err(StartupError::BindingMismatch)
        );
        assert_eq!(lanes.running(), Some(staged));
        assert_eq!(lanes.phase(staged), Ok(LanePhase::Starting));
        assert_eq!(lanes.binding(staged), Ok(binding(0)));
    }
}

#[test]
fn successful_startup_publishes_idle_exactly_once_then_normal_dispatch() {
    let mut lanes = Lanes::new(1, 2);
    let staged = lanes.allocate_staged(binding(0)).unwrap();
    lanes.begin_startup(staged, 30, free).unwrap();
    lanes.complete_startup(staged, 30, bound).unwrap();
    assert_eq!(lanes.phase(staged), Ok(LanePhase::Idle));
    assert_eq!(lanes.running(), None);
    assert_eq!(lanes.next_idle(), Some((staged, binding(0))));
    assert_eq!(lanes.active_dispatch_identity(staged), Ok(None));
    assert_eq!(
        lanes.complete_startup(staged, 30, |_, _| -> Result<_, u8> {
            panic!("duplicate completion query")
        }),
        Err(StartupError::Lane(LaneError::InvalidPhase))
    );
    lanes.begin_dispatch(staged, 30).unwrap();
    assert!(lanes.active_dispatch_identity(staged).unwrap().is_some());
    lanes.finish_dispatch(staged, 30).unwrap();
    assert_eq!(lanes.release(staged, 30), Ok(binding(0)));
}

#[test]
fn reused_slot_does_not_accept_old_startup_handle() {
    let mut lanes = Lanes::new(1, 2);
    let old = lanes.allocate(binding(0)).unwrap();
    lanes.release(old, 30).unwrap();
    let staged = lanes.allocate_staged(binding(0)).unwrap();
    assert_ne!(old, staged);
    assert_eq!(
        lanes.begin_startup(old, 30, free),
        Err(StartupError::Lane(LaneError::StaleGeneration))
    );
    lanes.begin_startup(staged, 30, free).unwrap();
    assert_eq!(
        lanes.complete_startup(old, 30, bound),
        Err(StartupError::Lane(LaneError::StaleGeneration))
    );
    assert_eq!(lanes.phase(staged), Ok(LanePhase::Starting));
    assert_eq!(lanes.running(), Some(staged));
}

#[test]
fn stopped_staged_and_starting_workers_remain_fenced_and_owned() {
    for started in [false, true] {
        let mut lanes = Lanes::new(2, 2);
        let lane = lanes.allocate_staged(binding(0)).unwrap();
        let other = lanes.allocate(binding(1)).unwrap();
        if started {
            lanes.begin_startup(lane, 30, free).unwrap();
        }
        lanes
            .stop_startup(
                lane,
                30,
                |executor| {
                    assert_eq!(executor, 10);
                    Ok::<_, u8>(())
                },
                free,
            )
            .unwrap();
        assert_eq!(lanes.phase(lane), Ok(LanePhase::StartupStopped));
        assert_eq!(lanes.binding(lane), Ok(binding(0)));
        assert_eq!(lanes.running(), Some(lane));
        assert!(lanes.execution_busy());
        assert_eq!(lanes.next_idle(), None);
        assert!(!lanes.needs_idle_lane());
        assert_eq!(lanes.release(lane, 30), Err(LaneError::Busy));
        assert_eq!(lanes.begin_dispatch(other, 31), Err(LaneError::Busy));
        assert!(lanes.finish_dispatch(lane, 30).is_err());
        assert!(lanes.complete_startup(lane, 30, bound).is_err());
        assert_eq!(
            lanes.verify_startup_stopped::<u8, u8>(lane, 30, |_, _| panic!("already verified")),
            Err(StartupStopError::Lane(LaneError::InvalidPhase))
        );
    }
}

#[test]
fn suspension_error_locks_stop_without_query_or_replay() {
    let mut lanes = Lanes::new(1, 2);
    let lane = lanes.allocate_staged(binding(0)).unwrap();
    lanes.begin_startup(lane, 30, free).unwrap();
    assert_eq!(
        lanes.stop_startup(
            lane,
            30,
            |executor| {
                assert_eq!(executor, 10);
                Err(7u8)
            },
            |_, _| -> Result<_, u8> { panic!("unacknowledged stop query") }
        ),
        Err(StartupStopError::Suspend(7))
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::StartupStopping));
    assert_eq!(lanes.running(), Some(lane));
    assert_eq!(
        lanes.stop_startup(
            lane,
            30,
            |_| -> Result<(), u8> { panic!("stop replay") },
            free
        ),
        Err(StartupStopError::Lane(LaneError::InvalidPhase))
    );
    assert_eq!(
        lanes.verify_startup_stopped::<u8, u8>(lane, 30, |_, _| panic!("unacknowledged verify")),
        Err(StartupStopError::Lane(LaneError::InvalidPhase))
    );
    assert_eq!(lanes.release(lane, 30), Err(LaneError::Busy));
}

#[test]
fn acknowledged_stop_retries_only_observation_until_exact_reply_is_free() {
    let mut lanes = Lanes::new(1, 2);
    let lane = lanes.allocate_staged(binding(0)).unwrap();
    assert_eq!(
        lanes.stop_startup(
            lane,
            30,
            |_| Ok::<_, u8>(()),
            |executor, reply| {
                assert_eq!((executor, reply), (10, 30));
                Err(8u8)
            }
        ),
        Err(StartupStopError::Query(8))
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::StartupStopAcknowledged));
    assert_eq!(
        lanes.stop_startup(
            lane,
            30,
            |_| -> Result<(), u8> { panic!("acknowledged suspend replay") },
            free
        ),
        Err(StartupStopError::Lane(LaneError::InvalidPhase))
    );
    for observation in [
        ReplyBindingObservation::Offered,
        ReplyBindingObservation::BoundToTarget,
        ReplyBindingObservation::BoundElsewhere,
    ] {
        assert_eq!(
            lanes.verify_startup_stopped::<u8, u8>(lane, 30, |executor, reply| {
                assert_eq!((executor, reply), (10, 30));
                Ok(observation)
            }),
            Err(StartupStopError::ReplyNotFree)
        );
        assert_eq!(lanes.phase(lane), Ok(LanePhase::StartupStopAcknowledged));
        assert_eq!(lanes.running(), Some(lane));
    }
    lanes
        .verify_startup_stopped::<u8, u8>(lane, 30, free)
        .unwrap();
    assert_eq!(lanes.phase(lane), Ok(LanePhase::StartupStopped));
    assert!(lanes.execution_busy());
}

#[test]
fn stop_rejects_wrong_binding_stale_handle_and_other_execution_without_effects() {
    let mut lanes = Lanes::new(2, 2);
    let old = lanes.allocate(binding(0)).unwrap();
    lanes.release(old, 30).unwrap();
    let lane = lanes.allocate_staged(binding(0)).unwrap();
    let other = lanes.allocate(binding(1)).unwrap();
    let suspend = |_| -> Result<(), u8> { panic!("invalid stop side effect") };
    let query = |_, _| -> Result<ReplyBindingObservation, u8> { panic!("invalid stop query") };
    assert_eq!(
        lanes.stop_startup(old, 30, suspend, query),
        Err(StartupStopError::Lane(LaneError::StaleGeneration))
    );
    assert_eq!(
        lanes.stop_startup(lane, 99, suspend, query),
        Err(StartupStopError::Lane(LaneError::WrongBinding))
    );
    lanes.begin_dispatch(other, 31).unwrap();
    assert_eq!(
        lanes.stop_startup(lane, 30, suspend, query),
        Err(StartupStopError::Lane(LaneError::Busy))
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Staged));
    assert_eq!(lanes.running(), Some(other));
    lanes.finish_dispatch(other, 31).unwrap();
    assert_eq!(
        lanes.stop_startup(lane, 30, |_| Ok::<_, u8>(()), bound),
        Err(StartupStopError::ReplyNotFree)
    );
    assert_eq!(
        lanes.verify_startup_stopped::<u8, u8>(old, 30, query),
        Err(StartupStopError::Lane(LaneError::StaleGeneration))
    );
    assert_eq!(
        lanes.verify_startup_stopped::<u8, u8>(lane, 99, query),
        Err(StartupStopError::Lane(LaneError::WrongBinding))
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::StartupStopAcknowledged));
    assert_eq!(lanes.running(), Some(lane));
}

#[test]
fn scheduler_detach_ack_retains_stopped_worker_fence_and_resources() {
    let mut lanes = Lanes::new(2, 2);
    let lane = lanes.allocate_staged(binding(0)).unwrap();
    let other = lanes.allocate(binding(1)).unwrap();
    lanes
        .stop_startup(lane, 30, |_| Ok::<_, u8>(()), free)
        .unwrap();
    lanes
        .detach_startup_scheduler(lane, 30, |executor| {
            assert_eq!(executor, 10);
            Ok::<_, u8>(())
        })
        .unwrap();
    assert_eq!(lanes.phase(lane), Ok(LanePhase::StartupDetached));
    assert_eq!(lanes.binding(lane), Ok(binding(0)));
    assert_eq!(lanes.running(), Some(lane));
    assert!(lanes.execution_busy());
    assert_eq!(lanes.next_idle(), None);
    assert_eq!(lanes.release(lane, 30), Err(LaneError::Busy));
    assert_eq!(lanes.begin_dispatch(other, 31), Err(LaneError::Busy));
    assert!(lanes.complete_startup(lane, 30, bound).is_err());
    assert!(lanes.finish_dispatch(lane, 30).is_err());
    assert_eq!(
        lanes.detach_startup_scheduler(lane, 30, |_| -> Result<(), u8> {
            panic!("duplicate detach")
        }),
        Err(StartupDetachError::Lane(LaneError::InvalidPhase))
    );
}

#[test]
fn detach_refuses_each_unverified_startup_phase_before_invocation() {
    let refused = |_| -> Result<(), u8> { panic!("unverified detach") };
    let mut lanes = Lanes::new(2, 2);
    let lane = lanes.allocate_staged(binding(0)).unwrap();
    let idle = lanes.allocate(binding(1)).unwrap();
    assert_eq!(
        lanes.detach_startup_scheduler(idle, 31, refused),
        Err(StartupDetachError::Lane(LaneError::InvalidPhase))
    );
    assert_eq!(
        lanes.detach_startup_scheduler(lane, 30, refused),
        Err(StartupDetachError::Lane(LaneError::InvalidPhase))
    );
    lanes.begin_startup(lane, 30, free).unwrap();
    assert_eq!(
        lanes.detach_startup_scheduler(lane, 30, refused),
        Err(StartupDetachError::Lane(LaneError::InvalidPhase))
    );
    assert!(lanes
        .stop_startup(lane, 30, |_| Ok::<_, u8>(()), bound)
        .is_err());
    assert_eq!(lanes.phase(lane), Ok(LanePhase::StartupStopAcknowledged));
    assert_eq!(
        lanes.detach_startup_scheduler(lane, 30, refused),
        Err(StartupDetachError::Lane(LaneError::InvalidPhase))
    );
    let mut failed = Lanes::new(1, 2);
    let failed_lane = failed.allocate_staged(binding(0)).unwrap();
    assert!(failed
        .stop_startup(failed_lane, 30, |_| Err(7u8), free)
        .is_err());
    assert_eq!(failed.phase(failed_lane), Ok(LanePhase::StartupStopping));
    assert_eq!(
        failed.detach_startup_scheduler(failed_lane, 30, refused),
        Err(StartupDetachError::Lane(LaneError::InvalidPhase))
    );
}

#[test]
fn scheduler_detach_error_locks_entered_operation_without_replay() {
    let mut lanes = Lanes::new(1, 2);
    let lane = lanes.allocate_staged(binding(0)).unwrap();
    lanes
        .stop_startup(lane, 30, |_| Ok::<_, u8>(()), free)
        .unwrap();
    assert_eq!(
        lanes.detach_startup_scheduler(lane, 30, |executor| {
            assert_eq!(executor, 10);
            Err(9u8)
        }),
        Err(StartupDetachError::Invoke(9))
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::StartupDetaching));
    assert_eq!(lanes.running(), Some(lane));
    assert_eq!(
        lanes.detach_startup_scheduler(lane, 30, |_| -> Result<(), u8> {
            panic!("ambiguous replay")
        }),
        Err(StartupDetachError::Lane(LaneError::InvalidPhase))
    );
    assert_eq!(lanes.release(lane, 30), Err(LaneError::Busy));
    assert!(lanes
        .verify_startup_stopped::<u8, u8>(lane, 30, free)
        .is_err());
}

#[test]
fn detach_rejects_stale_and_wrong_reply_without_changing_verified_owner() {
    let mut lanes = Lanes::new(1, 2);
    let old = lanes.allocate(binding(0)).unwrap();
    lanes.release(old, 30).unwrap();
    let lane = lanes.allocate_staged(binding(0)).unwrap();
    lanes
        .stop_startup(lane, 30, |_| Ok::<_, u8>(()), free)
        .unwrap();
    let refused = |_| -> Result<(), u8> { panic!("foreign detach") };
    assert_eq!(
        lanes.detach_startup_scheduler(old, 30, refused),
        Err(StartupDetachError::Lane(LaneError::StaleGeneration))
    );
    assert_eq!(
        lanes.detach_startup_scheduler(lane, 99, refused),
        Err(StartupDetachError::Lane(LaneError::WrongBinding))
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::StartupStopped));
    assert_eq!(lanes.running(), Some(lane));
}

fn detached_lane() -> (Lanes, LaneHandle) {
    let mut lanes = Lanes::new(2, 2);
    let lane = lanes.allocate_staged(binding(0)).unwrap();
    lanes
        .stop_startup(lane, 30, |_| Ok::<_, u8>(()), free)
        .unwrap();
    lanes
        .detach_startup_scheduler(lane, 30, |_| Ok::<_, u8>(()))
        .unwrap();
    (lanes, lane)
}

#[test]
fn scheduler_delete_ack_keeps_lane_fence_binding_and_allocation() {
    let (mut lanes, lane) = detached_lane();
    let other = lanes.allocate(binding(1)).unwrap();
    lanes
        .delete_startup_scheduler(lane, 30, |executor| {
            assert_eq!(executor, 10);
            Ok::<_, u8>(())
        })
        .unwrap();
    assert_eq!(lanes.phase(lane), Ok(LanePhase::StartupSchedulerDeleted));
    assert_eq!(lanes.binding(lane), Ok(binding(0)));
    assert_eq!(lanes.running(), Some(lane));
    assert_eq!(lanes.len(), 2);
    assert!(lanes.execution_busy());
    assert_eq!(lanes.release(lane, 30), Err(LaneError::Busy));
    assert_eq!(lanes.begin_dispatch(other, 31), Err(LaneError::Busy));
    assert_eq!(lanes.next_idle(), None);
    assert!(!lanes.needs_idle_lane());
    assert!(lanes.complete_startup(lane, 30, bound).is_err());
    assert!(lanes.finish_dispatch(lane, 30).is_err());
    assert_eq!(
        lanes.delete_startup_scheduler(lane, 30, |_| -> Result<(), u8> {
            panic!("duplicate delete")
        }),
        Err(StartupDeleteError::Lane(LaneError::InvalidPhase))
    );
}

#[test]
fn scheduler_delete_error_retains_entered_authority_without_replay() {
    let (mut lanes, lane) = detached_lane();
    assert_eq!(
        lanes.delete_startup_scheduler(lane, 30, |executor| {
            assert_eq!(executor, 10);
            Err(11u8)
        }),
        Err(StartupDeleteError::Invoke(11))
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::StartupSchedulerDeleting));
    assert_eq!(lanes.running(), Some(lane));
    assert_eq!(
        lanes.delete_startup_scheduler(lane, 30, |_| -> Result<(), u8> {
            panic!("ambiguous delete replay")
        }),
        Err(StartupDeleteError::Lane(LaneError::InvalidPhase))
    );
    assert!(lanes
        .detach_startup_scheduler(lane, 30, |_| Ok::<_, u8>(()))
        .is_err());
    assert_eq!(lanes.release(lane, 30), Err(LaneError::Busy));
}

#[test]
fn scheduler_delete_rejects_missing_detach_ack_before_effects() {
    let refused = |_| -> Result<(), u8> { panic!("unacknowledged detach delete") };
    let mut lanes = Lanes::new(1, 2);
    let lane = lanes.allocate_staged(binding(0)).unwrap();
    assert_eq!(
        lanes.delete_startup_scheduler(lane, 30, refused),
        Err(StartupDeleteError::Lane(LaneError::InvalidPhase))
    );
    lanes.begin_startup(lane, 30, free).unwrap();
    assert_eq!(
        lanes.delete_startup_scheduler(lane, 30, refused),
        Err(StartupDeleteError::Lane(LaneError::InvalidPhase))
    );
    assert!(lanes
        .stop_startup(lane, 30, |_| Ok::<_, u8>(()), bound)
        .is_err());
    assert_eq!(
        lanes.delete_startup_scheduler(lane, 30, refused),
        Err(StartupDeleteError::Lane(LaneError::InvalidPhase))
    );
    lanes
        .verify_startup_stopped::<u8, u8>(lane, 30, free)
        .unwrap();
    assert_eq!(
        lanes.delete_startup_scheduler(lane, 30, refused),
        Err(StartupDeleteError::Lane(LaneError::InvalidPhase))
    );
    assert!(lanes
        .detach_startup_scheduler(lane, 30, |_| Err(12u8))
        .is_err());
    assert_eq!(
        lanes.delete_startup_scheduler(lane, 30, refused),
        Err(StartupDeleteError::Lane(LaneError::InvalidPhase))
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::StartupDetaching));
}

#[test]
fn scheduler_delete_rejects_wrong_reply_and_stale_lane_without_effects() {
    let mut lanes = Lanes::new(1, 2);
    let old = lanes.allocate(binding(0)).unwrap();
    lanes.release(old, 30).unwrap();
    let lane = lanes.allocate_staged(binding(0)).unwrap();
    lanes
        .stop_startup(lane, 30, |_| Ok::<_, u8>(()), free)
        .unwrap();
    lanes
        .detach_startup_scheduler(lane, 30, |_| Ok::<_, u8>(()))
        .unwrap();
    let refused = |_| -> Result<(), u8> { panic!("foreign scheduler delete") };
    assert_eq!(
        lanes.delete_startup_scheduler(old, 30, refused),
        Err(StartupDeleteError::Lane(LaneError::StaleGeneration))
    );
    assert_eq!(
        lanes.delete_startup_scheduler(lane, 99, refused),
        Err(StartupDeleteError::Lane(LaneError::WrongBinding))
    );
    assert_eq!(lanes.phase(lane), Ok(LanePhase::StartupDetached));
    assert_eq!(lanes.running(), Some(lane));
}
