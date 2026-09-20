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
