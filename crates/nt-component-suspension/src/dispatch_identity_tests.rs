use super::*;

type Lanes = ComponentSuspensionLanes<u64, u32>;

fn binding(id: u64) -> LaneBinding {
    LaneBinding {
        executor_id: 0x100 + id,
        receive_endpoint: 0x200 + id,
        reply_object: 0x300 + id,
    }
}

fn owner(id: u64) -> SuspensionOwner {
    SuspensionOwner {
        provider_domain: 3,
        provider_generation: 7,
        client_pi: 2,
        client_generation: 11,
        client_tid: 24,
        client_badge: 4,
        dispatch_id: id,
    }
}

fn identity(lanes: &Lanes, lane: LaneHandle) -> LaneDispatchIdentity {
    lanes.active_dispatch_identity(lane).unwrap().unwrap()
}

#[test]
fn idle_completion_and_next_job_have_distinct_authority() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(None));
    lanes.begin_dispatch(lane, reply).unwrap();
    let first = identity(&lanes, lane);
    assert_eq!(first.lane(), lane);
    assert_ne!(first.epoch(), 0);
    assert!(lanes.is_dispatch_identity_active(first));
    lanes.finish_dispatch(lane, reply).unwrap();
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(None));
    assert!(!lanes.is_dispatch_identity_active(first));
    lanes.begin_dispatch(lane, reply).unwrap();
    let second = identity(&lanes, lane);
    assert!(second.epoch() > first.epoch());
    assert!(!lanes.is_dispatch_identity_active(first));
    assert!(lanes.is_dispatch_identity_active(second));
}

#[test]
fn external_suspend_replace_resume_and_retirement_preserve_job() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let job = identity(&lanes, lane);
    lanes.suspend_running(lane, reply, 1).unwrap();
    assert_eq!(identity(&lanes, lane), job);
    lanes.resume_external(lane, reply, 1).unwrap();
    lanes.repark_external(lane, reply, 1).unwrap();
    assert_eq!(identity(&lanes, lane), job);
    lanes.resume_external(lane, reply, 1).unwrap();
    lanes.replace_external_running(lane, reply, 1, 2).unwrap();
    assert_eq!(identity(&lanes, lane), job);
    lanes.resume_external(lane, reply, 2).unwrap();
    lanes.retire_external_running(lane, reply, 2).unwrap();
    assert_eq!(identity(&lanes, lane), job);
    lanes.finish_dispatch(lane, reply).unwrap();
    assert!(!lanes.is_dispatch_identity_active(job));
}

#[test]
fn typed_rollback_and_rearm_preserve_job_until_completion() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    let key = SuspensionKey::provider_wait(1);
    let next = SuspensionKey::lpc_request(2);
    lanes.begin_dispatch(lane, reply).unwrap();
    let job = identity(&lanes, lane);
    lanes
        .admit_running(lane, reply, key, 1, owner(1), 9)
        .unwrap();
    assert_eq!(identity(&lanes, lane), job);
    assert_eq!(lanes.rollback_admission(lane, reply, key), Ok(9));
    assert_eq!(identity(&lanes, lane), job);
    lanes
        .admit_running(lane, reply, key, 2, owner(1), 10)
        .unwrap();
    lanes.select(key, 0).unwrap();
    lanes.begin_resume(lane, reply, key).unwrap();
    assert_eq!(identity(&lanes, lane), job);
    lanes
        .rearm_running(lane, reply, key, next, 3, owner(1), 11)
        .unwrap();
    assert_eq!(identity(&lanes, lane), job);
    lanes.select(next, 0).unwrap();
    lanes.begin_resume(lane, reply, next).unwrap();
    lanes
        .deliver_terminal_for_test(lane, reply, next, owner(1))
        .unwrap();
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(None));
    assert!(!lanes.is_dispatch_identity_active(job));
}

#[test]
fn transfers_between_external_and_typed_waits_preserve_job() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    let key = SuspensionKey::provider_wait(1);
    lanes.begin_dispatch(lane, reply).unwrap();
    let job = identity(&lanes, lane);
    lanes.suspend_running(lane, reply, 1).unwrap();
    lanes.resume_external(lane, reply, 1).unwrap();
    lanes
        .transfer_external_to_suspension_running(lane, reply, 1, key, 1, owner(1), 9)
        .unwrap();
    assert_eq!(identity(&lanes, lane), job);
    lanes.select(key, 0).unwrap();
    lanes.begin_resume(lane, reply, key).unwrap();
    lanes
        .complete_running_and_suspend_external(lane, reply, key, owner(1), 2)
        .unwrap();
    assert_eq!(identity(&lanes, lane), job);
    lanes.resume_external(lane, reply, 2).unwrap();
    lanes.complete_external(lane, reply, 2).unwrap();
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(None));
    assert!(!lanes.is_dispatch_identity_active(job));
}

#[test]
fn completing_nested_external_and_retiring_cancelled_wait_keep_outer_job() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    let key = SuspensionKey::provider_wait(1);
    lanes.begin_dispatch(lane, reply).unwrap();
    let job = identity(&lanes, lane);
    lanes.suspend_running(lane, reply, 1).unwrap();
    lanes.resume_external(lane, reply, 1).unwrap();
    lanes.suspend_running(lane, reply, 2).unwrap();
    lanes.resume_external(lane, reply, 2).unwrap();
    lanes.complete_external(lane, reply, 2).unwrap();
    assert_eq!(identity(&lanes, lane), job);
    lanes.resume_external(lane, reply, 1).unwrap();
    lanes
        .admit_running(lane, reply, key, 1, owner(1), 9)
        .unwrap();
    lanes.cancel(key, 1).unwrap();
    lanes.begin_resume(lane, reply, key).unwrap();
    lanes
        .deliver_terminal_for_test(lane, reply, key, owner(1))
        .unwrap();
    assert_eq!(identity(&lanes, lane), job);
    lanes.resume_external(lane, reply, 1).unwrap();
    lanes.complete_external(lane, reply, 1).unwrap();
    assert!(!lanes.is_dispatch_identity_active(job));
}

#[test]
fn retiring_cancelled_last_wait_invalidates_job() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    let key = SuspensionKey::provider_wait(1);
    lanes.begin_dispatch(lane, reply).unwrap();
    let job = identity(&lanes, lane);
    lanes
        .admit_running(lane, reply, key, 1, owner(1), 9)
        .unwrap();
    lanes.cancel(key, 1).unwrap();
    lanes.begin_resume(lane, reply, key).unwrap();
    lanes
        .deliver_terminal_for_test(lane, reply, key, owner(1))
        .unwrap();
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(None));
    assert!(!lanes.is_dispatch_identity_active(job));
}

#[test]
fn completing_typed_wait_preserves_retained_outer_callback_job() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    let key = SuspensionKey::provider_wait(1);
    lanes.begin_dispatch(lane, reply).unwrap();
    let job = identity(&lanes, lane);
    lanes.suspend_running(lane, reply, 1).unwrap();
    lanes.resume_external(lane, reply, 1).unwrap();
    lanes
        .admit_running(lane, reply, key, 1, owner(1), 9)
        .unwrap();
    lanes.select(key, 0).unwrap();
    lanes.begin_resume(lane, reply, key).unwrap();
    lanes
        .deliver_terminal_for_test(lane, reply, key, owner(1))
        .unwrap();
    assert_eq!(identity(&lanes, lane), job);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    lanes.resume_external(lane, reply, 1).unwrap();
    lanes.complete_external(lane, reply, 1).unwrap();
    assert!(!lanes.is_dispatch_identity_active(job));
}

#[test]
fn suspended_jobs_on_distinct_lanes_and_fresh_tables_cannot_alias() {
    let mut lanes = Lanes::new(2, 4);
    let first = lanes.allocate(binding(1)).unwrap();
    let second = lanes.allocate(binding(2)).unwrap();
    lanes
        .begin_dispatch(first, binding(1).reply_object)
        .unwrap();
    let first_job = identity(&lanes, first);
    lanes
        .suspend_running(first, binding(1).reply_object, 1)
        .unwrap();
    lanes
        .begin_dispatch(second, binding(2).reply_object)
        .unwrap();
    let second_job = identity(&lanes, second);
    assert_ne!(first_job, second_job);
    assert!(lanes.is_dispatch_identity_active(first_job));
    assert!(lanes.is_dispatch_identity_active(second_job));

    let mut fresh = Lanes::new(1, 4);
    let same_handle = fresh.allocate(binding(1)).unwrap();
    assert_eq!(same_handle, first);
    fresh
        .begin_dispatch(same_handle, binding(1).reply_object)
        .unwrap();
    let fresh_job = identity(&fresh, same_handle);
    assert_ne!(fresh_job, first_job);
    assert!(!fresh.is_dispatch_identity_active(first_job));
    assert!(!lanes.is_dispatch_identity_active(fresh_job));
}

#[test]
fn lane_retirement_and_generation_reuse_do_not_restore_old_job() {
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let job = identity(&lanes, lane);
    assert_eq!(lanes.release(lane, reply), Err(LaneError::Busy));
    assert_eq!(identity(&lanes, lane), job);
    lanes.suspend_running(lane, reply, 1).unwrap();
    assert_eq!(lanes.release(lane, reply), Err(LaneError::Busy));
    assert_eq!(identity(&lanes, lane), job);
    lanes.resume_external(lane, reply, 1).unwrap();
    lanes.complete_external(lane, reply, 1).unwrap();
    lanes.release(lane, reply).unwrap();
    assert!(!lanes.is_dispatch_identity_active(job));
    let replacement = lanes.allocate(binding(1)).unwrap();
    assert_eq!(replacement.index, lane.index);
    assert!(replacement.generation > lane.generation);
    lanes.begin_dispatch(replacement, reply).unwrap();
    assert_eq!(
        lanes.active_dispatch_identity(lane),
        Err(LaneError::StaleGeneration)
    );
    assert!(!lanes.is_dispatch_identity_active(job));
}

#[test]
fn exhausted_or_invalid_epoch_counters_fail_before_lane_mutation() {
    for initial in [0, u64::MAX] {
        let counter = AtomicU64::new(initial);
        let mut lanes = Lanes::new(1, 4);
        let lane = lanes.allocate(binding(1)).unwrap();
        assert_eq!(
            lanes.begin_dispatch_with_counter(lane, binding(1).reply_object, &counter),
            Err(LaneError::NoCapacity)
        );
        assert_eq!(counter.load(Ordering::Relaxed), initial);
        assert_eq!(lanes.phase(lane), Ok(LanePhase::Idle));
        assert_eq!(lanes.active_dispatch_identity(lane), Ok(None));
        assert_eq!(lanes.running(), None);
        assert_eq!(lanes.next_idle(), Some((lane, binding(1))));
        assert_eq!(lanes.release(lane, binding(1).reply_object), Ok(binding(1)));
    }
}

#[test]
fn last_epoch_is_issued_once_and_failed_preflight_never_consumes_it() {
    let counter = AtomicU64::new(u64::MAX - 1);
    let mut lanes = Lanes::new(1, 4);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    assert_eq!(
        lanes.begin_dispatch_with_counter(lane, reply + 1, &counter),
        Err(LaneError::WrongBinding)
    );
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX - 1);
    lanes
        .begin_dispatch_with_counter(lane, reply, &counter)
        .unwrap();
    let job = identity(&lanes, lane);
    assert_eq!(job.epoch(), u64::MAX - 1);
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    assert_eq!(
        lanes.begin_dispatch_with_counter(lane, reply, &counter),
        Err(LaneError::Busy)
    );
    assert_eq!(identity(&lanes, lane), job);
    lanes.finish_dispatch(lane, reply).unwrap();
    assert_eq!(
        lanes.begin_dispatch_with_counter(lane, reply, &counter),
        Err(LaneError::NoCapacity)
    );
    assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(None));
    assert_eq!(lanes.running(), None);
}
