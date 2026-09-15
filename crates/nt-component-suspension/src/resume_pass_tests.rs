use super::*;

type Lanes = ComponentSuspensionLanes<u64, u32, ()>;

fn add(lanes: &mut Lanes, id: u64, sequence: u64, kernel: bool) -> LaneHandle {
    let binding = LaneBinding {
        executor_id: 100 + id,
        receive_endpoint: 200 + id,
        reply_object: 300 + id,
    };
    let lane = lanes.allocate(binding).unwrap();
    lanes.begin_dispatch(lane, binding.reply_object).unwrap();
    let owner = SuspensionOwner {
        provider_domain: 1,
        provider_generation: 1,
        dispatch_id: if kernel {
            lanes
                .active_dispatch_identity(lane)
                .unwrap()
                .unwrap()
                .epoch()
        } else {
            id
        },
        caller: if kernel {
            SuspensionCaller::Kernel { lane }
        } else {
            SuspensionCaller::Hosted(SuspensionHostedClient {
                client_pi: 1,
                client_generation: 1,
                client_tid: id,
                client_badge: id,
            })
        },
    };
    let key = SuspensionKey::provider_wait(id);
    lanes
        .admit_running(lane, binding.reply_object, key, sequence, owner, id)
        .unwrap();
    lanes.select(key, id as u32).unwrap();
    lane
}

#[test]
fn one_pass_orders_both_caller_kinds_and_does_not_retry_unclaimed_candidates() {
    let mut lanes = Lanes::new(3, 2);
    let later = add(&mut lanes, 1, 30, false);
    let first = add(&mut lanes, 2, 10, true);
    let middle = add(&mut lanes, 3, 20, false);
    let mut pass = lanes.resume_pass();
    for expected in [first, middle, later] {
        assert_eq!(
            lanes
                .next_resumable_in_pass(&mut pass, |_| true)
                .unwrap()
                .lane,
            expected
        );
    }
    assert!(lanes
        .next_resumable_in_pass(&mut pass, |_| panic!("exhausted"))
        .is_none());
    assert_eq!(lanes.total_suspensions(), 3);
    assert_eq!(lanes.next_resumable().unwrap().lane, first);
}

#[test]
fn refused_oldest_is_visited_once_without_starving_hosted_siblings() {
    let mut lanes = Lanes::new(3, 2);
    let kernel = add(&mut lanes, 1, 1, true);
    let hosted = add(&mut lanes, 2, 2, false);
    let later = add(&mut lanes, 3, 3, true);
    let mut pass = lanes.resume_pass();
    let mut visited = alloc::vec::Vec::new();
    assert_eq!(
        lanes
            .next_resumable_in_pass(&mut pass, |frame| {
                visited.push(frame.continuation);
                frame.continuation != 1
            })
            .unwrap()
            .lane,
        hosted
    );
    assert_eq!(visited, [1, 2]);
    assert_eq!(
        lanes
            .next_resumable_in_pass(&mut pass, |frame| {
                visited.push(frame.continuation);
                true
            })
            .unwrap()
            .lane,
        later
    );
    assert_eq!(visited, [1, 2, 3]);
    assert_eq!(lanes.phase(kernel), Ok(LanePhase::Suspended));
}

#[test]
fn fresh_immediately_selected_repark_waits_for_next_pass() {
    let mut lanes = Lanes::new(2, 2);
    let first = add(&mut lanes, 1, 1, true);
    let sibling = add(&mut lanes, 2, 2, false);
    let mut pass = lanes.resume_pass();
    let selected = lanes.next_resumable_in_pass(&mut pass, |_| true).unwrap();
    let owner = lanes.top(first).unwrap().unwrap().owner;
    lanes
        .begin_resume(
            first,
            selected.binding.reply_object,
            selected.suspension.key,
        )
        .unwrap();
    let next = SuspensionKey::provider_wait(3);
    lanes
        .rearm_running(
            first,
            selected.binding.reply_object,
            selected.suspension.key,
            next,
            3,
            owner,
            3,
        )
        .unwrap();
    lanes.select(next, 0).unwrap();
    assert_eq!(
        lanes
            .next_resumable_in_pass(&mut pass, |_| true)
            .unwrap()
            .lane,
        sibling
    );
    assert!(lanes.next_resumable_in_pass(&mut pass, |_| true).is_none());
    let mut next_pass = lanes.resume_pass();
    assert_eq!(
        lanes
            .next_resumable_in_pass(&mut next_pass, |_| true)
            .unwrap()
            .lane,
        sibling
    );
    assert_eq!(
        lanes
            .next_resumable_in_pass(&mut next_pass, |_| true)
            .unwrap()
            .suspension
            .key,
        next
    );
}

#[test]
fn later_admission_is_excluded_even_before_first_visit() {
    let mut lanes = Lanes::new(2, 2);
    let first = add(&mut lanes, 1, 1, false);
    let mut pass = lanes.resume_pass();
    add(&mut lanes, 2, 2, true);
    assert_eq!(
        lanes
            .next_resumable_in_pass(&mut pass, |_| true)
            .unwrap()
            .lane,
        first
    );
    assert!(lanes.next_resumable_in_pass(&mut pass, |_| true).is_none());
}

#[test]
fn tied_sequences_are_stable_and_cancellation_is_still_executable() {
    let mut lanes = Lanes::new(2, 2);
    let first = add(&mut lanes, 1, 10, true);
    let second = add(&mut lanes, 2, 10, false);
    lanes
        .cancel(SuspensionKey::provider_wait(2), 0xc000_0120)
        .unwrap();
    let mut pass = lanes.resume_pass();
    assert_eq!(
        lanes
            .next_resumable_in_pass(&mut pass, |_| true)
            .unwrap()
            .lane,
        first
    );
    let cancelled = lanes.next_resumable_in_pass(&mut pass, |_| true).unwrap();
    assert_eq!(cancelled.lane, second);
    assert!(cancelled.suspension.cancelled);
    assert_eq!(cancelled.suspension.completion, 0xc000_0120);
}

#[test]
fn physical_execution_exclusion_does_not_advance_the_pass() {
    let mut lanes = Lanes::new(2, 2);
    let selected = add(&mut lanes, 1, 1, true);
    let binding = LaneBinding {
        executor_id: 102,
        receive_endpoint: 202,
        reply_object: 302,
    };
    let running = lanes.allocate(binding).unwrap();
    let mut pass = lanes.resume_pass();
    lanes.begin_dispatch(running, binding.reply_object).unwrap();
    assert!(lanes
        .next_resumable_in_pass(&mut pass, |_| panic!("physical lane busy"))
        .is_none());
    lanes
        .finish_dispatch(running, binding.reply_object)
        .unwrap();
    assert_eq!(
        lanes
            .next_resumable_in_pass(&mut pass, |_| true)
            .unwrap()
            .lane,
        selected
    );
}

#[test]
fn cancellation_after_enumeration_is_authoritative_at_claim() {
    let mut lanes = Lanes::new(1, 2);
    let lane = add(&mut lanes, 1, 1, true);
    let mut pass = lanes.resume_pass();
    let candidate = lanes.next_resumable_in_pass(&mut pass, |_| true).unwrap();
    lanes.cancel(candidate.suspension.key, 0xc000_0120).unwrap();
    let claimed = lanes
        .begin_resume(
            lane,
            candidate.binding.reply_object,
            candidate.suspension.key,
        )
        .unwrap();
    assert!(!candidate.suspension.cancelled);
    assert!(claimed.cancelled);
    assert_eq!(claimed.completion, 0xc000_0120);
}

#[test]
fn replacement_lane_cannot_be_claimed_by_old_candidate_or_join_old_pass() {
    let mut lanes = Lanes::new(1, 2);
    let old = add(&mut lanes, 1, 1, true);
    let mut pass = lanes.resume_pass();
    let candidate = lanes.next_resumable_in_pass(&mut pass, |_| true).unwrap();
    let owner = lanes.top(old).unwrap().unwrap().owner;
    lanes
        .begin_resume(
            old,
            candidate.binding.reply_object,
            candidate.suspension.key,
        )
        .unwrap();
    lanes
        .deliver_terminal_for_test(
            old,
            candidate.binding.reply_object,
            candidate.suspension.key,
            owner,
        )
        .unwrap();
    lanes.release(old, candidate.binding.reply_object).unwrap();
    let replacement = add(&mut lanes, 2, 2, true);
    assert_eq!(replacement.index, old.index);
    assert_ne!(replacement.generation, old.generation);
    assert!(lanes
        .begin_resume(
            old,
            candidate.binding.reply_object,
            candidate.suspension.key
        )
        .is_err());
    assert!(lanes.next_resumable_in_pass(&mut pass, |_| true).is_none());
    assert_eq!(lanes.next_resumable().unwrap().lane, replacement);
}

#[test]
fn unburied_resuming_frame_is_not_reexecuted_in_either_pass() {
    let mut lanes = Lanes::new(1, 3);
    let lane = add(&mut lanes, 1, 1, false);
    let reply = lanes.binding(lane).unwrap().reply_object;
    let outer = SuspensionKey::provider_wait(1);
    let inner = SuspensionKey::provider_wait(2);
    let mut owner = lanes.top(lane).unwrap().unwrap().owner;
    owner.dispatch_id = 2;
    lanes.begin_resume(lane, reply, outer).unwrap();
    lanes
        .admit_running(lane, reply, inner, 2, owner, 2)
        .unwrap();
    lanes.select(inner, 0).unwrap();
    let mut pass = lanes.resume_pass();
    assert_eq!(
        lanes
            .next_resumable_in_pass(&mut pass, |_| true)
            .unwrap()
            .suspension
            .key,
        inner
    );
    lanes.begin_resume(lane, reply, inner).unwrap();
    lanes
        .deliver_terminal_for_test(lane, reply, inner, owner)
        .unwrap();
    assert!(lanes.next_resumable_in_pass(&mut pass, |_| true).is_none());
    assert!(lanes.next_resumable().is_none());
    assert_eq!(lanes.top(lane).unwrap().unwrap().key, outer);
    assert!(matches!(
        lanes.top(lane).unwrap().unwrap().phase,
        SuspensionPhase::Resuming { .. }
    ));
}
