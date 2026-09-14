use super::*;
use alloc::{boxed::Box, rc::Rc};
use core::{cell::Cell, fmt::Debug};

#[derive(Debug)]
struct Owned {
    value: Box<u64>,
    drops: Rc<Cell<usize>>,
}

impl Owned {
    fn new(value: u64, drops: &Rc<Cell<usize>>) -> Self {
        Self {
            value: Box::new(value),
            drops: Rc::clone(drops),
        }
    }

    fn address(&self) -> *const u64 {
        &*self.value
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

fn rejected<E: Debug + PartialEq, T: Debug>(
    result: Result<T, (E, Owned)>,
    expected: E,
    address: *const u64,
) -> Owned {
    let (error, owned) = result.unwrap_err();
    assert_eq!(error, expected);
    assert_eq!(owned.address(), address);
    owned
}

fn owner(dispatch_id: u64) -> SuspensionOwner {
    SuspensionOwner {
        provider_domain: 3,
        provider_generation: 7,
        dispatch_id,
        caller: SuspensionCaller::Hosted(SuspensionHostedClient {
            client_pi: 0,
            client_generation: 11,
            client_tid: 24,
            client_badge: 4,
        }),
    }
}

fn binding(id: u64) -> LaneBinding {
    LaneBinding {
        executor_id: id + 0x100,
        receive_endpoint: id + 0x200,
        reply_object: id + 0x300,
    }
}

type Lanes = ComponentSuspensionLanes<Owned, u32>;

fn kernel(lanes: &Lanes, lane: LaneHandle) -> SuspensionOwner {
    SuspensionOwner {
        dispatch_id: lanes
            .active_dispatch_identity(lane)
            .unwrap()
            .unwrap()
            .epoch(),
        caller: SuspensionCaller::Kernel { lane },
        ..owner(1)
    }
}

#[test]
fn stack_admission_returns_same_allocation_on_all_refusals() {
    let drops = Rc::new(Cell::new(0));
    let mut stack = ComponentSuspensionStack::<Owned, u32>::new(1);
    let mut offered = Owned::new(10, &drops);
    let address = offered.address();
    let key = SuspensionKey::provider_wait(1);
    for (bad_key, sequence, caller) in [
        (SuspensionKey::provider_wait(0), 1, owner(1)),
        (key, 0, owner(1)),
        (key, 1, owner(0)),
    ] {
        offered = rejected(
            stack.admit_owned(bad_key, sequence, caller, offered),
            SuspensionError::InvalidIdentity,
            address,
        );
        assert!(stack.is_empty());
    }
    offered = rejected(
        stack.admit_owned_with_capacity(key, 1, owner(1), offered, |_| {
            Err(SuspensionError::NoCapacity)
        }),
        SuspensionError::NoCapacity,
        address,
    );
    assert!(stack.is_empty());
    assert_eq!(drops.get(), 0);
    stack.admit_owned(key, 1, owner(1), offered).unwrap();
    let offered = Owned::new(20, &drops);
    let offered_address = offered.address();
    let offered = rejected(
        stack.admit_owned(key, 2, owner(2), offered),
        SuspensionError::DuplicateIdentity,
        offered_address,
    );
    let offered = rejected(
        stack.admit_owned(SuspensionKey::provider_wait(2), 2, owner(1), offered),
        SuspensionError::DuplicateIdentity,
        offered_address,
    );
    let offered = rejected(
        stack.admit_owned(SuspensionKey::provider_wait(2), 2, owner(2), offered),
        SuspensionError::Overflow,
        offered_address,
    );
    assert_eq!(stack.top().unwrap().continuation.address(), address);
    assert_eq!(drops.get(), 0);
    drop(offered);
    let admitted = stack.rollback_admission(key).unwrap();
    assert_eq!(admitted.address(), address);
    drop(admitted);
    assert_eq!(drops.get(), 2);
}

#[test]
fn stack_repark_refusal_preserves_old_and_offered_payloads() {
    let drops = Rc::new(Cell::new(0));
    let mut stack = ComponentSuspensionStack::<Owned, u32>::new(2);
    let old = SuspensionKey::provider_wait(1);
    let next = SuspensionKey::provider_wait(2);
    let offered = Owned::new(20, &drops);
    let address = offered.address();
    let offered = rejected(
        stack.rearm_owned(old, next, 2, owner(1), offered),
        SuspensionError::NotFound,
        address,
    );
    stack
        .admit_owned(old, 1, owner(1), Owned::new(10, &drops))
        .unwrap();
    let original_address = stack.top().unwrap().continuation.address();
    let mut offered = rejected(
        stack.rearm_owned(old, next, 2, owner(1), offered),
        SuspensionError::InvalidPhase,
        address,
    );
    stack.select(old, 17).unwrap();
    stack.begin_resume(old).unwrap();
    for (completed, new, sequence, caller, error) in [
        (
            old,
            SuspensionKey::provider_wait(0),
            2,
            owner(1),
            SuspensionError::InvalidIdentity,
        ),
        (old, old, 2, owner(1), SuspensionError::DuplicateIdentity),
        (next, next, 2, owner(1), SuspensionError::NotTop),
        (old, next, 0, owner(1), SuspensionError::InvalidIdentity),
        (old, next, 2, owner(2), SuspensionError::InvalidPhase),
    ] {
        offered = rejected(
            stack.rearm_owned(completed, new, sequence, caller, offered),
            error,
            address,
        );
        let frame = stack.top().unwrap();
        assert_eq!(frame.key, old);
        assert_eq!(frame.admission_sequence, 1);
        assert_eq!(frame.continuation.address(), original_address);
        assert_eq!(
            frame.phase,
            SuspensionPhase::Resuming {
                completion: 17,
                cancelled: false
            }
        );
        assert_eq!(drops.get(), 0);
    }
    let previous = stack.rearm_owned(old, next, 2, owner(1), offered).unwrap();
    assert_eq!(previous.address(), original_address);
    assert_eq!(drops.get(), 0);
    drop(previous);
    assert_eq!(drops.get(), 1);
    assert_eq!(stack.top().unwrap().continuation.address(), address);
    assert_eq!(stack.top().unwrap().phase, SuspensionPhase::Waiting);
    drop(stack);
    assert_eq!(drops.get(), 2);
}

#[test]
fn lane_admission_rejects_wrong_authority_without_consuming_continuation() {
    let drops = Rc::new(Cell::new(0));
    let mut lanes = Lanes::new(1, 2);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    let key = SuspensionKey::provider_wait(1);
    let offered = Owned::new(10, &drops);
    let address = offered.address();
    let offered = rejected(
        lanes.admit_running_owned(lane, reply, key, 1, owner(1), offered),
        LaneError::InvalidPhase,
        address,
    );
    lanes.begin_dispatch(lane, reply).unwrap();
    let caller = kernel(&lanes, lane);
    let mut offered = rejected(
        lanes.admit_running_owned(lane, reply + 1, key, 1, caller, offered),
        LaneError::WrongBinding,
        address,
    );
    offered = rejected(
        lanes.admit_running_owned(
            lane,
            reply,
            key,
            1,
            SuspensionOwner {
                dispatch_id: caller.dispatch_id + 1,
                ..caller
            },
            offered,
        ),
        LaneError::InvalidIdentity,
        address,
    );
    offered = rejected(
        lanes.admit_running_owned(lane, reply, key, 0, caller, offered),
        LaneError::Suspension(SuspensionError::InvalidIdentity),
        address,
    );
    assert_eq!(lanes.running(), Some(lane));
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Running));
    assert_eq!(lanes.suspension_count(lane), Ok(0));
    assert_eq!(drops.get(), 0);
    lanes
        .admit_running_owned(lane, reply, key, 1, caller, offered)
        .unwrap();
    assert_eq!(lanes.running(), None);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    let owned = lanes.rollback_admission(lane, reply, key).unwrap();
    assert_eq!(owned.address(), address);
    drop(owned);
    assert_eq!(drops.get(), 1);
}

#[test]
fn lane_cross_owner_admission_and_repark_refusals_preserve_running_frame() {
    let drops = Rc::new(Cell::new(0));
    let mut lanes = Lanes::new(2, 2);
    let first = lanes.allocate(binding(1)).unwrap();
    let second = lanes.allocate(binding(2)).unwrap();
    let key = SuspensionKey::provider_wait(1);
    let sibling = SuspensionKey::provider_wait(2);
    let next = SuspensionKey::provider_wait(3);
    lanes
        .begin_dispatch(first, binding(1).reply_object)
        .unwrap();
    let first_owner = kernel(&lanes, first);
    lanes
        .admit_running_owned(
            first,
            binding(1).reply_object,
            key,
            1,
            first_owner,
            Owned::new(10, &drops),
        )
        .unwrap();
    lanes
        .begin_dispatch(second, binding(2).reply_object)
        .unwrap();
    let second_owner = kernel(&lanes, second);
    let offered = Owned::new(20, &drops);
    let address = offered.address();
    let offered = rejected(
        lanes.admit_running_owned(
            second,
            binding(2).reply_object,
            key,
            2,
            second_owner,
            offered,
        ),
        LaneError::Suspension(SuspensionError::DuplicateIdentity),
        address,
    );
    assert_eq!(lanes.running(), Some(second));
    lanes
        .admit_running_owned(
            second,
            binding(2).reply_object,
            sibling,
            2,
            second_owner,
            offered,
        )
        .unwrap();
    lanes.select(key, 21).unwrap();
    lanes
        .begin_resume(first, binding(1).reply_object, key)
        .unwrap();
    let original = lanes
        .frame(first, key)
        .unwrap()
        .unwrap()
        .continuation
        .address();
    let mut offered = Owned::new(30, &drops);
    let address = offered.address();
    for (reply, completed, new, sequence, caller, error) in [
        (
            binding(2).reply_object,
            key,
            next,
            3,
            first_owner,
            LaneError::WrongBinding,
        ),
        (
            binding(1).reply_object,
            key,
            next,
            3,
            second_owner,
            LaneError::InvalidIdentity,
        ),
        (
            binding(1).reply_object,
            key,
            sibling,
            3,
            first_owner,
            LaneError::Suspension(SuspensionError::DuplicateIdentity),
        ),
        (
            binding(1).reply_object,
            next,
            next,
            3,
            first_owner,
            LaneError::Suspension(SuspensionError::NotTop),
        ),
        (
            binding(1).reply_object,
            key,
            next,
            0,
            first_owner,
            LaneError::Suspension(SuspensionError::InvalidIdentity),
        ),
    ] {
        offered = rejected(
            lanes.rearm_running_owned(first, reply, completed, new, sequence, caller, offered),
            error,
            address,
        );
        assert_eq!(lanes.running(), Some(first));
        assert_eq!(lanes.phase(first), Ok(LanePhase::Running));
        let frame = lanes.frame(first, key).unwrap().unwrap();
        assert_eq!(frame.continuation.address(), original);
        assert_eq!(
            frame.phase,
            SuspensionPhase::Resuming {
                completion: 21,
                cancelled: false
            }
        );
        assert_eq!(drops.get(), 0);
    }
    let previous = lanes
        .rearm_running_owned(
            first,
            binding(1).reply_object,
            key,
            next,
            3,
            first_owner,
            offered,
        )
        .unwrap();
    assert_eq!(previous.address(), original);
    assert_eq!(drops.get(), 0);
    drop(previous);
    assert_eq!(drops.get(), 1);
    assert_eq!(lanes.running(), None);
    assert_eq!(lanes.phase(first), Ok(LanePhase::Suspended));
    assert_eq!(
        lanes
            .frame(first, next)
            .unwrap()
            .unwrap()
            .continuation
            .address(),
        address
    );
    assert!(lanes.frame(second, sibling).unwrap().is_some());
    drop(lanes);
    assert_eq!(drops.get(), 3);
}

#[test]
fn external_transfer_refusals_preserve_token_and_offered_payload() {
    let drops = Rc::new(Cell::new(0));
    let mut lanes = Lanes::new(1, 2);
    let lane = lanes.allocate(binding(1)).unwrap();
    let reply = binding(1).reply_object;
    lanes.begin_dispatch(lane, reply).unwrap();
    let caller = kernel(&lanes, lane);
    lanes.suspend_running(lane, reply, 50).unwrap();
    lanes.resume_external(lane, reply, 50).unwrap();
    let key = SuspensionKey::provider_wait(1);
    let mut offered = Owned::new(10, &drops);
    let address = offered.address();
    for (reply_object, token, sequence, error) in [
        (reply, 0, 1, LaneError::InvalidIdentity),
        (reply + 1, 50, 1, LaneError::WrongBinding),
        (reply, 51, 1, LaneError::InvalidPhase),
        (
            reply,
            50,
            0,
            LaneError::Suspension(SuspensionError::InvalidIdentity),
        ),
    ] {
        offered = rejected(
            lanes.transfer_external_to_suspension_running_owned(
                lane,
                reply_object,
                token,
                key,
                sequence,
                caller,
                offered,
            ),
            error,
            address,
        );
        assert_eq!(lanes.external_top(lane), Ok(Some(50)));
        assert_eq!(lanes.running(), Some(lane));
        assert_eq!(lanes.suspension_count(lane), Ok(0));
        assert_eq!(drops.get(), 0);
    }
    lanes
        .transfer_external_to_suspension_running_owned(lane, reply, 50, key, 1, caller, offered)
        .unwrap();
    assert_eq!(lanes.external_top(lane), Ok(None));
    assert_eq!(lanes.running(), None);
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Suspended));
    assert_eq!(
        lanes
            .frame(lane, key)
            .unwrap()
            .unwrap()
            .continuation
            .address(),
        address
    );
    assert_eq!(drops.get(), 0);
    drop(lanes);
    assert_eq!(drops.get(), 1);
}

#[test]
fn legacy_wrappers_keep_their_drop_on_error_contract() {
    let drops = Rc::new(Cell::new(0));
    let mut stack = ComponentSuspensionStack::<Owned, u32>::new(1);
    let key = SuspensionKey::provider_wait(1);
    assert_eq!(
        stack.admit(key, 0, owner(1), Owned::new(1, &drops)),
        Err(SuspensionError::InvalidIdentity)
    );
    assert_eq!(
        stack.rearm(key, key, 1, owner(1), Owned::new(2, &drops)),
        Err(SuspensionError::NotFound)
    );
    let mut lanes = Lanes::new(1, 1);
    let lane = lanes.allocate(binding(1)).unwrap();
    assert_eq!(
        lanes.admit_running(
            lane,
            binding(1).reply_object,
            key,
            1,
            owner(1),
            Owned::new(3, &drops)
        ),
        Err(LaneError::InvalidPhase)
    );
    assert_eq!(
        lanes.rearm_running(
            lane,
            binding(1).reply_object,
            key,
            key,
            1,
            owner(1),
            Owned::new(4, &drops)
        ),
        Err(LaneError::InvalidPhase)
    );
    assert_eq!(drops.get(), 4);
    assert_eq!(
        lanes.transfer_external_to_suspension_running(
            lane,
            binding(1).reply_object,
            0,
            key,
            1,
            owner(1),
            Owned::new(5, &drops),
        ),
        Err(LaneError::InvalidIdentity)
    );
    assert_eq!(drops.get(), 5);
}
