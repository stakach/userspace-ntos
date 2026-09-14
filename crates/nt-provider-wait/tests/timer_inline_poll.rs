//! Composition of the production timer store, deadlines, and dispatcher arbiter. The adapter
//! delegates every state operation to the timer store; native IPC and reply delivery are not run.

use nt_component_suspension::{ComponentSuspensionLanes, LaneBinding, LanePhase};
use nt_provider_wait::*;
use nt_time::TimeSnapshot;

const PROVIDER: ProviderDomainIdentity = ProviderDomainIdentity {
    domain: 7,
    generation: 3,
};

struct Timers {
    table: ProviderTimerTable,
    held: usize,
}

impl ProviderDispatcherWaitBackend for Timers {
    type Lease = ProviderTimerLeaseId;
    type Error = ProviderTimerError;

    fn acquire_dispatcher_wait(
        &mut self,
        owner: ProviderWaitOwner,
        object: ProviderWaitObject,
    ) -> Result<Self::Lease, Self::Error> {
        let lease = self.table.acquire_wait(owner, object)?;
        self.held += 1;
        Ok(lease)
    }

    fn dispatcher_is_ready(&self, lease: Self::Lease) -> bool {
        self.table.is_ready(lease).unwrap()
    }

    fn consume_ready_dispatcher(&mut self, lease: Self::Lease) {
        self.table.consume_ready(lease).unwrap();
    }

    fn release_dispatcher_wait(&mut self, lease: Self::Lease) {
        assert_eq!(self.table.release_wait(lease), Ok(None));
        self.held -= 1;
    }
}

fn now(monotonic_100ns: u64) -> TimeSnapshot {
    TimeSnapshot {
        monotonic_100ns,
        system_time_100ns: 100_000 + monotonic_100ns,
        clock_generation: 0,
    }
}

fn owner(dispatch_id: u64) -> ProviderWaitOwner {
    ProviderWaitOwner {
        provider_domain: PROVIDER.domain,
        provider_generation: PROVIDER.generation,
        dispatch_id,
        caller: SuspensionCaller::Hosted(SuspensionHostedClient {
            client_pi: 2,
            client_generation: 4,
            client_tid: dispatch_id + 10,
            client_badge: dispatch_id + 100,
        }),
    }
}

fn request(
    owner: ProviderWaitOwner,
    wait_id: u64,
    timer: ProviderTimerId,
    timeout_kind: ProviderWaitTimeoutKind,
) -> ProviderWaitRequest {
    let mut request = ProviderWaitRequest::empty();
    request
        .begin(
            ProviderWaitRequestMetadata {
                wait_id,
                owner,
                wait_type: ProviderWaitType::Any,
                wait_mode: ProviderWaitMode::Kernel,
                alertable: false,
                timeout_kind,
                timeout_100ns: 0,
            },
            &[timer.wait_object()],
        )
        .unwrap();
    request
}

fn timer(kind: ProviderTimerKind) -> (Timers, ProviderTimerId) {
    let mut table = ProviderTimerTable::new(PROVIDER).unwrap();
    let id = table.publish(1, kind).unwrap();
    assert_eq!(table.set_local(1, -10, 0, now(100)), Ok(false));
    assert!(table.expire_next_due(now(109)).is_none());
    assert_eq!(table.read_state(id), Ok(false));
    (Timers { table, held: 0 }, id)
}

#[test]
fn older_waiter_consumes_expired_sync_timer_before_inline_poll_without_lane_switch() {
    let (mut timers, id) = timer(ProviderTimerKind::Synchronization);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    let original = owner(1);
    let polling = owner(2);
    let blocking = request(original, 11, id, ProviderWaitTimeoutKind::Infinite);
    assert_eq!(
        arbiter.admit(&mut timers, &blocking, original, 1, now(100)),
        Ok(ProviderDispatcherWaitAdmission::Parked { wait_id: 11 })
    );
    assert_eq!(timers.held, 1);

    let mut lanes = ComponentSuspensionLanes::<u64, i32>::new(1, 4);
    let binding = LaneBinding {
        executor_id: 101,
        receive_endpoint: 201,
        reply_object: 301,
    };
    let lane = lanes.allocate(binding).unwrap();
    lanes.begin_dispatch(lane, binding.reply_object).unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap();

    assert_eq!(timers.table.expire_next_due(now(110)).unwrap().id, id);
    assert!(timers.table.expire_next_due(now(110)).is_none());
    let completion = arbiter.pop_ready(&mut timers).unwrap();
    assert_eq!(completion.owner, original);
    assert_eq!(completion.wait_id, 11);
    assert_eq!(completion.admission_sequence, 1);
    assert_eq!(completion.status, STATUS_WAIT_0);
    assert_eq!(timers.table.read_state(id), Ok(false));
    assert_eq!(timers.held, 0);
    let poll = request(polling, 12, id, ProviderWaitTimeoutKind::Poll);
    assert_eq!(
        arbiter.poll(&mut timers, &poll, polling),
        Ok(STATUS_TIMEOUT)
    );
    assert_eq!(timers.held, 0);
    assert!(arbiter.is_empty());
    assert!(arbiter.pop_ready(&mut timers).is_none());
    // Selecting the prior completion is not scheduling its continuation. The native pump must
    // retain this same distinction until the polling caller has received its synchronous reply.
    assert_eq!(lanes.phase(lane), Ok(LanePhase::Running));
    assert_eq!(lanes.active_dispatch_identity(lane), Ok(dispatch));
}

#[test]
fn expired_sync_timer_without_prior_waiter_satisfies_exactly_one_inline_poll() {
    let (mut timers, id) = timer(ProviderTimerKind::Synchronization);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    assert_eq!(timers.table.expire_next_due(now(110)).unwrap().id, id);
    assert!(arbiter.pop_ready(&mut timers).is_none());
    let polling = owner(2);
    let poll = request(polling, 12, id, ProviderWaitTimeoutKind::Poll);
    assert_eq!(arbiter.poll(&mut timers, &poll, polling), Ok(STATUS_WAIT_0));
    assert_eq!(
        arbiter.poll(&mut timers, &poll, polling),
        Ok(STATUS_TIMEOUT)
    );
    assert_eq!(timers.table.read_state(id), Ok(false));
    assert_eq!(timers.held, 0);
    assert!(arbiter.is_empty());
}

#[test]
fn expired_notification_timer_satisfies_parked_waiters_and_remains_ready_for_poll() {
    let (mut timers, id) = timer(ProviderTimerKind::Notification);
    let mut arbiter = ProviderDispatcherWaitArbiter::new();
    for sequence in [1, 2] {
        let original = owner(sequence);
        let blocking = request(
            original,
            sequence + 10,
            id,
            ProviderWaitTimeoutKind::Infinite,
        );
        assert_eq!(
            arbiter.admit(&mut timers, &blocking, original, sequence, now(100)),
            Ok(ProviderDispatcherWaitAdmission::Parked {
                wait_id: sequence + 10
            })
        );
    }
    assert_eq!(timers.table.expire_next_due(now(110)).unwrap().id, id);
    for sequence in [1, 2] {
        let completion = arbiter.pop_ready(&mut timers).unwrap();
        assert_eq!(completion.owner, owner(sequence));
        assert_eq!(completion.admission_sequence, sequence);
        assert_eq!(completion.status, STATUS_WAIT_0);
    }
    assert!(arbiter.pop_ready(&mut timers).is_none());
    let polling = owner(3);
    let poll = request(polling, 13, id, ProviderWaitTimeoutKind::Poll);
    for _ in 0..2 {
        assert_eq!(arbiter.poll(&mut timers, &poll, polling), Ok(STATUS_WAIT_0));
        assert_eq!(timers.table.read_state(id), Ok(true));
        assert_eq!(timers.held, 0);
    }
    assert!(arbiter.is_empty());
}
