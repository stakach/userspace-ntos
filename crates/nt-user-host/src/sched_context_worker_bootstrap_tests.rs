//! Contracts for the first passive executive worker (#382).
//!
//! The kernel's checked unbind ACK establishes the blocked private receive and offered Reply;
//! a ready message or pre-observation is never authority for passive handoff.

use super::{
    BootstrapError, BootstrapUnbindIo, PassiveWorkerBootstrap, UnbindOutcome,
    WorkerBootstrapResources,
};
use nt_component_suspension::executor_local::TcbIdentity;
use nt_component_suspension::ExecutorTable;

const WORKER_TCB: u64 = 400;
const PRIVATE_ENDPOINT: u64 = 500;
const BOOTSTRAP_SC: u64 = 100;
const IPC_BUFFER: u64 = 600;
const REPLY_CAP: u64 = 700;

fn resources() -> WorkerBootstrapResources {
    WorkerBootstrapResources {
        worker_tcb: WORKER_TCB,
        private_endpoint: PRIVATE_ENDPOINT,
        bootstrap_sc: BOOTSTRAP_SC,
        ipc_buffer: IPC_BUFFER,
        reply_cap: REPLY_CAP,
    }
}

struct Unbinder {
    result: UnbindOutcome,
    calls: usize,
    last_request: Option<(u64, u64, u64, u64)>,
}

// SAFETY: This test backend's Acknowledged variant models only the exact zero-word kernel ACK.
unsafe impl BootstrapUnbindIo for Unbinder {
    fn unbind_bootstrap_sc(&mut self, sc: u64, tcb: u64, endpoint: u64, reply: u64) -> UnbindOutcome {
        self.calls += 1;
        self.last_request = Some((sc, tcb, endpoint, reply));
        self.result
    }
}

#[test]
fn checked_unbind_ack_establishes_blocked_private_receive_without_prior_observation() {
    let mut owner = PassiveWorkerBootstrap::new(resources()).unwrap();
    let mut unbinder = Unbinder {
        // Model the kernel's exact zero-word ACK: it atomically checked this SC, TCB,
        // private endpoint, and offered Reply before removing the bootstrap SC.
        result: UnbindOutcome::Acknowledged,
        calls: 0,
        last_request: None,
    };

    owner.try_unbind(&mut unbinder).expect("checked ACK establishes the blocked receiver");
    assert_eq!(unbinder.calls, 1);
    assert_eq!(
        unbinder.last_request,
        Some((BOOTSTRAP_SC, WORKER_TCB, PRIVATE_ENDPOINT, REPLY_CAP))
    );
    let passive = owner.take_passive().expect("ACK transfers the exact worker owner");
    assert_eq!(passive.worker_tcb(), WORKER_TCB);
    assert_eq!(passive.private_endpoint(), PRIVATE_ENDPOINT);
    assert_eq!(passive.reply_cap(), REPLY_CAP);
    assert!(owner.retained_resources().is_none());
    assert!(owner.take_passive().is_none(), "worker owner transfers only once");
}

#[test]
fn indeterminate_checked_unbind_without_prior_observation_retains_and_never_replays() {
    let mut owner = PassiveWorkerBootstrap::new(resources()).unwrap();
    let mut unbinder = Unbinder {
        result: UnbindOutcome::Indeterminate(0xdead),
        calls: 0,
        last_request: None,
    };

    assert_eq!(
        owner.try_unbind(&mut unbinder),
        Err(BootstrapError::UnbindIndeterminate(0xdead))
    );
    assert_eq!(unbinder.calls, 1);
    assert_eq!(
        unbinder.last_request,
        Some((BOOTSTRAP_SC, WORKER_TCB, PRIVATE_ENDPOINT, REPLY_CAP))
    );
    assert_eq!(owner.retained_resources(), Some(&resources()));
    assert!(owner.take_passive().is_none());
    unbinder.result = UnbindOutcome::Acknowledged;
    assert_eq!(owner.try_unbind(&mut unbinder), Err(BootstrapError::InvalidState));
    assert_eq!(unbinder.calls, 1, "uncertain effect must never be replayed");
    assert_eq!(owner.retained_resources(), Some(&resources()));
    assert!(owner.take_passive().is_none());
}

#[test]
fn checked_unbind_ack_enables_one_use_ready_proof_with_resources_retained() {
    let mut owner = PassiveWorkerBootstrap::new(resources()).unwrap();
    let mut unbinder = Unbinder {
        result: UnbindOutcome::Acknowledged,
        calls: 0,
        last_request: None,
    };

    assert!(owner.take_passive().is_none());
    assert_eq!(unbinder.calls, 0);
    assert_eq!(unbinder.last_request, None);
    owner.try_unbind(&mut unbinder).unwrap();
    assert_eq!(unbinder.calls, 1);
    assert_eq!(unbinder.last_request, Some((
        BOOTSTRAP_SC, WORKER_TCB, PRIVATE_ENDPOINT, REPLY_CAP,
    )));
    let mut passive = owner
        .take_passive()
        .expect("acknowledged unbind yields passive worker");
    assert_eq!(passive.worker_tcb(), WORKER_TCB);
    assert_eq!(passive.private_endpoint(), PRIVATE_ENDPOINT);
    assert_eq!(passive.bootstrap_sc(), BOOTSTRAP_SC);
    assert_eq!(passive.ipc_buffer(), IPC_BUFFER);
    assert_eq!(passive.reply_cap(), REPLY_CAP);
    let (mut table, root) = ExecutorTable::try_new(1).unwrap();
    let executor = table.register_unready(&root).unwrap();
    let tcb = TcbIdentity::new(WORKER_TCB, 1);
    assert!(matches!(
        unsafe { passive.issue_ready_proof_once(executor, tcb, WORKER_TCB + 1) },
        Err(BootstrapError::WrongWorker)
    ));
    let ready = unsafe { passive.issue_ready_proof_once(executor, tcb, WORKER_TCB) }.unwrap();
    assert_eq!(ready.executor(), executor);
    assert_eq!(ready.tcb(), tcb);
    assert_eq!(ready.target_cap(), WORKER_TCB);
    assert!(matches!(
        unsafe { passive.issue_ready_proof_once(executor, tcb, WORKER_TCB) },
        Err(BootstrapError::InvalidState)
    ));
    assert_eq!(passive.worker_tcb(), WORKER_TCB);
    assert_eq!(passive.private_endpoint(), PRIVATE_ENDPOINT);
    assert_eq!(passive.bootstrap_sc(), BOOTSTRAP_SC);
    assert_eq!(passive.reply_cap(), REPLY_CAP);
    assert!(owner.take_passive().is_none());
}
