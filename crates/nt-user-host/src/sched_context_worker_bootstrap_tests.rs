//! RED contracts for the first passive executive worker (#382).
//!
//! `ExecutorTable::register` already assumes a blocked worker. The bootstrap owner must
//! establish that physical state before the table may receive a passive-worker proof.

use super::{
    BlockedWorkerObservation, BootstrapError, BootstrapUnbindIo, PassiveWorkerBootstrap,
    ReplyObservation, UnbindOutcome, WorkerBootstrapResources,
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

fn observed(tcb: u64, endpoint: u64, reply: ReplyObservation) -> BlockedWorkerObservation {
    BlockedWorkerObservation {
        worker_tcb: tcb,
        private_endpoint: endpoint,
        reply,
    }
}

#[test]
fn first_receive_requires_reply_offered_to_the_exact_blocked_worker() {
    let mut owner = PassiveWorkerBootstrap::new(resources()).unwrap();
    // rust-micro's receive_ipc offers the Reply object to this worker before blocking.
    // An unoffered Reply cannot receive root's later Call with this Reply object.
    assert_eq!(
        owner.observe_blocked(observed(
            WORKER_TCB,
            PRIVATE_ENDPOINT,
            ReplyObservation::Free
        )),
        Err(BootstrapError::ReplyNotOffered),
    );
    owner
        .observe_blocked(observed(
            WORKER_TCB,
            PRIVATE_ENDPOINT,
            ReplyObservation::OfferedToWorker,
        ))
        .unwrap();
}

struct Unbinder {
    result: UnbindOutcome,
    calls: usize,
    last_request: Option<(u64, u64, u64, u64)>,
}

impl BootstrapUnbindIo for Unbinder {
    fn unbind_bootstrap_sc(&mut self, sc: u64, tcb: u64, endpoint: u64, reply: u64) -> UnbindOutcome {
        self.calls += 1;
        self.last_request = Some((sc, tcb, endpoint, reply));
        self.result
    }
}

#[test]
fn only_exact_blocked_worker_and_offered_reply_permit_unbind() {
    let mut owner = PassiveWorkerBootstrap::new(resources()).unwrap();
    let mut unbinder = Unbinder {
        result: UnbindOutcome::Acknowledged,
        calls: 0,
        last_request: None,
    };

    assert!(owner.try_unbind(&mut unbinder).is_err());
    assert_eq!(unbinder.calls, 0);
    assert!(owner
        .observe_blocked(observed(
            WORKER_TCB + 1,
            PRIVATE_ENDPOINT,
            ReplyObservation::OfferedToWorker
        ))
        .is_err());
    assert!(owner
        .observe_blocked(observed(
            WORKER_TCB,
            PRIVATE_ENDPOINT + 1,
            ReplyObservation::OfferedToWorker
        ))
        .is_err());
    assert!(owner
        .observe_blocked(observed(
            WORKER_TCB,
            PRIVATE_ENDPOINT,
            ReplyObservation::Held
        ))
        .is_err());
    assert!(owner.take_passive().is_none());
    assert_eq!(unbinder.calls, 0);
    assert_eq!(unbinder.last_request, None);

    owner
        .observe_blocked(observed(
            WORKER_TCB,
            PRIVATE_ENDPOINT,
            ReplyObservation::OfferedToWorker,
        ))
        .unwrap();
    assert!(owner.take_passive().is_none());
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

#[test]
fn indeterminate_unbind_retains_owner_and_cannot_replay_native_effect() {
    let mut owner = PassiveWorkerBootstrap::new(resources()).unwrap();
    owner
        .observe_blocked(observed(
            WORKER_TCB,
            PRIVATE_ENDPOINT,
            ReplyObservation::OfferedToWorker,
        ))
        .unwrap();
    let mut unbinder = Unbinder {
        result: UnbindOutcome::Indeterminate(0xdead),
        calls: 0,
        last_request: None,
    };

    assert!(owner.try_unbind(&mut unbinder).is_err());
    assert_eq!(unbinder.calls, 1);
    assert_eq!(unbinder.last_request, Some((
        BOOTSTRAP_SC, WORKER_TCB, PRIVATE_ENDPOINT, REPLY_CAP,
    )));
    assert_eq!(owner.retained_resources(), Some(&resources()));
    assert!(owner.take_passive().is_none());
    unbinder.result = UnbindOutcome::Acknowledged;
    assert!(owner.try_unbind(&mut unbinder).is_err());
    assert_eq!(
        unbinder.calls, 1,
        "uncertain unbind must not be issued twice"
    );
    assert_eq!(unbinder.last_request, Some((
        BOOTSTRAP_SC, WORKER_TCB, PRIVATE_ENDPOINT, REPLY_CAP,
    )));
    assert_eq!(owner.retained_resources(), Some(&resources()));
    assert!(owner.take_passive().is_none());
}
