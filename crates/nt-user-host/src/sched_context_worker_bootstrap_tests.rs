//! RED contracts for the first passive executive worker (#382).
//!
//! `ExecutorTable::register` already assumes a blocked worker. The bootstrap owner must
//! establish that physical state before the table may receive a passive-worker proof.

use super::{
    BlockedWorkerObservation, BootstrapUnbindIo, PassiveWorkerBootstrap, ReplyObservation,
    UnbindOutcome, WorkerBootstrapResources,
};

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

struct Unbinder {
    result: UnbindOutcome,
    calls: usize,
}

impl BootstrapUnbindIo for Unbinder {
    fn unbind_bootstrap_sc(&mut self, sc: u64, tcb: u64) -> UnbindOutcome {
        assert_eq!((sc, tcb), (BOOTSTRAP_SC, WORKER_TCB));
        self.calls += 1;
        self.result
    }
}

#[test]
fn only_exact_blocked_worker_and_free_reply_permit_unbind() {
    let mut owner = PassiveWorkerBootstrap::new(resources()).unwrap();
    let mut unbinder = Unbinder {
        result: UnbindOutcome::Acknowledged,
        calls: 0,
    };

    assert!(owner.try_unbind(&mut unbinder).is_err());
    assert_eq!(unbinder.calls, 0);
    assert!(owner
        .observe_blocked(observed(
            WORKER_TCB + 1,
            PRIVATE_ENDPOINT,
            ReplyObservation::Free
        ))
        .is_err());
    assert!(owner
        .observe_blocked(observed(
            WORKER_TCB,
            PRIVATE_ENDPOINT + 1,
            ReplyObservation::Free
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

    owner
        .observe_blocked(observed(
            WORKER_TCB,
            PRIVATE_ENDPOINT,
            ReplyObservation::Free,
        ))
        .unwrap();
    assert!(owner.take_passive().is_none());
    owner.try_unbind(&mut unbinder).unwrap();
    assert_eq!(unbinder.calls, 1);
    let passive = owner
        .take_passive()
        .expect("acknowledged unbind yields passive worker");
    assert_eq!(passive.worker_tcb(), WORKER_TCB);
    assert_eq!(passive.private_endpoint(), PRIVATE_ENDPOINT);
    assert_eq!(passive.bootstrap_sc(), BOOTSTRAP_SC);
    assert_eq!(passive.ipc_buffer(), IPC_BUFFER);
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
            ReplyObservation::Free,
        ))
        .unwrap();
    let mut unbinder = Unbinder {
        result: UnbindOutcome::Indeterminate(0xdead),
        calls: 0,
    };

    assert!(owner.try_unbind(&mut unbinder).is_err());
    assert_eq!(unbinder.calls, 1);
    assert_eq!(owner.retained_resources(), Some(&resources()));
    assert!(owner.take_passive().is_none());
    unbinder.result = UnbindOutcome::Acknowledged;
    assert!(owner.try_unbind(&mut unbinder).is_err());
    assert_eq!(
        unbinder.calls, 1,
        "uncertain unbind must not be issued twice"
    );
    assert_eq!(owner.retained_resources(), Some(&resources()));
    assert!(owner.take_passive().is_none());
}
