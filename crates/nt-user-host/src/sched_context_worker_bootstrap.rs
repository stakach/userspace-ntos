//! Exact physical bootstrap proof for the first passive executive worker.
//!
//! The run-token executor table admits a worker only after this owner has observed its private
//! receive, checked a free Reply and acknowledged removal of the temporary scheduling context.
//! A native unbind with an uncertain result leaves every resource retained and cannot be replayed.

/// Capabilities and memory that must remain owned from worker creation through passive handoff.
/// The bootstrap SC remains here after unbind so its eventual retirement has one owner. A native
/// adapter must authenticate each physical capability before constructing this bundle; equal
/// numeric CPtrs alone do not prove ownership.
#[derive(Debug, PartialEq, Eq)]
pub struct WorkerBootstrapResources {
    pub(super) worker_tcb: u64,
    pub(super) private_endpoint: u64,
    pub(super) bootstrap_sc: u64,
    pub(super) ipc_buffer: u64,
    pub(super) reply_cap: u64,
}

impl WorkerBootstrapResources {
    pub fn worker_tcb(&self) -> u64 {
        self.worker_tcb
    }
    pub fn private_endpoint(&self) -> u64 {
        self.private_endpoint
    }
    pub fn bootstrap_sc(&self) -> u64 {
        self.bootstrap_sc
    }
    pub fn ipc_buffer(&self) -> u64 {
        self.ipc_buffer
    }
    pub fn reply_cap(&self) -> u64 {
        self.reply_cap
    }

    /// # Safety
    /// The native adapter must own these exact physical capabilities and the private IPC buffer
    /// for this worker. Reusing a numeric CPtr from another generation violates the contract.
    pub unsafe fn from_native_owned(
        worker_tcb: u64,
        private_endpoint: u64,
        bootstrap_sc: u64,
        ipc_buffer: u64,
        reply_cap: u64,
    ) -> Self {
        Self {
            worker_tcb,
            private_endpoint,
            bootstrap_sc,
            ipc_buffer,
            reply_cap,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReplyObservation {
    /// No receive has offered this object; root's Call cannot bind it to this worker.
    Free,
    /// The object is offered to the observed worker, unbound to any caller or Reply chain.
    OfferedToWorker,
    /// Bound to a caller or offered to a different worker.
    Held,
}

/// Native observation of the worker blocked at its own first receive. The native adapter must
/// derive this from authenticated TCB/endpoint/Reply state, not from a request's claimed IDs.
/// `OfferedToWorker` requires the kernel Reply object to name this exact TCB as its offered
/// receiver and have no bound caller or Reply-chain links.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockedWorkerObservation {
    pub(super) worker_tcb: u64,
    pub(super) private_endpoint: u64,
    pub(super) reply: ReplyObservation,
}

impl BlockedWorkerObservation {
    /// # Safety
    /// The native adapter must have inspected the exact physical worker TCB and private endpoint
    /// after its first receive, and must authenticate the Reply state for that same generation.
    pub unsafe fn from_native_checked(
        worker_tcb: u64,
        private_endpoint: u64,
        reply: ReplyObservation,
    ) -> Self {
        Self {
            worker_tcb,
            private_endpoint,
            reply,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnbindOutcome {
    Acknowledged,
    /// The caller cannot prove whether the native effect occurred. Retain and never retry.
    Indeterminate(u64),
}

/// `Acknowledged` means the native adapter observed an exact physical SC unbind ACK for this
/// SC/TCB pair. A numeric match or issued request is insufficient; uncertain results remain owned.
pub trait BootstrapUnbindIo {
    fn unbind_bootstrap_sc(&mut self, sc: u64, tcb: u64) -> UnbindOutcome;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootstrapError {
    InvalidResources,
    InvalidState,
    WrongWorker,
    ReplyNotOffered,
    UnbindIndeterminate(u64),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Created,
    Blocked,
    UnbindInFlight,
    Unbound,
    Uncertain,
    Transferred,
}

/// Move-only owner of the temporary SC and all worker resources before passive handoff.
#[must_use = "retain the worker and bootstrap SC until acknowledged passive handoff"]
pub struct PassiveWorkerBootstrap {
    resources: Option<WorkerBootstrapResources>,
    phase: Phase,
}

impl PassiveWorkerBootstrap {
    pub fn new(
        resources: WorkerBootstrapResources,
    ) -> Result<Self, (BootstrapError, WorkerBootstrapResources)> {
        if resources.worker_tcb <= 1
            || resources.private_endpoint == 0
            || resources.bootstrap_sc == 0
            || resources.ipc_buffer == 0
            || resources.reply_cap == 0
        {
            return Err((BootstrapError::InvalidResources, resources));
        }
        Ok(Self {
            resources: Some(resources),
            phase: Phase::Created,
        })
    }

    pub fn retained_resources(&self) -> Option<&WorkerBootstrapResources> {
        self.resources.as_ref()
    }

    pub fn observe_blocked(
        &mut self,
        observed: BlockedWorkerObservation,
    ) -> Result<(), BootstrapError> {
        if self.phase != Phase::Created {
            return Err(BootstrapError::InvalidState);
        }
        let resources = self
            .resources
            .as_ref()
            .expect("untransferred bootstrap owns resources");
        if observed.worker_tcb != resources.worker_tcb
            || observed.private_endpoint != resources.private_endpoint
        {
            return Err(BootstrapError::WrongWorker);
        }
        if observed.reply != ReplyObservation::OfferedToWorker {
            return Err(BootstrapError::ReplyNotOffered);
        }
        self.phase = Phase::Blocked;
        Ok(())
    }

    /// Record the native attempt before calling out. An indeterminate result is sticky; neither
    /// a second unbind nor a passive handoff is legal without a separately proven ACK protocol.
    pub fn try_unbind(&mut self, io: &mut impl BootstrapUnbindIo) -> Result<(), BootstrapError> {
        if self.phase != Phase::Blocked {
            return Err(BootstrapError::InvalidState);
        }
        let resources = self
            .resources
            .as_ref()
            .expect("blocked bootstrap owns resources");
        let (sc, tcb) = (resources.bootstrap_sc, resources.worker_tcb);
        self.phase = Phase::UnbindInFlight;
        match io.unbind_bootstrap_sc(sc, tcb) {
            UnbindOutcome::Acknowledged => {
                self.phase = Phase::Unbound;
                Ok(())
            }
            UnbindOutcome::Indeterminate(status) => {
                self.phase = Phase::Uncertain;
                Err(BootstrapError::UnbindIndeterminate(status))
            }
        }
    }

    pub fn take_passive(&mut self) -> Option<PassiveWorker> {
        if self.phase != Phase::Unbound {
            return None;
        }
        self.phase = Phase::Transferred;
        Some(PassiveWorker {
            resources: self
                .resources
                .take()
                .expect("ACKed bootstrap retained resources"),
        })
    }
}

/// One-use proof that the worker can receive root's donated run token.
#[must_use = "transfer the passive worker to its native executive owner"]
pub struct PassiveWorker {
    resources: WorkerBootstrapResources,
}

impl PassiveWorker {
    pub fn worker_tcb(&self) -> u64 {
        self.resources.worker_tcb()
    }
    pub fn private_endpoint(&self) -> u64 {
        self.resources.private_endpoint()
    }
    pub fn bootstrap_sc(&self) -> u64 {
        self.resources.bootstrap_sc()
    }
    pub fn ipc_buffer(&self) -> u64 {
        self.resources.ipc_buffer()
    }
    pub fn reply_cap(&self) -> u64 {
        self.resources.reply_cap()
    }
}
