//! Proof-only native passive executor for issue #382.
//!
//! This worker never receives production ingress or borrows `LoopState`. Its first receive is
//! private; the kernel's checked SC-unbind ACK is the only authority for publishing readiness.
//! Worker-specific caps and mapped frames remain with this owner on failure or an uncertain
//! effect. The root's paging-structure cache and failed SC construction rows retain their own
//! resources through their existing owners.

use alloc::boxed::Box;

use nt_component_suspension::executor_local::{
    ExecutorLocalAnchor, ExecutorLocalRegistry, FsInstallAcknowledgement, PassiveWorkerReadyProof,
    PhysicalTcbClaim, PhysicalWorkerEndpointClaim, TcbIdentity,
};
#[cfg(feature = "executor-fault-supervisor-probe")]
use nt_component_suspension::{
    ExecutorFaultBinding, ExecutorFaultReport, ExecutorResume, ExecutorRun, ExecutorState,
    ExecutorYield,
};
use nt_component_suspension::{ExecutorHandle, ExecutorTable, RootReplyIdentity, RootReplySlotTable, RunToken};
use nt_user_host::sched_context::{
    BootstrapError, BootstrapUnbindIo, PassiveWorker, PassiveWorkerBootstrap, UnbindOutcome,
    WorkerBootstrapResources,
};

use super::native_probe_resources::{
    checked, resume_owned_tcb, retype_owned, try_box, OwnedCap, ProbeFailure,
};
#[cfg(feature = "executor-fault-supervisor-probe")]
use super::native_supervisor::{NativeSupervisorProbe, TERMINAL_INFO, TERMINAL_STATUS};
use super::{local, ExecutorLocal};
use crate::*;

const WORKER_SLOT: nt_executive_layout::root::ExecutorWorkerSlot =
    match nt_executive_layout::root::executor_worker_slot(0) {
        Some(slot) => slot,
        None => panic!("diagnostic executor slot must fit the root address plan"),
    };
const STACK_PAGES: usize = (WORKER_SLOT.stack.len / nt_executive_layout::PAGE) as usize;
const STACK_FIRST: u64 = WORKER_SLOT.stack.base;
const STACK_TOP: u64 = WORKER_SLOT.stack.end();
const IPC_VA: u64 = WORKER_SLOT.ipc.base;
const _: () = {
    assert!(STACK_FIRST == WORKER_SLOT.guard.end());
    assert!(IPC_VA >= STACK_TOP + 0x1000);
    assert!(IPC_VA + 0x1000 <= nt_executive_layout::root::EXECUTOR_WORKERS.end());
};

struct WorkerEntryArgs {
    endpoint: u64,
    reply: u64,
    expected_local: *const ExecutorLocal,
}

#[cfg(feature = "executor-fault-supervisor-probe")]
struct FaultCallOwner {
    _root_replies: RootReplySlotTable,
    _supervisor_replies: RootReplySlotTable,
    root_reply: RootReplyIdentity,
    supervisor_reply: RootReplyIdentity,
    run: Option<ExecutorRun>,
    refused_report: Option<ExecutorFaultReport>,
}

/// Root publishes this heap-allocated value before its first native effect and retains the one
/// handle for eventual exact TCB retirement. The worker dereferences only its separately boxed
/// entry arguments and executor-local block, never a field of root's stack frame.
#[must_use = "retain worker caps and FS payload until exact physical TCB retirement"]
struct NativePassiveWorker {
    slot: nt_executive_layout::root::ExecutorWorkerSlot,
    start_attempted: bool,
    executor: Option<ExecutorHandle>,
    identity: Option<TcbIdentity>,
    anchor: Option<ExecutorLocalAnchor>,
    tcb: Option<OwnedCap>,
    endpoint: Option<OwnedCap>,
    reply: Option<OwnedCap>,
    ipc_frame: Option<OwnedCap>,
    stack_frames: [Option<OwnedCap>; STACK_PAGES],
    bootstrap_sc: Option<u64>,
    unbound_local: Option<Box<ExecutorLocal>>,
    unbound_claim: Option<PhysicalTcbClaim>,
    entry_args: Option<Box<WorkerEntryArgs>>,
    fs_ack: Option<FsInstallAcknowledgement>,
    ready: Option<PassiveWorkerReadyProof>,
    bootstrap: Option<PassiveWorkerBootstrap>,
    passive: Option<PassiveWorker>,
    ingress_claim: Option<PhysicalWorkerEndpointClaim>,
    private_reply: Option<RootReplyIdentity>,
}

impl NativePassiveWorker {
    fn new(slot: nt_executive_layout::root::ExecutorWorkerSlot) -> Self {
        Self {
            slot,
            start_attempted: false,
            executor: None,
            identity: None,
            anchor: None,
            tcb: None,
            endpoint: None,
            reply: None,
            ipc_frame: None,
            stack_frames: [const { None }; STACK_PAGES],
            bootstrap_sc: None,
            unbound_local: None,
            unbound_claim: None,
            entry_args: None,
            fs_ack: None,
            ready: None,
            bootstrap: None,
            passive: None,
            ingress_claim: None,
            private_reply: None,
        }
    }
}

pub(crate) struct NativeWorkerProbe {
    table: ExecutorTable,
    root: Option<RunToken>,
    locals: ExecutorLocalRegistry<ExecutorLocal>,
    private_replies: RootReplySlotTable,
    diagnostic: NativePassiveWorker,
    production: NativePassiveWorker,
    #[cfg(feature = "executor-fault-supervisor-probe")]
    fault_probe_attempted: bool,
    #[cfg(feature = "executor-fault-supervisor-probe")]
    supervisor: Option<Box<NativeSupervisorProbe>>,
    #[cfg(feature = "executor-fault-supervisor-probe")]
    production_supervisor: Option<Box<NativeSupervisorProbe>>,
    #[cfg(feature = "executor-fault-supervisor-probe")]
    fault_call: Option<FaultCallOwner>,
}

impl NativeWorkerProbe {
    pub(crate) fn try_new_boxed() -> Result<Box<Self>, ProbeFailure> {
        let _durable = allocator::enter_durable();
        let (table, root) =
            ExecutorTable::try_new(2).map_err(|_| ProbeFailure::at(b"executor-table", u64::MAX))?;
        let private_replies = RootReplySlotTable::new(2)
            .map_err(|_| ProbeFailure::at(b"private-reply-table", u64::MAX))?;
        let production_slot = nt_executive_layout::root::executor_worker_slot(1)
            .ok_or(ProbeFailure::at(b"production-address-slot", 1))?;
        try_box(
            Self {
                table,
                root: Some(root),
                locals: ExecutorLocalRegistry::new(),
                private_replies,
                diagnostic: NativePassiveWorker::new(WORKER_SLOT),
                production: NativePassiveWorker::new(production_slot),
                #[cfg(feature = "executor-fault-supervisor-probe")]
                fault_probe_attempted: false,
                #[cfg(feature = "executor-fault-supervisor-probe")]
                supervisor: None,
                #[cfg(feature = "executor-fault-supervisor-probe")]
                production_supervisor: None,
                #[cfg(feature = "executor-fault-supervisor-probe")]
                fault_call: None,
            },
            b"owner-alloc",
        )
    }

    /// One checked native attempt. Failure leaves this owner, its exact TCB cap, and every
    /// worker-specific possibly published resource intact. The caller may continue root's
    /// existing boot path.
    ///
    /// # Safety
    /// The root task must be the sole accessor of the published owner throughout bootstrap.
    /// The root's CSpace and VSpace must still be the active native address space.
    pub(crate) unsafe fn start(&mut self) -> Result<(), ProbeFailure> {
        unsafe { self.start_one(false) }
    }

    /// Admit a distinct idle worker while the diagnostic worker remains faulted and retained.
    #[cfg(feature = "executor-fault-supervisor-probe")]
    pub(crate) unsafe fn start_production(&mut self) -> Result<(), ProbeFailure> {
        if self.diagnostic.executor
            .and_then(|executor| self.table.state(executor).ok())
            != Some(ExecutorState::Faulted)
        {
            return Err(ProbeFailure::at(b"diagnostic-not-faulted", 0));
        }
        unsafe { self.start_one(true)?; }
        if self.production.executor
            .and_then(|executor| self.table.state(executor).ok())
            != Some(ExecutorState::Idle)
        {
            return Err(ProbeFailure::at(b"production-not-idle", 0));
        }
        Ok(())
    }

    unsafe fn start_one(&mut self, production: bool) -> Result<(), ProbeFailure> {
        let worker = if production { &mut self.production } else { &mut self.diagnostic };
        // A checked error can still leave a partially constructed native owner, and an
        // indeterminate effect must never be replayed. Reject every later attempt before it can
        // overwrite a retained cap, mapping, FS claim or bootstrap state.
        if core::mem::replace(&mut worker.start_attempted, true) {
            return Err(ProbeFailure::at(b"start-already-attempted", u64::MAX));
        }
        let _durable = allocator::enter_durable();
        let tcb = unsafe { retype_owned(&mut worker.tcb, OBJ_TCB, 0, true, b"tcb-retype")? };
        // Fresh root CSpace slots are never recycled by this owner. The retype above creates
        // one physical TCB and this identity is not reused before its confirmed retirement.
        let identity = TcbIdentity::new(tcb, 1);
        worker.identity = Some(identity);
        let endpoint = unsafe {
            retype_owned(
                &mut worker.endpoint,
                OBJ_ENDPOINT,
                0,
                false,
                b"endpoint-retype",
            )?
        };
        let reply = unsafe { retype_owned(&mut worker.reply, OBJ_REPLY, 0, false, b"reply-retype")? };
        let ipc_frame = unsafe {
            retype_owned(
                &mut worker.ipc_frame,
                OBJ_X86_4K_PAGE,
                PAGING_BITS,
                false,
                b"ipc-retype",
            )?
        };
        for (index, slot) in worker.stack_frames.iter_mut().enumerate() {
            let frame = unsafe {
                retype_owned(slot, OBJ_X86_4K_PAGE, PAGING_BITS, false, b"stack-retype")?
            };
            let va = worker.slot.stack.base + index as u64 * 0x1000;
            if !unsafe { ensure_executive_paging(va) } {
                return Err(ProbeFailure::at(b"stack-paging", va));
            }
            checked(b"stack-map", unsafe {
                page_map_r(frame, va, RW_NX, CAP_INIT_THREAD_VSPACE)
            })?;
        }
        // The pages immediately below and above the mapped stack remain unmapped guards.
        if !unsafe { ensure_executive_paging(worker.slot.ipc.base) } {
            return Err(ProbeFailure::at(b"ipc-paging", worker.slot.ipc.base));
        }
        checked(b"ipc-map", unsafe {
            page_map_r(ipc_frame, worker.slot.ipc.base, RW_NX, CAP_INIT_THREAD_VSPACE)
        })?;

        checked(b"tcb-space", unsafe {
            tcb_set_space_r(tcb, 0, CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE)
        })?;
        checked(b"tcb-ipc", unsafe {
            tcb_set_ipc_buffer_r(tcb, worker.slot.ipc.base, ipc_frame)
        })?;
        checked(b"tcb-priority", unsafe { tcb_set_priority_r(tcb, 100) })?;
        worker.bootstrap_sc = Some(
            unsafe { thread_sched_context::attach_sched_context(tcb) }
                .map_err(|status| ProbeFailure::at(b"bootstrap-sc", status))?,
        );

        let executor = self
            .table
            .register_unready(
                self.root
                    .as_ref()
                    .ok_or(ProbeFailure::at(b"root-owner", 0))?,
            )
            .map_err(|_| ProbeFailure::at(b"register-unready", u64::MAX))?;
        worker.executor = Some(executor);
        let payload = try_box(ExecutorLocal::new(), b"local-alloc")?;
        unsafe { payload.initialize_self_anchor() };
        worker.unbound_local = Some(payload);
        worker.unbound_claim = Some(
            unsafe { PhysicalTcbClaim::new(identity, tcb) }
                .map_err(|_| ProbeFailure::at(b"tcb-claim", u64::MAX))?,
        );
        let payload = worker
            .unbound_local
            .take()
            .ok_or(ProbeFailure::at(b"local-owner", 0))?;
        let claim = worker
            .unbound_claim
            .take()
            .ok_or(ProbeFailure::at(b"tcb-owner", 0))?;
        let anchor = match self
            .locals
            .bind_native(&self.table, executor, claim, payload)
        {
            Ok(anchor) => anchor,
            Err((_, payload, claim)) => {
                worker.unbound_local = Some(payload);
                worker.unbound_claim = Some(claim);
                return Err(ProbeFailure::at(b"local-bind", u64::MAX));
            }
        };
        worker.anchor = Some(anchor);
        let ingress_claim = unsafe {
            PhysicalWorkerEndpointClaim::from_native(
                self.locals.physical_claim_for(anchor, identity, executor)
                    .map_err(|_| ProbeFailure::at(b"ingress-tcb-owner", 0))?,
                endpoint,
                1,
            )
        }.map_err(|_| ProbeFailure::at(b"ingress-endpoint-owner", 0))?;
        worker.ingress_claim = Some(ingress_claim);
        let reply_identity = self.private_replies.insert_free(reply)
            .map_err(|_| ProbeFailure::at(b"ingress-reply-owner", 0))?;
        worker.private_reply = Some(reply_identity);
        // Reserve the physical Reply before the worker can offer it in its private receive.
        // A later failed bootstrap keeps this claim with the durable owner.
        self.private_replies.mark_used(reply_identity)
            .map_err(|_| ProbeFailure::at(b"ingress-reply-claim", 0))?;
        self.table.admit_private_ingress(
            self.root.as_ref().ok_or(ProbeFailure::at(b"root-owner", 0))?,
            executor,
            worker.ingress_claim.as_ref().ok_or(ProbeFailure::at(b"ingress-claim", 0))?,
            &self.private_replies,
            reply_identity,
        ).map_err(|_| ProbeFailure::at(b"ingress-admission", 0))?;
        let attempt = self
            .locals
            .begin_fs_install(anchor, &self.table)
            .map_err(|_| ProbeFailure::at(b"fs-begin", u64::MAX))?;
        let target = attempt.target_cap();
        let base = attempt.base();
        let result = unsafe { super::local::set_owned_tcb_fs_base(target, base) };
        if result != 0 {
            // The attempt stays Installing and the registry retains its payload and TCB claim.
            return Err(ProbeFailure::at(b"fs-install", result));
        }
        worker.fs_ack = Some(
            unsafe { self.locals.acknowledge_fs_install(attempt) }
                .map_err(|_| ProbeFailure::at(b"fs-ack", u64::MAX))?,
        );

        worker.entry_args = Some(try_box(
            WorkerEntryArgs {
                endpoint,
                reply,
                expected_local: base,
            },
            b"entry-alloc",
        )?);
        let args = worker
            .entry_args
            .as_deref()
            .ok_or(ProbeFailure::at(b"entry-owner", 0))?
            as *const WorkerEntryArgs as u64;
        checked(b"tcb-registers", unsafe {
            tcb_write_registers_r(tcb, worker_entry as *const () as u64, worker.slot.stack.end() - 8, args)
        })?;
        let resources = unsafe {
            WorkerBootstrapResources::from_native_owned(
                tcb,
                endpoint,
                worker.bootstrap_sc.ok_or(ProbeFailure::at(b"sc-owner", 0))?,
                ipc_frame,
                reply,
            )
        };
        worker.bootstrap = Some(
            PassiveWorkerBootstrap::new(resources)
                .map_err(|_| ProbeFailure::at(b"bootstrap-owner", u64::MAX))?,
        );

        // `tcb_resume_r` belongs to hosted-thread admission and rejects this owned sibling.
        // The private checked wrapper below is authorized only by this retained TCB field.
        checked(b"tcb-resume", unsafe { resume_owned_tcb(tcb) })?;
        // Resume may let the worker reach its private Recv before this one-shot handoff.
        // YieldTo then reports IllegalOperation because the target is already blocked; only
        // the checked unbind ACK below proves the blocked receive and offered Reply.
        let yield_status = sel4_rt::tcb_yield_to(tcb);
        crate::print_str(if production {
            b"[executor-production-worker] yield-status="
        } else {
            b"[executor-passive-worker-probe] yield-status="
        });
        crate::print_hex_u64(yield_status);
        crate::print_str(b"\n");
        worker.bootstrap
            .as_mut()
            .ok_or(ProbeFailure::at(b"bootstrap-missing", 0))?
            .try_unbind(&mut NativeUnbinder)
            .map_err(|error| match error {
                BootstrapError::UnbindIndeterminate(status) => {
                    ProbeFailure::at(b"checked-unbind", status)
                }
                _ => ProbeFailure::at(b"checked-unbind-state", u64::MAX),
            })?;
        let passive = worker
            .bootstrap
            .as_mut()
            .and_then(PassiveWorkerBootstrap::take_passive)
            .ok_or(ProbeFailure::at(b"passive-owner", 0))?;
        worker.passive = Some(passive);
        worker.ready = Some(
            unsafe {
                worker.passive
                    .as_mut()
                    .ok_or(ProbeFailure::at(b"passive-missing", 0))?
                    .issue_ready_proof_once(executor, identity, tcb)
            }
            .map_err(|_| ProbeFailure::at(b"ready-proof", u64::MAX))?,
        );
        #[cfg(feature = "executor-fault-supervisor-probe")]
        if production {
            // Keep the worker Unready until its separate fault receiver is installed. A
            // refusal retains both owners, with no path to the run token or a second attempt.
            self.production_supervisor = Some(
                NativeSupervisorProbe::try_new_boxed_for_worker(1)?
            );
            let supervisor = self.production_supervisor.as_mut()
                .ok_or(ProbeFailure::at(b"production-supervisor-owner", 0))?;
            let fault_endpoint = unsafe { supervisor.prepare(tcb, reply)? };
            checked(b"production-fault-handler", unsafe {
                tcb_set_space_r(tcb, fault_endpoint, 0, 0)
            })?;
        }
        let fs_ack = worker.fs_ack.take().ok_or(ProbeFailure::at(b"fs-proof", 0))?;
        let ready = worker
            .ready
            .take()
            .ok_or(ProbeFailure::at(b"ready-owner", 0))?;
        match self.table.activate_unready(
            self.root
                .as_ref()
                .ok_or(ProbeFailure::at(b"root-owner", 0))?,
            fs_ack,
            ready,
        ) {
            Ok(activated) if activated == executor => Ok(()),
            Ok(_) => Err(ProbeFailure::at(b"activate-identity", u64::MAX)),
            Err((_, fs_ack, ready)) => {
                worker.fs_ack = Some(fs_ack);
                worker.ready = Some(ready);
                Err(ProbeFailure::at(b"activate-unready", u64::MAX))
            }
        }
    }

    /// Give one private Call to the admitted worker. Its deliberate #UD must be delivered to
    /// the separately scheduled supervisor, which suspends that exact worker and returns the
    /// terminal on a pre-existing alias of the worker's Reply. Every owner stays published after
    /// the terminal: this proof does not retire or reuse either Reply or the faulted TCB.
    ///
    /// # Safety
    /// Root is the sole accessor of this published owner. The worker has completed `start`,
    /// and the native CSpace/VSpace and root TCB are still live.
    #[cfg(feature = "executor-fault-supervisor-probe")]
    pub(crate) unsafe fn prove_supervised_fault_once(&mut self) -> Result<(), ProbeFailure> {
        if core::mem::replace(&mut self.fault_probe_attempted, true) {
            return Err(ProbeFailure::at(b"fault-probe-already-attempted", u64::MAX));
        }
        let _durable = allocator::enter_durable();
        let executor = self.diagnostic
            .executor
            .ok_or(ProbeFailure::at(b"fault-executor-owner", 0))?;
        if self.table.state(executor) != Ok(ExecutorState::Idle) {
            return Err(ProbeFailure::at(b"fault-worker-not-idle", 0));
        }
        let tcb = self.diagnostic
            .tcb
            .as_ref()
            .ok_or(ProbeFailure::at(b"fault-tcb-owner", 0))?
            .value();
        let identity = self.diagnostic
            .identity
            .ok_or(ProbeFailure::at(b"fault-tcb-identity", 0))?;
        let anchor = self.diagnostic
            .anchor
            .ok_or(ProbeFailure::at(b"fault-local-anchor", 0))?;
        let endpoint = self.diagnostic
            .endpoint
            .as_ref()
            .ok_or(ProbeFailure::at(b"fault-endpoint-owner", 0))?
            .value();
        let worker_reply = self.diagnostic
            .reply
            .as_ref()
            .ok_or(ProbeFailure::at(b"fault-reply-owner", 0))?
            .value();

        // Publish the stable subowner before it acquires a capability. Its entry argument is an
        // immutable boxed value and never borrows this owner while root blocks in the Call.
        self.supervisor = Some(NativeSupervisorProbe::try_new_boxed()?);
        let supervisor = self
            .supervisor
            .as_mut()
            .ok_or(ProbeFailure::at(b"fault-supervisor-owner", 0))?;
        let fault_endpoint = unsafe { supervisor.prepare(tcb, worker_reply)? };
        checked(b"fault-handler-install", unsafe {
            tcb_set_space_r(tcb, fault_endpoint, 0, 0)
        })?;
        let fault_reply = supervisor
            .fault_reply()
            .ok_or(ProbeFailure::at(b"fault-supervisor-reply", 0))?;
        let alias = supervisor
            .root_reply_alias()
            .ok_or(ProbeFailure::at(b"fault-root-reply-alias", 0))?;

        let mut root_replies = RootReplySlotTable::new(1)
            .map_err(|_| ProbeFailure::at(b"fault-root-reply-table", u64::MAX))?;
        let mut supervisor_replies = RootReplySlotTable::new(1)
            .map_err(|_| ProbeFailure::at(b"fault-supervisor-reply-table", u64::MAX))?;
        let root_reply = root_replies
            .insert_free(worker_reply)
            .map_err(|_| ProbeFailure::at(b"fault-root-reply-id", u64::MAX))?;
        let supervisor_reply = supervisor_replies
            .insert_free(fault_reply)
            .map_err(|_| ProbeFailure::at(b"fault-supervisor-reply-id", u64::MAX))?;
        // Conservatively claim both Replies before the Call can bind them. The Used state
        // prevents reuse even if either following native effect is uncertain.
        root_replies
            .mark_used(root_reply)
            .map_err(|_| ProbeFailure::at(b"fault-root-reply-claim", u64::MAX))?;
        supervisor_replies
            .mark_used(supervisor_reply)
            .map_err(|_| ProbeFailure::at(b"fault-supervisor-reply-claim", u64::MAX))?;
        self.fault_call = Some(FaultCallOwner {
            _root_replies: root_replies,
            _supervisor_replies: supervisor_replies,
            root_reply,
            supervisor_reply,
            run: None,
            refused_report: None,
        });

        // All fallible physical-identity checks precede the run-token transfer. If the later
        // pure binding refuses, an ordinary idle yield restores the token before any native Call.
        let claim = self
            .locals
            .physical_claim_for(anchor, identity, executor)
            .map_err(|_| ProbeFailure::at(b"fault-physical-claim", u64::MAX))?;
        let binding = unsafe {
            ExecutorFaultBinding::from_native(executor, claim, root_reply, supervisor_reply)
        }
        .ok_or(ProbeFailure::at(b"fault-binding-owner", 0))?;

        let token = self
            .root
            .take()
            .ok_or(ProbeFailure::at(b"fault-root-token", 0))?;
        let run = match self.table.resume(token, ExecutorResume::Unrouted) {
            Ok(run) => run,
            Err((_, token)) => {
                self.root = Some(token);
                return Err(ProbeFailure::at(b"fault-run-resume", u64::MAX));
            }
        };
        self.fault_call
            .as_mut()
            .ok_or(ProbeFailure::at(b"fault-call-owner", 0))?
            .run = Some(run);
        let run = self
            .fault_call
            .as_ref()
            .and_then(|owner| owner.run.as_ref())
            .ok_or(ProbeFailure::at(b"fault-run-owner", 0))?;
        if self.table.bind_fault(run, binding).is_err() {
            let run = self
                .fault_call
                .as_mut()
                .and_then(|owner| owner.run.take())
                .ok_or(ProbeFailure::at(b"fault-run-owner", 0))?;
            match self.table.accept_yield(run, ExecutorYield::Idle) {
                Ok(token) => self.root = Some(token),
                Err((_, run)) => {
                    self.fault_call
                        .as_mut()
                        .ok_or(ProbeFailure::at(b"fault-call-owner", 0))?
                        .run = Some(run);
                }
            }
            return Err(ProbeFailure::at(b"fault-binding", u64::MAX));
        }

        let (reply_info, reply_status) = unsafe { call_worker_once(endpoint) };
        crate::print_str(b"[executor-fault-supervisor-probe] terminal-info=");
        crate::print_hex_u64(reply_info);
        crate::print_str(b" status=");
        crate::print_hex_u64(reply_status);
        crate::print_str(b"\n");
        // The checked terminal and both now-free physical Reply bindings are required before
        // acknowledging the fault. A mismatched return quarantines the run, never yields it.
        let exact = reply_info == TERMINAL_INFO
            && reply_status == TERMINAL_STATUS
            && unsafe { sel4_rt::reply_binding::query(1, alias) }
                == Ok(sel4_rt::reply_binding::Binding::Free)
            && unsafe { sel4_rt::reply_binding::query(tcb, fault_reply) }
                == Ok(sel4_rt::reply_binding::Binding::Free);
        let report = if exact {
            unsafe {
                ExecutorFaultReport::acknowledged(
                    executor,
                    identity,
                    tcb,
                    root_reply,
                    supervisor_reply,
                )
            }
        } else {
            unsafe {
                ExecutorFaultReport::uncertain(
                    executor,
                    identity,
                    tcb,
                    root_reply,
                    supervisor_reply,
                )
            }
        }
        .ok_or(ProbeFailure::at(b"fault-report-owner", 0))?;
        let run = self
            .fault_call
            .as_mut()
            .and_then(|owner| owner.run.take())
            .ok_or(ProbeFailure::at(b"fault-run-owner", 0))?;
        match self.table.accept_fault_terminal(run, report) {
            Ok(token) => self.root = Some(token),
            Err((_, run, report)) => {
                let owner = self
                    .fault_call
                    .as_mut()
                    .ok_or(ProbeFailure::at(b"fault-call-owner", 0))?;
                owner.run = Some(run);
                owner.refused_report = Some(report);
                return Err(ProbeFailure::at(b"fault-terminal-uncertain", reply_info));
            }
        }
        if self.table.state(executor) != Ok(ExecutorState::Faulted) {
            return Err(ProbeFailure::at(b"fault-state", u64::MAX));
        }
        Ok(())
    }
}

#[cfg(feature = "executor-fault-supervisor-probe")]
unsafe fn call_worker_once(endpoint: u64) -> (u64, u64) {
    let info: u64;
    let status: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rdx") SYS_CALL as u64 => _,
            inout("rdi") endpoint => _,
            inout("rsi") (0x382u64 << 12) => info,
            inout("r10") 0u64 => status,
            inout("r8") 0u64 => _,
            inout("r9") 0u64 => _,
            in("r12") 0u64,
            in("r13") 0u64,
            lateout("r15") _, lateout("rax") _, lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
    }
    (info, status)
}

struct NativeUnbinder;

// SAFETY: only an exact zero-word checked kernel reply reports Acknowledged. Any other result
// retains the bootstrap owner in its sticky uncertain state and is never replayed.
unsafe impl BootstrapUnbindIo for NativeUnbinder {
    fn unbind_bootstrap_sc(
        &mut self,
        sc: u64,
        tcb: u64,
        endpoint: u64,
        reply_cap: u64,
    ) -> UnbindOutcome {
        let reply: u64;
        unsafe {
            core::arch::asm!(
                "syscall",
                inout("rdx") SYS_CALL as u64 => _,
                inout("rdi") sc => _,
                inout("rsi") (LBL_SCHED_CONTEXT_UNBIND_PASSIVE_WORKER << 12) | 3 => reply,
                inout("r10") tcb => _,
                inout("r8") endpoint => _,
                inout("r9") reply_cap => _,
                in("r12") 0u64,
                in("r13") 0u64,
                lateout("r15") _, lateout("rax") _, lateout("rcx") _, lateout("r11") _,
                options(nostack),
            );
        }
        if reply == 0 {
            UnbindOutcome::Acknowledged
        } else {
            UnbindOutcome::Indeterminate(reply)
        }
    }
}

extern "C" fn worker_entry(args: *const WorkerEntryArgs) -> ! {
    let selected: *const ExecutorLocal;
    unsafe {
        core::arch::asm!(
            "mov {}, qword ptr fs:[0]",
            out(reg) selected,
            options(nostack, preserves_flags),
        );
    }
    let args = unsafe { &*args };
    if selected != args.expected_local || local() as *const ExecutorLocal != args.expected_local {
        unsafe { core::arch::asm!("ud2", options(noreturn)) }
    }
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rdx") SYS_RECV as u64,
            inout("rdi") args.endpoint => _,
            in("r12") args.reply,
            in("r13") 0u64,
            lateout("rsi") _, lateout("r10") _, lateout("r8") _, lateout("r9") _,
            lateout("r15") _, lateout("rax") _, lateout("rcx") _, lateout("r11") _,
            options(nostack),
        );
        // This proof-only worker has no dispatch contract. A delivered message is a violation.
        core::arch::asm!("ud2", options(noreturn))
    }
}
