//! Proof-only native passive executor for issue #382.
//!
//! This worker never receives production ingress or borrows `LoopState`. Its first receive is
//! private; the kernel's checked SC-unbind ACK is the only authority for publishing readiness.
//! Worker-specific caps and mapped frames remain with this owner on failure or an uncertain
//! effect. The root's paging-structure cache and failed SC construction rows retain their own
//! resources through their existing owners.

use alloc::boxed::Box;

use nt_component_suspension::executor_local::{
    ExecutorLocalRegistry, FsInstallAcknowledgement, PassiveWorkerReadyProof, PhysicalTcbClaim,
    TcbIdentity,
};
use nt_component_suspension::{ExecutorHandle, ExecutorTable, RunToken};
use nt_user_host::sched_context::{
    BootstrapError, BootstrapUnbindIo, PassiveWorker, PassiveWorkerBootstrap, UnbindOutcome,
    WorkerBootstrapResources,
};

use super::native_probe_resources::{
    checked, resume_owned_tcb, retype_owned, try_box, OwnedCap, ProbeFailure,
};
use super::{local, ExecutorLocal};
use crate::*;

const STACK_PAGES: usize = 8;
const WORKER_BASE: u64 = nt_executive_layout::root::EXECUTOR_WORKERS.base;
const STACK_FIRST: u64 = WORKER_BASE + 0x1000;
const STACK_TOP: u64 = STACK_FIRST + STACK_PAGES as u64 * 0x1000;
const IPC_VA: u64 = WORKER_BASE + 0x1_0000;
const _: () = {
    assert!(STACK_FIRST - WORKER_BASE == 0x1000);
    assert!(IPC_VA >= STACK_TOP + 0x1000);
    assert!(IPC_VA + 0x1000 <= nt_executive_layout::root::EXECUTOR_WORKERS.end());
};

struct WorkerEntryArgs {
    endpoint: u64,
    reply: u64,
    expected_local: *const ExecutorLocal,
}

/// Root publishes this heap-allocated value before its first native effect and retains the one
/// handle for eventual exact TCB retirement. The worker dereferences only its separately boxed
/// entry arguments and executor-local block, never a field of root's stack frame.
#[must_use = "retain worker caps and FS payload until exact physical TCB retirement"]
pub(crate) struct NativeWorkerProbe {
    table: ExecutorTable,
    root: RunToken,
    locals: ExecutorLocalRegistry<ExecutorLocal>,
    start_attempted: bool,
    executor: Option<ExecutorHandle>,
    identity: Option<TcbIdentity>,
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
}

impl NativeWorkerProbe {
    pub(crate) fn try_new_boxed() -> Result<Box<Self>, ProbeFailure> {
        let _durable = allocator::enter_durable();
        let (table, root) =
            ExecutorTable::try_new(1).map_err(|_| ProbeFailure::at(b"executor-table", u64::MAX))?;
        try_box(
            Self {
                table,
                root,
                locals: ExecutorLocalRegistry::new(),
                start_attempted: false,
                executor: None,
                identity: None,
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
        // A checked error can still leave a partially constructed native owner, and an
        // indeterminate effect must never be replayed. Reject every later attempt before it can
        // overwrite a retained cap, mapping, FS claim or bootstrap state.
        if core::mem::replace(&mut self.start_attempted, true) {
            return Err(ProbeFailure::at(b"start-already-attempted", u64::MAX));
        }
        let _durable = allocator::enter_durable();
        let tcb = unsafe { retype_owned(&mut self.tcb, OBJ_TCB, 0, true, b"tcb-retype")? };
        // Fresh root CSpace slots are never recycled by this owner. The retype above creates
        // one physical TCB and this identity is not reused before its confirmed retirement.
        let identity = TcbIdentity::new(tcb, 1);
        self.identity = Some(identity);
        let endpoint = unsafe {
            retype_owned(
                &mut self.endpoint,
                OBJ_ENDPOINT,
                0,
                false,
                b"endpoint-retype",
            )?
        };
        let reply = unsafe { retype_owned(&mut self.reply, OBJ_REPLY, 0, false, b"reply-retype")? };
        let ipc_frame = unsafe {
            retype_owned(
                &mut self.ipc_frame,
                OBJ_X86_4K_PAGE,
                PAGING_BITS,
                false,
                b"ipc-retype",
            )?
        };
        for (index, slot) in self.stack_frames.iter_mut().enumerate() {
            let frame = unsafe {
                retype_owned(slot, OBJ_X86_4K_PAGE, PAGING_BITS, false, b"stack-retype")?
            };
            let va = STACK_FIRST + index as u64 * 0x1000;
            if !unsafe { ensure_executive_paging(va) } {
                return Err(ProbeFailure::at(b"stack-paging", va));
            }
            checked(b"stack-map", unsafe {
                page_map_r(frame, va, RW_NX, CAP_INIT_THREAD_VSPACE)
            })?;
        }
        // The pages immediately below and above the mapped stack remain unmapped guards.
        if !unsafe { ensure_executive_paging(IPC_VA) } {
            return Err(ProbeFailure::at(b"ipc-paging", IPC_VA));
        }
        checked(b"ipc-map", unsafe {
            page_map_r(ipc_frame, IPC_VA, RW_NX, CAP_INIT_THREAD_VSPACE)
        })?;

        checked(b"tcb-space", unsafe {
            tcb_set_space_r(tcb, 0, CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE)
        })?;
        checked(b"tcb-ipc", unsafe {
            tcb_set_ipc_buffer_r(tcb, IPC_VA, ipc_frame)
        })?;
        checked(b"tcb-priority", unsafe { tcb_set_priority_r(tcb, 100) })?;
        self.bootstrap_sc = Some(
            unsafe { thread_sched_context::attach_sched_context(tcb) }
                .map_err(|status| ProbeFailure::at(b"bootstrap-sc", status))?,
        );

        let executor = self
            .table
            .register_unready(&self.root)
            .map_err(|_| ProbeFailure::at(b"register-unready", u64::MAX))?;
        self.executor = Some(executor);
        let payload = try_box(ExecutorLocal::new(), b"local-alloc")?;
        unsafe { payload.initialize_self_anchor() };
        self.unbound_local = Some(payload);
        self.unbound_claim = Some(
            unsafe { PhysicalTcbClaim::new(identity, tcb) }
                .map_err(|_| ProbeFailure::at(b"tcb-claim", u64::MAX))?,
        );
        let payload = self
            .unbound_local
            .take()
            .ok_or(ProbeFailure::at(b"local-owner", 0))?;
        let claim = self
            .unbound_claim
            .take()
            .ok_or(ProbeFailure::at(b"tcb-owner", 0))?;
        let anchor = match self
            .locals
            .bind_native(&self.table, executor, claim, payload)
        {
            Ok(anchor) => anchor,
            Err((_, payload, claim)) => {
                self.unbound_local = Some(payload);
                self.unbound_claim = Some(claim);
                return Err(ProbeFailure::at(b"local-bind", u64::MAX));
            }
        };
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
        self.fs_ack = Some(
            unsafe { self.locals.acknowledge_fs_install(attempt) }
                .map_err(|_| ProbeFailure::at(b"fs-ack", u64::MAX))?,
        );

        self.entry_args = Some(try_box(
            WorkerEntryArgs {
                endpoint,
                reply,
                expected_local: base,
            },
            b"entry-alloc",
        )?);
        let args = self
            .entry_args
            .as_deref()
            .ok_or(ProbeFailure::at(b"entry-owner", 0))?
            as *const WorkerEntryArgs as u64;
        checked(b"tcb-registers", unsafe {
            tcb_write_registers_r(tcb, worker_entry as *const () as u64, STACK_TOP - 8, args)
        })?;
        let resources = unsafe {
            WorkerBootstrapResources::from_native_owned(
                tcb,
                endpoint,
                self.bootstrap_sc.ok_or(ProbeFailure::at(b"sc-owner", 0))?,
                ipc_frame,
                reply,
            )
        };
        self.bootstrap = Some(
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
        crate::print_str(b"[executor-passive-worker-probe] yield-status=");
        crate::print_hex_u64(yield_status);
        crate::print_str(b"\n");
        self.bootstrap
            .as_mut()
            .ok_or(ProbeFailure::at(b"bootstrap-missing", 0))?
            .try_unbind(&mut NativeUnbinder)
            .map_err(|error| match error {
                BootstrapError::UnbindIndeterminate(status) => {
                    ProbeFailure::at(b"checked-unbind", status)
                }
                _ => ProbeFailure::at(b"checked-unbind-state", u64::MAX),
            })?;
        let passive = self
            .bootstrap
            .as_mut()
            .and_then(PassiveWorkerBootstrap::take_passive)
            .ok_or(ProbeFailure::at(b"passive-owner", 0))?;
        self.passive = Some(passive);
        self.ready = Some(
            unsafe {
                self.passive
                    .as_mut()
                    .ok_or(ProbeFailure::at(b"passive-missing", 0))?
                    .issue_ready_proof_once(executor, identity, tcb)
            }
            .map_err(|_| ProbeFailure::at(b"ready-proof", u64::MAX))?,
        );
        let fs_ack = self.fs_ack.take().ok_or(ProbeFailure::at(b"fs-proof", 0))?;
        let ready = self
            .ready
            .take()
            .ok_or(ProbeFailure::at(b"ready-owner", 0))?;
        match self.table.activate_unready(&self.root, fs_ack, ready) {
            Ok(activated) if activated == executor => Ok(()),
            Ok(_) => Err(ProbeFailure::at(b"activate-identity", u64::MAX)),
            Err((_, fs_ack, ready)) => {
                self.fs_ack = Some(fs_ack);
                self.ready = Some(ready);
                Err(ProbeFailure::at(b"activate-unready", u64::MAX))
            }
        }
    }
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
