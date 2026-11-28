//! Retained, proof-only fault supervisor for one native executor Call.
//!
//! The root owns this value and every native resource it creates. The supervisor has its own
//! scheduling context, stack, IPC buffer, FS payload, fault receive Reply, and an alias of the
//! worker's outer Reply. Its entry point reads only immutable arguments: root may be blocked on
//! the worker Call while the supervisor handles a fault. No resource is reused after a failed or
//! uncertain native effect.

use alloc::boxed::Box;

use sel4_rt::reply_binding::{self, Binding};

use super::native_probe_resources::{
    checked, resume_owned_tcb, retype_owned, try_box, OwnedCap, ProbeFailure,
};
use super::ExecutorLocal;
use crate::*;

const SUPERVISOR_SLOT: nt_executive_layout::root::ExecutorWorkerSlot =
    nt_executive_layout::root::EXECUTOR_FAULT_SUPERVISOR;
const STACK_PAGES: usize = (SUPERVISOR_SLOT.stack.len / nt_executive_layout::PAGE) as usize;
const ROOT_TCB: u64 = 1; // Fixed root TCB boot capability, not a process identity.
const FAULT_INFO: u64 = (3 << 12) | 5; // x86 UserException, five message words.
const ILLEGAL_INSTRUCTION: u64 = 6; // x86 #UD exception number.

/// The terminal is accepted only after root receives both exact words on its retained Reply.
pub(crate) const TERMINAL_INFO: u64 = (0x382 << 12) | 1;
pub(crate) const TERMINAL_STATUS: u64 = 0xc000_001d; // STATUS_ILLEGAL_INSTRUCTION.
const UNCERTAIN_STATUS: u64 = 0xc000_0001; // A distinct terminal; root must reject it.

const _: () = {
    assert!(SUPERVISOR_SLOT.stack.base == SUPERVISOR_SLOT.guard.end());
    assert!(SUPERVISOR_SLOT.ipc.base >= SUPERVISOR_SLOT.stack.end() + 0x1000);
    assert!(SUPERVISOR_SLOT.ipc.end() <= nt_executive_layout::root::EXECUTOR_WORKERS.end());
};

struct SupervisorEntryArgs {
    fault_endpoint: u64,
    fault_reply: u64,
    root_reply_alias: u64,
    worker_tcb: u64,
    expected_local: *const ExecutorLocal,
}

/// A single retained native construction. Root publishes its containing worker owner before
/// `prepare`; the supervisor never dereferences that owner after root enters the blocking Call.
#[must_use = "retain supervisor capabilities and Reply aliases until exact native retirement"]
pub(crate) struct NativeSupervisorProbe {
    slot: nt_executive_layout::root::ExecutorWorkerSlot,
    attempted: bool,
    tcb: Option<OwnedCap>,
    fault_endpoint: Option<OwnedCap>,
    fault_reply: Option<OwnedCap>,
    root_reply_alias: Option<u64>,
    ipc_frame: Option<OwnedCap>,
    stack_frames: [Option<OwnedCap>; STACK_PAGES],
    sched_context: Option<u64>,
    local: Option<Box<ExecutorLocal>>,
    entry_args: Option<Box<SupervisorEntryArgs>>,
}

impl NativeSupervisorProbe {
    pub(crate) fn try_new_boxed() -> Result<Box<Self>, ProbeFailure> {
        Self::try_new_boxed_for_worker(0)
    }

    pub(crate) fn try_new_boxed_for_worker(worker_index: usize) -> Result<Box<Self>, ProbeFailure> {
        let _durable = allocator::enter_durable();
        let slot = nt_executive_layout::root::executor_fault_supervisor_slot(worker_index)
            .ok_or(ProbeFailure::at(b"supervisor-address-slot", worker_index as u64))?;
        try_box(
            Self {
                slot,
                attempted: false,
                tcb: None,
                fault_endpoint: None,
                fault_reply: None,
                root_reply_alias: None,
                ipc_frame: None,
                stack_frames: [const { None }; STACK_PAGES],
                sched_context: None,
                local: None,
                entry_args: None,
            },
            b"supervisor-owner-alloc",
        )
    }

    /// Prepare an independently scheduled receiver for the worker's fault and return its
    /// capability-owned endpoint. Root configures the exact worker TCB's fault handler only
    /// after this returns. This attempt is one-shot even if a native effect is uncertain.
    ///
    /// # Safety
    /// `worker_tcb` and `worker_reply` must be held by the stable root worker owner throughout
    /// this attempt and every later fault. Root must be the only accessor of this value here.
    pub(crate) unsafe fn prepare(
        &mut self,
        worker_tcb: u64,
        worker_reply: u64,
    ) -> Result<u64, ProbeFailure> {
        if core::mem::replace(&mut self.attempted, true) {
            return Err(ProbeFailure::at(b"supervisor-already-attempted", u64::MAX));
        }
        if worker_tcb == 0 || worker_reply == 0 {
            return Err(ProbeFailure::at(b"supervisor-worker-owner", 0));
        }
        let _durable = allocator::enter_durable();
        let tcb = unsafe { retype_owned(&mut self.tcb, OBJ_TCB, 0, true, b"supervisor-tcb")? };
        let fault_endpoint = unsafe {
            retype_owned(
                &mut self.fault_endpoint,
                OBJ_ENDPOINT,
                0,
                false,
                b"supervisor-fault-endpoint",
            )?
        };
        let fault_reply = unsafe {
            retype_owned(
                &mut self.fault_reply,
                OBJ_REPLY,
                0,
                false,
                b"supervisor-fault-reply",
            )?
        };
        // Record the alias slot before CNodeCopy; an uncertain copy is never replayed and the
        // slot stays with this owner even if the checked result is a refusal.
        let alias =
            try_alloc_slot().ok_or(ProbeFailure::at(b"supervisor-reply-alias-slot", u64::MAX))?;
        self.root_reply_alias = Some(alias);
        checked(b"supervisor-reply-alias-copy", unsafe {
            copy_cap_into_r(worker_reply, alias)
        })?;

        let ipc_frame = unsafe {
            retype_owned(
                &mut self.ipc_frame,
                OBJ_X86_4K_PAGE,
                PAGING_BITS,
                false,
                b"supervisor-ipc-frame",
            )?
        };
        for (index, slot) in self.stack_frames.iter_mut().enumerate() {
            let frame = unsafe {
                retype_owned(
                    slot,
                    OBJ_X86_4K_PAGE,
                    PAGING_BITS,
                    false,
                    b"supervisor-stack-frame",
                )?
            };
            let va = self.slot.stack.base + index as u64 * 0x1000;
            if !unsafe { ensure_executive_paging(va) } {
                return Err(ProbeFailure::at(b"supervisor-stack-paging", va));
            }
            checked(b"supervisor-stack-map", unsafe {
                page_map_r(frame, va, RW_NX, CAP_INIT_THREAD_VSPACE)
            })?;
        }
        if !unsafe { ensure_executive_paging(self.slot.ipc.base) } {
            return Err(ProbeFailure::at(b"supervisor-ipc-paging", self.slot.ipc.base));
        }
        checked(b"supervisor-ipc-map", unsafe {
            page_map_r(ipc_frame, self.slot.ipc.base, RW_NX, CAP_INIT_THREAD_VSPACE)
        })?;

        checked(b"supervisor-tcb-space", unsafe {
            tcb_set_space_r(tcb, 0, CAP_INIT_THREAD_CNODE, CAP_INIT_THREAD_VSPACE)
        })?;
        checked(b"supervisor-tcb-ipc", unsafe {
            tcb_set_ipc_buffer_r(tcb, self.slot.ipc.base, ipc_frame)
        })?;
        checked(b"supervisor-tcb-priority", unsafe {
            tcb_set_priority_r(tcb, 100)
        })?;
        self.sched_context = Some(
            unsafe { thread_sched_context::attach_sched_context(tcb) }
                .map_err(|status| ProbeFailure::at(b"supervisor-sc", status))?,
        );

        let local = try_box(ExecutorLocal::new(), b"supervisor-local-alloc")?;
        unsafe { local.initialize_self_anchor() };
        self.local = Some(local);
        let base = self
            .local
            .as_deref()
            .ok_or(ProbeFailure::at(b"supervisor-local-owner", 0))?
            as *const ExecutorLocal;
        let fs_result = unsafe { super::local::set_owned_tcb_fs_base(tcb, base) };
        if fs_result != 0 {
            return Err(ProbeFailure::at(b"supervisor-fs-install", fs_result));
        }

        self.entry_args = Some(try_box(
            SupervisorEntryArgs {
                fault_endpoint,
                fault_reply,
                root_reply_alias: alias,
                worker_tcb,
                expected_local: base,
            },
            b"supervisor-entry-alloc",
        )?);
        let args = self
            .entry_args
            .as_deref()
            .ok_or(ProbeFailure::at(b"supervisor-entry-owner", 0))?
            as *const SupervisorEntryArgs as u64;
        checked(b"supervisor-registers", unsafe {
            tcb_write_registers_r(
                tcb,
                supervisor_entry as *const () as u64,
                self.slot.stack.end() - 8,
                args,
            )
        })?;
        checked(b"supervisor-resume", unsafe { resume_owned_tcb(tcb) })?;
        // YieldTo is advisory: a blocked Recv may already make it report IllegalOperation.
        // The offered Reply, retained by this owner, is the checked readiness observation.
        let _ = sel4_rt::tcb_yield_to(tcb);
        if unsafe { reply_binding::query(tcb, fault_reply) } != Ok(Binding::Offered) {
            return Err(ProbeFailure::at(b"supervisor-not-receiving", u64::MAX));
        }
        Ok(fault_endpoint)
    }

    pub(crate) fn root_reply_alias(&self) -> Option<u64> {
        self.root_reply_alias
    }

    pub(crate) fn fault_reply(&self) -> Option<u64> {
        self.fault_reply.as_ref().map(OwnedCap::value)
    }

    pub(crate) fn tcb(&self) -> Option<u64> {
        self.tcb.as_ref().map(OwnedCap::value)
    }
}

fn log_failure(stage: &[u8], status: u64) {
    // The root is blocked during fault handling. Use the direct serial syscall rather than
    // borrowing root's shared line buffer from this independent supervisor TCB.
    sel4_rt::print_str(b"[executor-fault-supervisor-probe] FAIL stage=");
    sel4_rt::print_str(stage);
    sel4_rt::print_str(b" status=");
    sel4_rt::print_hex(status);
    sel4_rt::print_str(b"\n");
}

fn park_supervisor(endpoint: u64) -> ! {
    // Block without offering a Reply again. A duplicate event is never interpreted as a second
    // terminal; the owner retains all physical resources for later exact retirement.
    loop {
        let _ = unsafe { sel4_rt::ep_recv(endpoint) };
        log_failure(b"duplicate-fault", 0);
    }
}

fn send_terminal(args: &SupervisorEntryArgs, status: u64) -> ! {
    // SYS_SEND cannot acknowledge the native effect. Root accepts only a complete matching
    // Reply message; any uncertain send leaves this supervisor and both Reply owners intact.
    unsafe {
        sel4_rt::syscall5(
            sel4_rt::SYS_SEND,
            args.root_reply_alias,
            TERMINAL_INFO,
            status,
            0,
            0,
        );
    }
    park_supervisor(args.fault_endpoint)
}

fn refuse(args: &SupervisorEntryArgs, stage: &[u8], status: u64, outer_bound: bool) -> ! {
    log_failure(stage, status);
    if outer_bound {
        send_terminal(args, UNCERTAIN_STATUS)
    }
    park_supervisor(args.fault_endpoint)
}

extern "C" fn supervisor_entry(args: *const SupervisorEntryArgs) -> ! {
    let args = unsafe { &*args };
    let selected: *const ExecutorLocal;
    unsafe {
        core::arch::asm!(
            "mov {}, qword ptr fs:[0]",
            out(reg) selected,
            options(nostack, preserves_flags),
        );
    }
    if selected != args.expected_local {
        log_failure(b"supervisor-fs-selection", selected as u64);
        park_supervisor(args.fault_endpoint)
    }

    let (badge, info, exception_number): (u64, u64, u64);
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rdx") SYS_RECV as u64,
            inout("rdi") args.fault_endpoint => badge,
            in("r12") args.fault_reply,
            in("r13") 0u64,
            lateout("rsi") info,
            lateout("r10") _,
            lateout("r8") _,
            lateout("r9") _,
            lateout("r15") exception_number,
            lateout("rax") _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }

    let outer_bound = unsafe { reply_binding::query(ROOT_TCB, args.root_reply_alias) }
        == Ok(Binding::BoundToTarget);
    if !outer_bound {
        refuse(args, b"outer-reply-binding", 0, false)
    }
    if info != FAULT_INFO || badge != 0 || exception_number != ILLEGAL_INSTRUCTION {
        refuse(args, b"fault-shape", info, true)
    }
    if unsafe { reply_binding::query(args.worker_tcb, args.fault_reply) }
        != Ok(Binding::BoundToTarget)
    {
        refuse(args, b"inner-reply-binding", 0, true)
    }
    let suspend = unsafe { tcb_suspend_raw_r(args.worker_tcb) };
    if suspend != 0 {
        refuse(args, b"worker-suspend", suspend, true)
    }
    if unsafe { reply_binding::query(args.worker_tcb, args.fault_reply) } != Ok(Binding::Free) {
        refuse(args, b"inner-reply-retirement", 0, true)
    }
    if unsafe { reply_binding::query(ROOT_TCB, args.root_reply_alias) }
        != Ok(Binding::BoundToTarget)
    {
        refuse(args, b"outer-reply-after-suspend", 0, false)
    }
    send_terminal(args, TERMINAL_STATUS)
}
