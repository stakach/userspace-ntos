//! Executor-local context: the ambient state of one thread running executive code.
//!
//! Each field is read without naming an owner ("the IPC buffer", "the hosted Call being
//! served"), which is only sound while one thread runs executive code. Stage 1 of issue #382
//! adds passive executor TCBs, and each then needs a private copy of exactly this state.
//!
//! There is one executor today, the root TCB, and therefore one block. [`local`] is the single
//! place that changes when an executor gets its own: the block's address is then published
//! through the TCB's FS base and read back here. Resolve [`local`] at each use. The reference
//! belongs to the calling executor and must not be stored in shared state.
//!
//! The block is an ordinary image static, with the same mapping as the statics it replaces:
//! writable in the root executive and visible read-only, as root's values, to spawned components
//! that share the image. State a spawned component must write does not belong here.

use core::ops::Deref;
use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

pub(crate) const RECEIVE_TRACE_DEPTH: usize = 8;

/// Diagnostic-only stack of entered shared receives. The route is published last and cleared
/// first, so a sampled frame never claims authority over a Reply or provider continuation.
pub(crate) struct ReceiveTraceFrame {
    pub(crate) route: AtomicU64,
    pub(crate) tcb: AtomicU64,
    pub(crate) reply: AtomicU64,
}

impl ReceiveTraceFrame {
    const fn new() -> Self {
        Self {
            route: AtomicU64::new(0),
            tcb: AtomicU64::new(0),
            reply: AtomicU64::new(0),
        }
    }
}

/// Fields are atomics so the block is `Sync` without `unsafe`. Exactly one executor runs at a
/// time, and each call site keeps the ordering it used before the state moved here.
#[repr(C)]
pub(crate) struct ExecutorLocal {
    /// `%fs:0` holds this exact block's stable address. Install before publishing the block as
    /// a TCB's FS base; retain a worker's boxed block until that physical TCB is retired.
    pub(crate) self_anchor: AtomicPtr<ExecutorLocal>,
    /// VA of this executor's seL4 IPC buffer. Message registers 4 and above, and the extra-cap
    /// words of an invocation, are staged here. Zero until boot publishes the BootInfo address.
    pub(crate) ipc_buffer: AtomicU64,
    /// Reply object slot that identifies the hosted Call currently delivered to this executor.
    /// Zero means no hosted Call is delivered.
    ///
    /// The kernel has a single per-TCB `reply_to` stash that `finish_call` overwrites with the
    /// latest caller, so each caller is bound to its own `Cap::Reply` (receive with r12, then
    /// send on that cap). That resumes exactly the intended caller when a provider faults in the
    /// middle of another caller's syscall. Shared ingress owns the component Replies and rotates
    /// them independently of this slot.
    pub(crate) reply_main_slot: AtomicU64,
    /// Live `ComponentSchedulerScope` guards on this executor's stack. Nonzero means the
    /// executor is inside a retained component invocation.
    pub(crate) scheduler_depth: AtomicU64,
    /// Live shared pump receives on this executor's stack. Above one, the innermost receive
    /// was entered inside another pump's receive, which keeps the root off its own boundary.
    pub(crate) receive_depth: AtomicU64,
    /// Read-only evidence of the actual LIFO receive chain, bounded independently of depth.
    pub(crate) receive_trace: [ReceiveTraceFrame; RECEIVE_TRACE_DEPTH],
    /// Bounded NtUserRegisterHotKey diagnostics emitted by this executor.
    pub(crate) hotkey_registration_traces: AtomicU64,
    /// Bounded fatal dialog text receipts from this executor's Win32k input capture.
    pub(crate) fatal_dialog_text_receipts: AtomicU64,
    /// Index of the hosted process whose event this executor is serving. Client copy-in and
    /// copy-out resolve user addresses against this process. The service loop sets it, with
    /// [`Self::scratch_base`], at the top of each iteration. A redrive that completes another
    /// thread's parked work switches both to that thread's process and restores them afterwards.
    pub(crate) client_pi: AtomicU64,
    /// Base of that process's demand scratch window: the executive VA range where its frames are
    /// aliased for a copy. It always belongs to the process named by [`Self::client_pi`].
    pub(crate) scratch_base: AtomicU64,
    /// This executor's rewindable allocation lane.
    pub(crate) transient: TransientLane,
}

/// An executor's rewindable allocation lane: the arena the allocator routes to while a
/// `TransientAllocScope` guard is live on that executor's stack.
///
/// Scopes rewind the mark in LIFO order, which holds only for the guards of one stack, so the
/// mark and the scope depth belong to the executor and not to the heap. Only the root executive
/// has a lane; the allocator checks that before it reads this state. There is one executor
/// today, so its lane spans the whole transient reservation at the top of the root heap. Each
/// further executor needs its own range of that reservation, recorded here beside the mark.
pub(crate) struct TransientLane {
    /// Bytes consumed downward from the top of the lane: the rewind mark.
    pub(crate) used: AtomicUsize,
    /// Live transient scopes on this executor's stack. Zero routes allocations to the durable
    /// heap, which is also how a durable scope suspends an outer transient one.
    pub(crate) depth: AtomicUsize,
    /// Peak of [`Self::used`], reported by the heap census.
    pub(crate) high_water: AtomicUsize,
}

impl ExecutorLocal {
    pub(crate) const fn new() -> Self {
        Self {
            self_anchor: AtomicPtr::new(core::ptr::null_mut()),
            ipc_buffer: AtomicU64::new(0),
            reply_main_slot: AtomicU64::new(0),
            scheduler_depth: AtomicU64::new(0),
            receive_depth: AtomicU64::new(0),
            receive_trace: [const { ReceiveTraceFrame::new() }; RECEIVE_TRACE_DEPTH],
            hotkey_registration_traces: AtomicU64::new(0),
            fatal_dialog_text_receipts: AtomicU64::new(0),
            // Before the first event is admitted, boot work addresses the first hosted process.
            client_pi: AtomicU64::new(0),
            scratch_base: AtomicU64::new(crate::SMSS_SCRATCH_BASE),
            transient: TransientLane {
                used: AtomicUsize::new(0),
                depth: AtomicUsize::new(0),
                high_water: AtomicUsize::new(0),
            },
        }
    }

    /// Prepare the first word before a native SetTLSBase invocation can select this block.
    ///
    /// # Safety
    /// This address must remain stable and mapped for the entire lifetime of every TCB that may
    /// select it. Static blocks satisfy this; a worker block must be owned in its stable Box
    /// until exact physical TCB retirement.
    pub(crate) unsafe fn initialize_self_anchor(&self) {
        self.self_anchor
            .store(self as *const Self as *mut Self, Ordering::Release);
    }
}

const _: () = assert!(core::mem::offset_of!(ExecutorLocal, self_anchor) == 0);

/// The root executor's block.
static ROOT_EXECUTOR_LOCAL: ExecutorLocal = ExecutorLocal::new();

/// Install an executor-local block on the current root TCB. The invocation updates both the
/// live FS base and the TCB's saved base, so context switches preserve the same selection.
#[cfg(feature = "executor-local-fs-probe")]
#[inline]
fn select_current_tcb(block: &'static ExecutorLocal) -> bool {
    // Root boot CSpace slot 1 is the current root TCB; selector 0 sets FS, leaving GS for TEB.
    unsafe { block.initialize_self_anchor() };
    let reply: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rdx") crate::SYS_CALL as u64,
            in("rdi") 1u64,
            inout("rsi") crate::LBL_TCB_SET_TLS_BASE << 12 => reply,
            in("r10") block as *const _ as u64,
            in("r8") 0u64,
            in("r9") 0u64,
            in("r12") 0u64,
            in("r13") 0u64,
            lateout("rax") _,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack, preserves_flags),
        );
    }
    reply == 0
}

#[cfg(feature = "executor-local-fs-probe")]
pub(crate) fn install_root() -> bool {
    select_current_tcb(&ROOT_EXECUTOR_LOCAL)
}

#[cfg(feature = "executor-local-fs-probe")]
pub(crate) fn probe_fs_selection(other: &'static ExecutorLocal) -> bool {
    let selected = select_current_tcb(other);
    let observed_other = selected && core::ptr::eq(local(), other);
    // Restore the root TCB before any result handling, including a failed selection.
    let restored = select_current_tcb(&ROOT_EXECUTOR_LOCAL);
    let observed_root = restored && core::ptr::eq(local(), &ROOT_EXECUTOR_LOCAL);
    selected && observed_other && restored && observed_root
}

/// The calling executor's block.
#[inline(always)]
pub(crate) fn local() -> &'static ExecutorLocal {
    #[cfg(feature = "executor-local-fs-probe")]
    {
        let selected: *const ExecutorLocal;
        unsafe {
            core::arch::asm!(
                "mov {}, qword ptr fs:[0]",
                out(reg) selected,
                options(nostack, preserves_flags),
            );
        }
        if selected.is_null() {
            crate::print_str(b"[executor-local] missing FS self anchor; parking executor\n");
            crate::park();
        }
        // The native SetTLSBase ACK and retained static/boxed owner keep this address live.
        return unsafe { &*selected };
    }
    #[cfg(not(feature = "executor-local-fs-probe"))]
    {
        &ROOT_EXECUTOR_LOCAL
    }
}

/// Old-path name for [`ExecutorLocal::reply_main_slot`]. The crate root re-exports it so the
/// service loop and syscall handlers compile unchanged until the loop hoist ports them. Every
/// use still resolves the calling executor's block. New code names the field through [`local`].
pub(crate) struct ReplyMainSlot;

impl Deref for ReplyMainSlot {
    type Target = AtomicU64;

    #[inline(always)]
    fn deref(&self) -> &AtomicU64 {
        &local().reply_main_slot
    }
}

pub(crate) const REPLY_MAIN_SLOT: ReplyMainSlot = ReplyMainSlot;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_boxed_probe_place_distinct_self_pointers_at_fs_offset_zero() {
        assert_eq!(core::mem::offset_of!(ExecutorLocal, self_anchor), 0);
        assert_eq!(
            core::mem::size_of::<AtomicPtr<ExecutorLocal>>(),
            core::mem::size_of::<usize>()
        );
        let probe = Box::new(ExecutorLocal::new());
        unsafe {
            ROOT_EXECUTOR_LOCAL.initialize_self_anchor();
            probe.initialize_self_anchor();
        }
        let root = &ROOT_EXECUTOR_LOCAL as *const ExecutorLocal as *mut ExecutorLocal;
        let probe_address = &*probe as *const ExecutorLocal as *mut ExecutorLocal;
        assert_eq!(ROOT_EXECUTOR_LOCAL.self_anchor.load(Ordering::Acquire), root);
        assert_eq!(probe.self_anchor.load(Ordering::Acquire), probe_address);
        assert_ne!(root, probe_address);
    }

    #[test]
    fn boxed_worker_keeps_its_self_pointer_when_the_owner_moves() {
        let worker = Box::new(ExecutorLocal::new());
        assert!(worker.self_anchor.load(Ordering::Acquire).is_null());
        unsafe { worker.initialize_self_anchor() };
        let address = &*worker as *const ExecutorLocal as *mut ExecutorLocal;
        let owner = worker;
        assert_eq!(owner.self_anchor.load(Ordering::Acquire), address);
        assert_eq!(&*owner as *const ExecutorLocal as *mut ExecutorLocal, address);
    }
}
