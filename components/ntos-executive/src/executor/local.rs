//! Executor-local context: the ambient state of one thread running executive code.
//!
//! Each field is read without naming an owner ("the IPC buffer", "the hosted Call being
//! served"), which is only sound while one thread runs executive code. Stage 1 of issue #382
//! adds passive executor TCBs, and each then needs a private copy of exactly this state.
//!
//! There is one executor today, the root TCB, and therefore one block. [`local`] is the single
//! place that changes when an executor gets its own: the block's address is then published
//! through the TCB's gs base and read back here. Resolve [`local`] at each use. The reference
//! belongs to the calling executor and must not be stored in shared state.
//!
//! The block is an ordinary zero-initialised image static, with the same mapping as the statics
//! it replaces: writable in the root executive and visible read-only, as root's values, to
//! spawned components that share the image. State a spawned component must write does not
//! belong here.

use core::ops::Deref;
use core::sync::atomic::AtomicU64;

/// Fields are atomics so the block is `Sync` without `unsafe`. Exactly one executor runs at a
/// time, and each call site keeps the ordering it used before the state moved here.
pub(crate) struct ExecutorLocal {
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
}

impl ExecutorLocal {
    const fn new() -> Self {
        Self {
            ipc_buffer: AtomicU64::new(0),
            reply_main_slot: AtomicU64::new(0),
            scheduler_depth: AtomicU64::new(0),
        }
    }
}

/// The root executor's block.
static ROOT_EXECUTOR_LOCAL: ExecutorLocal = ExecutorLocal::new();

/// The calling executor's block.
#[inline(always)]
pub(crate) fn local() -> &'static ExecutorLocal {
    &ROOT_EXECUTOR_LOCAL
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
