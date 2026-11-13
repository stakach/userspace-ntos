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
//! The block is an ordinary image static, with the same mapping as the statics it replaces:
//! writable in the root executive and visible read-only, as root's values, to spawned components
//! that share the image. State a spawned component must write does not belong here.

use core::ops::Deref;
use core::sync::atomic::{AtomicU64, AtomicUsize};

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
    const fn new() -> Self {
        Self {
            ipc_buffer: AtomicU64::new(0),
            reply_main_slot: AtomicU64::new(0),
            scheduler_depth: AtomicU64::new(0),
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
