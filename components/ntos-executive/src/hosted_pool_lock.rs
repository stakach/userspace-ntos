//! The one pool lock word shared by root's executive view of a hosted pool and the component's
//! own view of it. Both sides tag the word with their holder.
//!
//! Every hosted thread runs on root's processor below root's priority, and root can hold or
//! suspend a component thread's execution. A component holder that root observes therefore
//! cannot release until root returns or hands it the processor. Root never yields or spins for
//! it: a runnable holder gets a bounded number of exact one-shot dispatches, and any other holder
//! is a no-effects refusal returned to the caller. Component threads may still wait: a root
//! holder is running and never blocks while holding.

use super::*;
use nt_hosted_runtime::{release_hosted_pool_lock, try_acquire_hosted_pool_lock,
    HostedPoolLockHolder};

static ROOT_BUSY: AtomicU64 = AtomicU64::new(0);

pub(super) struct ComponentPoolLockGuard(HostedPoolLockHolder);

impl Drop for ComponentPoolLockGuard {
    fn drop(&mut self) {
        let lock = unsafe { &*((FSD_POOL_VADDR + COMPONENT_POOL_LOCK_OFF) as *const AtomicU64) };
        if let Err(actual) = release_hosted_pool_lock(lock, self.0) {
            trace_foreign_release(FSD_POOL_VADDR, self.0, actual);
        }
    }
}

/// Component view only. The holder is named by this thread's stack pointer.
pub(super) unsafe fn component_pool_lock() -> ComponentPoolLockGuard {
    let lock = &*((FSD_POOL_VADDR + COMPONENT_POOL_LOCK_OFF) as *const AtomicU64);
    let stack_pointer: u64;
    core::arch::asm!("mov {}, rsp", out(reg) stack_pointer, options(nostack, nomem, preserves_flags));
    let holder = HostedPoolLockHolder::Component { stack_pointer };
    while try_acquire_hosted_pool_lock(lock, holder).is_err() {
        // Another hosted thread of this component, or root, owns the bounded allocator
        // mutation. Yielding lets an equal-priority owner finish; a root owner is running.
        crate::yield_now();
    }
    ComponentPoolLockGuard(holder)
}

pub(super) struct ExecutivePoolLockGuard(*const AtomicU64);

impl Drop for ExecutivePoolLockGuard {
    fn drop(&mut self) {
        let lock = unsafe { &*self.0 };
        if let Err(actual) = release_hosted_pool_lock(lock, HostedPoolLockHolder::Root) {
            trace_foreign_release(self.0 as u64, HostedPoolLockHolder::Root, actual);
        }
    }
}

/// Root's executive-view admission. `None` is a no-effects refusal: the caller still owns its
/// work and must retain or refuse it. Root never yields for a holder; it only gives an exact,
/// root-registered runnable holder its own dispatch (see `hand_off_to_pool_holder`).
#[track_caller]
pub(super) unsafe fn hosted_instance_pool_lock(exec_pool_va: u64) -> Option<ExecutivePoolLockGuard> {
    if exec_pool_va == 0 {
        return None;
    }
    let lock_address = exec_pool_va.checked_add(COMPONENT_POOL_LOCK_OFF)?;
    let lock = &*(lock_address as *const AtomicU64);
    let refusal = match try_acquire_hosted_pool_lock(lock, HostedPoolLockHolder::Root) {
        Ok(()) => return Some(ExecutivePoolLockGuard(lock as *const AtomicU64)),
        Err(holder @ HostedPoolLockHolder::Component { .. }) =>
            match hand_off_to_pool_holder(exec_pool_va, lock, holder) {
                Ok(()) => return Some(ExecutivePoolLockGuard(lock as *const AtomicU64)),
                Err(refusal) => refusal,
            },
        // Root is the single executor: a root holder is an outer frame of this same operation.
        Err(holder) => Refusal { holder, reason: b"not-component" },
    };
    trace_root_busy(exec_pool_va, refusal, core::panic::Location::caller());
    None
}

/// A DPC runs at DISPATCH_LEVEL, which NT never enters over a pool-lock holder on the same
/// processor. False keeps the DPC queued: its lane's allocator would otherwise wait on a holder
/// that root is keeping stopped.
#[track_caller]
pub(super) unsafe fn hosted_instance_pool_quiescent(exec_pool_va: u64) -> bool {
    exec_pool_va == 0 || hosted_instance_pool_lock(exec_pool_va).is_some()
}

const HOLDER_HANDOFF_ROUNDS: usize = 8;

struct Refusal {
    holder: HostedPoolLockHolder,
    reason: &'static [u8],
}

/// Each round names the current holder from root's own thread registry and gives that exact TCB
/// one dispatch on root's processor. The kernel refuses the handoff unless the holder is
/// runnable there, so an execution-held, suspended, faulted or blocked holder is refused at once.
unsafe fn hand_off_to_pool_holder(
    exec_pool_va: u64,
    lock: &AtomicU64,
    mut holder: HostedPoolLockHolder,
) -> Result<(), Refusal> {
    for _ in 0..HOLDER_HANDOFF_ROUNDS {
        let HostedPoolLockHolder::Component { stack_pointer } = holder else {
            return Err(Refusal { holder, reason: b"not-component" });
        };
        let Some(tcb) = pool_holder_tcb(exec_pool_va, stack_pointer) else {
            return Err(Refusal { holder, reason: b"unregistered-holder" });
        };
        let ran = super::component_scheduler::handoff_exact_component_once(tcb);
        match try_acquire_hosted_pool_lock(lock, HostedPoolLockHolder::Root) {
            Ok(()) => return Ok(()),
            Err(current) if ran => holder = current,
            Err(current) => return Err(Refusal { holder: current, reason: b"holder-not-runnable" }),
        }
    }
    Err(Refusal { holder, reason: b"handoff-budget" })
}

/// The component-written stack pointer is only a lookup key into root's registry of this pool's
/// threads. An unmatched or ambiguous key names no TCB.
unsafe fn pool_holder_tcb(exec_pool_va: u64, stack_pointer: u64) -> Option<u64> {
    let mut found = None;
    for (index, inst) in driver_instances()?.iter().enumerate() {
        if !inst.used || inst.exec_pool_va != exec_pool_va {
            continue;
        }
        let Some(domain) = instance_domain_identity(*inst) else { continue };
        let Some(tcb) = instance_thread_for_stack(index, *inst, domain, stack_pointer) else {
            continue;
        };
        if found.is_some_and(|other| other != tcb) {
            return None;
        }
        found = Some(tcb);
    }
    found
}

unsafe fn instance_thread_for_stack(
    index: usize,
    inst: DriverInstance,
    domain: HostedDomainIdentity,
    stack_pointer: u64,
) -> Option<u64> {
    let within = |base: u64, frames: u64| {
        stack_pointer.checked_sub(base).is_some_and(|offset| offset < frames * 0x1000)
    };
    if within(FSD_STACK_VADDR, FSD_STACK_FRAMES) {
        return (inst.tcb != 0).then_some(inst.tcb);
    }
    if within(hosted_worker_component_base_for_slot(FSD_IRQ_LANE_COMPONENT_SLOT)?,
        FSD_WORKER_STACK_FRAMES)
    {
        return hosted_irq_lanes()?.iter().find(|lane| lane.projection_instance == index
            && lane.domain == domain && lane.pml4 == inst.pml4 && lane.tcb != 0
            && matches!(lane.state, HostedIrqLaneState::Booting | HostedIrqLaneState::Ready))
            .map(|lane| lane.tcb);
    }
    let base = hosted_worker_component_base_from_rsp(stack_pointer)?;
    (*core::ptr::addr_of!(HOSTED_DRIVER_THREAD_RUNTIMES)).as_ref()?.iter()
        .find(|runtime| runtime.instance == index && runtime.domain == domain
            && runtime.pml4 == inst.pml4 && runtime.tcb != 0
            && hosted_worker_component_base_for_slot(runtime.component_slot) == Some(base))
        .map(|runtime| runtime.tcb)
}

fn trace_root_busy(
    exec_pool_va: u64,
    refusal: Refusal,
    site: &'static core::panic::Location<'static>,
) {
    let ordinal = ROOT_BUSY.fetch_add(1, Ordering::Relaxed) + 1;
    if ordinal > 32 && !ordinal.is_power_of_two() {
        return;
    }
    print_str(b"[hosted-pool-busy] ordinal=");
    print_u64(ordinal);
    print_str(b" pool=0x");
    print_hex64(exec_pool_va);
    print_holder(refusal.holder);
    print_str(b" reason=");
    print_str(refusal.reason);
    print_str(b" site=");
    print_str(site.file().as_bytes());
    print_str(b":");
    print_u64(u64::from(site.line()));
    print_str(b"\n");
}

fn trace_foreign_release(
    pool: u64,
    releaser: HostedPoolLockHolder,
    actual: Option<HostedPoolLockHolder>,
) {
    print_str(b"[hosted-pool-lock-foreign-release] pool=0x");
    print_hex64(pool);
    print_holder(releaser);
    print_str(b" actual=");
    match actual {
        Some(actual) => print_holder(actual),
        None => print_str(b"free"),
    }
    print_str(b"\n");
}

fn print_holder(holder: HostedPoolLockHolder) {
    match holder {
        HostedPoolLockHolder::Root => print_str(b" holder=root"),
        HostedPoolLockHolder::Component { stack_pointer } => {
            print_str(b" holder=component stack=0x");
            print_hex64(stack_pointer);
        }
        HostedPoolLockHolder::Unknown(word) => {
            print_str(b" holder=unknown word=0x");
            print_hex64(word);
        }
    }
}
