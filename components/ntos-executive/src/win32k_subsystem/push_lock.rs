//! NT push-lock slow paths with intrusive, allocation-pinned waiters and real dispatcher waits.

use super::*;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicI32, AtomicU32};
use nt_kernel_exec::push_lock as policy;

const MAGIC: u64 = 0x5055_5348_5741_4954;
const TAG: u64 = 0x5055_5348;

#[repr(C, align(16))]
struct Waiter {
    event: UnsafeCell<[u8; 24]>,
    next: AtomicU64,
    last: AtomicU64,
    previous: AtomicU64,
    shares: AtomicI32,
    flags: AtomicU32,
    refs: AtomicU64,
    magic: u64,
    pin: core::mem::ManuallyDrop<source_irp::PinnedSystemBuffer>,
}

const _: () = assert!(core::mem::offset_of!(Waiter, next) == 24);
const _: () = assert!(core::mem::offset_of!(Waiter, last) == 32);
const _: () = assert!(core::mem::offset_of!(Waiter, previous) == 40);
const _: () = assert!(core::mem::offset_of!(Waiter, shares) == 48);
const _: () = assert!(core::mem::offset_of!(Waiter, flags) == 52);

fn fatal(address: u64, stage: u64) -> ! {
    unsafe { crate::provider_bugcheck::report(0xc4, [TAG, address, stage, 0]) }
}

unsafe fn waiter(address: u64) -> &'static Waiter {
    if address & policy::PTR_BITS != 0
        || provider_pool_allocation_capacity(address)
            .is_none_or(|capacity| capacity < core::mem::size_of::<Waiter>() as u64)
    {
        fatal(address, 1);
    }
    let node = &*(address as *const Waiter);
    if node.magic != MAGIC
        || node.refs.load(Ordering::Acquire) == 0
        || !source_irp::system_buffer_live(&node.pin)
    {
        fatal(address, 2);
    }
    node
}

unsafe fn allocate_waiter() -> u64 {
    let address = pool_alloc(core::mem::size_of::<Waiter>() as u64);
    if address == 0 {
        fatal(address, 3);
    }
    let Some(pin) = source_irp::pin_system_buffer(address, core::mem::size_of::<Waiter>() as u64)
    else {
        fatal(address, 4);
    };
    core::ptr::write(
        address as *mut Waiter,
        Waiter {
            event: UnsafeCell::new([0; 24]),
            next: AtomicU64::new(0),
            last: AtomicU64::new(0),
            previous: AtomicU64::new(0),
            shares: AtomicI32::new(0),
            flags: AtomicU32::new(0),
            refs: AtomicU64::new(1),
            magic: MAGIC,
            pin: core::mem::ManuallyDrop::new(pin),
        },
    );
    // Publication brokers IPC. Complete it before any lock word can expose this node.
    s_ke_initialize_event(address, 1, 0);
    address
}

unsafe fn add_queue_ref(address: u64) {
    if waiter(address)
        .refs
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |refs| {
            refs.checked_add(1).filter(|_| refs != 0)
        })
        .is_err()
    {
        fatal(address, 5);
    }
}

unsafe fn release_node(address: u64) {
    let previous = {
        let node = waiter(address);
        node.refs.fetch_sub(1, Ordering::AcqRel)
    };
    if previous == 0 {
        fatal(address, 6);
    }
    if previous != 1 {
        return;
    }
    // The queue reference becomes the signaling reference at detach. Its release occurs only
    // after the Set Call returns; the waiter reference releases only after its wait lease drains.
    if !retire_existing_provider_local_event(address) {
        fatal(address, 7);
    }
    let pin = core::mem::ManuallyDrop::take(&mut (*(address as *mut Waiter)).pin);
    if !source_irp::release_system_buffer(pin) || !provider_pool_free(address) {
        fatal(address, 8);
    }
}

struct LockLease {
    address: u64,
    map_owner: u64,
    pin: Option<file_ioctl_target::PinnedIoctlOutput>,
}

impl LockLease {
    unsafe fn capture(address: u64) -> Self {
        if address == 0 || address & 7 != 0 {
            fatal(address, 9);
        }
        let Some(activation) = active_provider_stack_event_activation() else {
            fatal(address, 10);
        };
        {
            let _metadata = ProviderMetadataGuard::acquire();
            if (&*core::ptr::addr_of!(WIN32K_STACK_EVENT_ACTIVATIONS))
                .as_ref()
                .is_none_or(|catalog| {
                    !catalog
                        .current_irql(activation)
                        .is_ok_and(|irql| irql <= nt_kernel_exec::APC_LEVEL)
                })
            {
                fatal(address, 11);
            }
        }
        let pin = file_ioctl_target::pin_output(activation, address, 8)
            .unwrap_or_else(|_| fatal(address, 12));
        Self {
            address,
            map_owner: WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire),
            pin: Some(pin),
        }
    }

    unsafe fn atomic(&self) -> &AtomicU64 {
        if !source_irp::target_live(self.pin.as_ref().unwrap(), self.map_owner, self.address, 8) {
            fatal(self.address, 13);
        }
        &*(self.address as *const AtomicU64)
    }
}

impl Drop for LockLease {
    fn drop(&mut self) {
        unsafe {
            file_ioctl_target::release_output(self.pin.take().unwrap());
        }
    }
}

unsafe fn oldest(head: u64) -> u64 {
    let mut address = head;
    loop {
        let node = waiter(address);
        let tail = node.last.load(Ordering::Acquire);
        if tail != 0 {
            return tail;
        }
        let next = node.next.load(Ordering::Acquire);
        if next == 0 {
            fatal(address, 14);
        }
        waiter(next).previous.store(address, Ordering::Release);
        address = next;
    }
}

unsafe fn wake(lock: &LockLease, mut old: u64) {
    loop {
        let head = old & !policy::PTR_BITS;
        let tail = oldest(head);
        let previous = waiter(tail).previous.load(Ordering::Acquire);
        let exclusive = waiter(tail).flags.load(Ordering::Acquire) & 1 != 0;
        let action = policy::wake_action(old, exclusive, previous != 0)
            .unwrap_or_else(|_| fatal(lock.address, 15));
        match action {
            policy::WakeDecision::Relocked { new } => {
                match lock
                    .atomic()
                    .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
                {
                    Ok(_) => return,
                    Err(current) => {
                        old = current;
                        continue;
                    }
                }
            }
            policy::WakeDecision::DetachAll { new } => {
                if let Err(current) =
                    lock.atomic()
                        .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
                {
                    old = current;
                    continue;
                }
            }
            policy::WakeDecision::DetachOldest { .. } => {
                // Keep WAKING responsibility until the tail is detached. A concurrently
                // prepended head reaches this completed subchain through its immutable Next.
                waiter(head).last.store(previous, Ordering::Release);
                waiter(tail).previous.store(0, Ordering::Release);
                lock.atomic().fetch_and(!policy::WAKING, Ordering::AcqRel);
            }
        }
        let mut address = tail;
        while address != 0 {
            let node = waiter(address);
            let previous = node.previous.load(Ordering::Acquire);
            if node.flags.fetch_and(!2, Ordering::AcqRel) & 2 == 0 {
                // Queue ownership is retained across this broker Call and becomes the waker
                // reference. Never discard it on a fault/indeterminate signal.
                s_ke_set_event(address, 0, 0);
            }
            release_node(address);
            address = previous;
        }
        return;
    }
}

unsafe fn optimize(lock: &LockLease, mut old: u64) {
    loop {
        if old & policy::LOCKED == 0 {
            wake(lock, old);
            return;
        }
        let head = old & !policy::PTR_BITS;
        let tail = oldest(head);
        waiter(head).last.store(tail, Ordering::Release);
        match lock.atomic().compare_exchange(
            old,
            old & !policy::WAKING,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return,
            Err(current) => old = current,
        }
    }
}

unsafe fn acquire(address: u64, shared: bool) {
    let lock = LockLease::capture(address);
    let mut node = 0;
    let mut old = lock.atomic().load(Ordering::Acquire);
    loop {
        // The pure planner needs an aligned nonzero placeholder even before slow-path allocation.
        let decision = if shared {
            policy::acquire_shared(old, if node == 0 { 16 } else { node })
        } else {
            policy::acquire_exclusive(old, if node == 0 { 16 } else { node })
        }
        .unwrap_or_else(|_| fatal(address, 16));
        match decision {
            policy::AcquireDecision::Acquire { new } => {
                match lock
                    .atomic()
                    .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
                {
                    Ok(_) => {
                        if node != 0 {
                            release_node(node);
                        }
                        return;
                    }
                    Err(current) => old = current,
                }
            }
            policy::AcquireDecision::Queue(plan) => {
                if node == 0 {
                    node = allocate_waiter();
                    old = lock.atomic().load(Ordering::Acquire);
                    continue;
                }
                let block = waiter(node);
                block.next.store(plan.next, Ordering::Relaxed);
                block.last.store(plan.last, Ordering::Relaxed);
                block.previous.store(0, Ordering::Relaxed);
                block.shares.store(plan.saved_shared, Ordering::Relaxed);
                block.flags.store(plan.flags, Ordering::Relaxed);
                add_queue_ref(node);
                match lock.atomic().compare_exchange(
                    old,
                    plan.new,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                ) {
                    Err(current) => {
                        release_node(node);
                        old = current;
                    }
                    Ok(_) => {
                        if plan.needs_optimize {
                            optimize(&lock, plan.new);
                        }
                        if waiter(node).flags.fetch_and(!2, Ordering::AcqRel) & 2 != 0 {
                            let status = s_ke_wait_for_single_object(node, 28, 0, 0, 0);
                            if status != 0 {
                                fatal(address, 17);
                            }
                        }
                        // A resumed waiter may still have a signaling reference. It owns its
                        // own reference throughout retry, so allocation reuse is impossible.
                        old = lock.atomic().load(Ordering::Acquire);
                    }
                }
            }
        }
    }
}

unsafe fn try_wake(lock: &LockLease) {
    let old = lock.atomic().load(Ordering::Acquire);
    let Some(new) = policy::try_wake(old).unwrap_or_else(|_| fatal(lock.address, 18)) else {
        return;
    };
    if lock
        .atomic()
        .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        wake(lock, new);
    }
}

unsafe fn release(address: u64, shared: bool, generic: bool) {
    let lock = LockLease::capture(address);
    let mut old = lock.atomic().load(Ordering::Acquire);
    let mut remaining = None;
    loop {
        let plan = if (shared || generic) && old & policy::WAITING != 0 {
            let count = if old & policy::MULTIPLE_SHARED != 0 {
                if let Some(count) = remaining {
                    count
                } else {
                    let tail = oldest(old & !policy::PTR_BITS);
                    let before = waiter(tail).shares.fetch_sub(1, Ordering::AcqRel);
                    if before <= 0 {
                        fatal(address, 19);
                    }
                    remaining = Some(before - 1);
                    before - 1
                }
            } else {
                0
            };
            let Some(plan) =
                policy::release_shared_waiting(old, count).unwrap_or_else(|_| fatal(address, 20))
            else {
                return;
            };
            plan
        } else if shared || (generic && old & !policy::PTR_BITS != 0) {
            policy::release_shared_no_waiters(old).unwrap_or_else(|_| fatal(address, 21))
        } else {
            policy::release_exclusive(old).unwrap_or_else(|_| fatal(address, 22))
        };
        match lock
            .atomic()
            .compare_exchange(old, plan.new, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => {
                if plan.wake {
                    wake(&lock, plan.new);
                }
                return;
            }
            Err(current) => old = current,
        }
    }
}

pub(super) extern "win64" fn acquire_exclusive(address: u64) {
    unsafe {
        acquire(address, false);
    }
}
pub(super) extern "win64" fn acquire_shared(address: u64) {
    unsafe {
        acquire(address, true);
    }
}
pub(super) extern "win64" fn release_exclusive(address: u64) {
    unsafe {
        release(address, false, false);
    }
}
pub(super) extern "win64" fn release_shared(address: u64) {
    unsafe {
        release(address, true, false);
    }
}
pub(super) extern "win64" fn release_generic(address: u64) {
    unsafe {
        release(address, false, true);
    }
}
pub(super) extern "win64" fn try_to_wake(address: u64) {
    unsafe {
        let lock = LockLease::capture(address);
        try_wake(&lock);
    }
}
