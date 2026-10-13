//! Retained Type3InputBuffer return for zero-output METHOD_NEITHER controls.
//!
//! IoCompleteRequest may run at DISPATCH_LEVEL, so storage is reserved before provider entry.
//! The snapshot outlives the pending IRP graph on synchronous completion and is freed only after
//! the caller has copied it and acknowledged that exact canonical request.

use super::*;

const SLOT_COUNT: usize = FSD_PENDING_IRP_CAP;
const EMPTY: u64 = 0;
const RESERVED: u64 = 1;
const CAPTURED: u64 = 2;
const COPYING: u64 = 3;
const COPIED: u64 = 4;
const BLOCKED: u64 = 5;

#[derive(Clone, Copy)]
struct Snapshot {
    phase: u64,
    canonical_irp_id: u64,
    node: u64,
    node_generation: u64,
    source: u64,
    source_generation: u64,
    snapshot: u64,
    snapshot_generation: u64,
    length: u64,
    graph_released: bool,
}

const EMPTY_SNAPSHOT: Snapshot = Snapshot {
    phase: EMPTY,
    canonical_irp_id: 0,
    node: 0,
    node_generation: 0,
    source: 0,
    source_generation: 0,
    snapshot: 0,
    snapshot_generation: 0,
    length: 0,
    graph_released: false,
};

static SNAPSHOT_LOCK: AtomicBool = AtomicBool::new(false);
static mut SNAPSHOTS: [Snapshot; SLOT_COUNT] = [EMPTY_SNAPSHOT; SLOT_COUNT];

struct Lock;
impl Lock {
    fn acquire() -> Self {
        while SNAPSHOT_LOCK
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        Self
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        SNAPSHOT_LOCK.store(false, Ordering::Release);
    }
}

unsafe fn slots() -> &'static mut [Snapshot; SLOT_COUNT] {
    &mut *core::ptr::addr_of_mut!(SNAPSHOTS)
}

pub(super) fn eligible(major: u64, method: Option<u32>, input_len: u64, output_len: u64) -> bool {
    (major == IRP_MJ_DEVICE_CONTROL || major == IRP_MJ_INTERNAL_DEVICE_CONTROL)
        && method == Some(ioctl::METHOD_NEITHER)
        && input_len != 0
        && input_len <= nt_io_manager::detached_file_irp::MAX_MUTABLE_METHOD_NEITHER_INPUT as u64
        && output_len == 0
}

pub(super) unsafe fn reserve(
    canonical_irp_id: u64,
    node: u64,
    node_generation: u64,
    source: u64,
    length: u64,
) -> bool {
    if canonical_irp_id == 0 || node_generation == 0 || length == 0 {
        return false;
    }
    let _lock = Lock::acquire();
    let slots = slots();
    if slots
        .iter()
        .any(|slot| slot.phase != EMPTY && slot.canonical_irp_id == canonical_irp_id)
    {
        return false;
    }
    let Some(slot) = slots.iter_mut().find(|slot| slot.phase == EMPTY) else {
        return false;
    };
    if !component_pool_allocation_capacity(source).is_some_and(|capacity| length <= capacity) {
        return false;
    }
    let source_generation = read_volatile((source - 8) as *const u64);
    if source_generation == 0 {
        return false;
    }
    let snapshot = pool_alloc(length);
    if snapshot == 0 {
        return false;
    }
    let snapshot_generation = read_volatile((snapshot - 8) as *const u64);
    *slot = Snapshot {
        phase: RESERVED,
        canonical_irp_id,
        node,
        node_generation,
        source,
        source_generation,
        snapshot,
        snapshot_generation,
        length,
        graph_released: false,
    };
    true
}

/// Valid only before provider entry, when no completion can race this cleanup.
pub(super) unsafe fn abort_before_entry(canonical_irp_id: u64) -> bool {
    let _lock = Lock::acquire();
    let Some(slot) = slots()
        .iter_mut()
        .find(|slot| slot.canonical_irp_id == canonical_irp_id && slot.phase != EMPTY)
    else {
        return false;
    };
    if slot.phase != RESERVED || !pool_free_exact(slot.snapshot, slot.snapshot_generation) {
        slot.phase = BLOCKED;
        return false;
    }
    *slot = EMPTY_SNAPSHOT;
    true
}

pub(super) unsafe fn capture(canonical_irp_id: u64, node: u64, node_generation: u64) -> bool {
    let _lock = Lock::acquire();
    let Some(slot) = slots()
        .iter_mut()
        .find(|slot| slot.canonical_irp_id == canonical_irp_id && slot.phase != EMPTY)
    else {
        return false;
    };
    if slot.phase != RESERVED
        || slot.node != node
        || slot.node_generation != node_generation
        || component_pool_allocation_capacity(slot.source)
            .is_none_or(|capacity| capacity < slot.length)
        || read_volatile((slot.source - 8) as *const u64) != slot.source_generation
    {
        slot.phase = BLOCKED;
        return false;
    }
    for index in 0..slot.length {
        let byte = read_volatile((slot.source + index) as *const u8);
        write_volatile((slot.snapshot + index) as *mut u8, byte);
    }
    slot.phase = CAPTURED;
    true
}

pub(super) unsafe fn copy(canonical_irp_id: u64, offset: u64, capacity: u64) -> (i32, u64) {
    let (snapshot, snapshot_generation) = {
        let _lock = Lock::acquire();
        let Some(slot) = slots()
            .iter_mut()
            .find(|slot| slot.canonical_irp_id == canonical_irp_id && slot.phase != EMPTY)
        else {
            return (STATUS_INVALID_PARAMETER, 0);
        };
        if slot.phase != CAPTURED
            || offset != 0
            || capacity != slot.length
            || component_pool_allocation_capacity(slot.snapshot)
                .is_none_or(|available| available < capacity)
            || read_volatile((slot.snapshot - 8) as *const u64) != slot.snapshot_generation
        {
            return (STATUS_INVALID_PARAMETER, 0);
        }
        // The push crosses a transport boundary. Once attempted, a failed or lost reply cannot
        // authorize a second push from this owner.
        slot.phase = COPYING;
        (slot.snapshot, slot.snapshot_generation)
    };
    let pushed = pool_push_request_bytes(canonical_irp_id, snapshot, 0, 0, capacity);
    let _lock = Lock::acquire();
    let Some(slot) = slots()
        .iter_mut()
        .find(|slot| slot.canonical_irp_id == canonical_irp_id && slot.phase != EMPTY)
    else {
        return (STATUS_UNSUCCESSFUL, 0);
    };
    if slot.phase != COPYING
        || slot.snapshot != snapshot
        || slot.snapshot_generation != snapshot_generation
    {
        slot.phase = BLOCKED;
        return (STATUS_UNSUCCESSFUL, 0);
    }
    slot.phase = if pushed { COPIED } else { BLOCKED };
    if pushed {
        (STATUS_SUCCESS, capacity)
    } else {
        (STATUS_UNSUCCESSFUL, 0)
    }
}

pub(super) unsafe fn has_owner(canonical_irp_id: u64) -> bool {
    let _lock = Lock::acquire();
    slots()
        .iter()
        .any(|slot| slot.phase != EMPTY && slot.canonical_irp_id == canonical_irp_id)
}

pub(super) unsafe fn graph_released(canonical_irp_id: u64) -> Option<bool> {
    let _lock = Lock::acquire();
    slots()
        .iter()
        .find(|slot| slot.phase != EMPTY && slot.canonical_irp_id == canonical_irp_id)
        .map(|slot| slot.graph_released)
}

pub(super) unsafe fn mark_graph_released(
    canonical_irp_id: u64,
    node: u64,
    node_generation: u64,
) -> bool {
    let _lock = Lock::acquire();
    let Some(slot) = slots()
        .iter_mut()
        .find(|slot| slot.phase != EMPTY && slot.canonical_irp_id == canonical_irp_id)
    else {
        return false;
    };
    if slot.node != node || slot.node_generation != node_generation || slot.phase == RESERVED {
        slot.phase = BLOCKED;
        return false;
    }
    slot.graph_released = true;
    true
}

pub(super) unsafe fn acknowledge(canonical_irp_id: u64) -> bool {
    let _lock = Lock::acquire();
    let Some(slot) = slots()
        .iter_mut()
        .find(|slot| slot.canonical_irp_id == canonical_irp_id && slot.phase != EMPTY)
    else {
        return false;
    };
    if slot.phase != COPIED || !pool_free_exact(slot.snapshot, slot.snapshot_generation) {
        slot.phase = BLOCKED;
        return false;
    }
    *slot = EMPTY_SNAPSHOT;
    true
}
