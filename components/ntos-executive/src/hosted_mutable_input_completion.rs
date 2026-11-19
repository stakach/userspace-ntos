//! Retained Type3InputBuffer return for zero-output METHOD_NEITHER controls.
//!
//! IoCompleteRequest may run at DISPATCH_LEVEL, so storage is reserved before provider entry.
//! The snapshot outlives the pending IRP graph on synchronous completion and is freed only after
//! the caller has copied it and acknowledged that exact canonical request.
//!
//! The root reserves, copies and acknowledges; the hosted driver captures inside
//! IoCompleteRequest. Each slot's phase is its owner ([`crate::phase_slots`]); no path waits on
//! another. A global spin lock here once stranded IoCompleteRequest behind a holder that could
//! not run (boot 44460274197, mouclass IOCTL_INTERNAL_MOUSE_CONNECT).

use super::*;
use crate::phase_slots::{PhaseSlots, EMPTY};

const SLOT_COUNT: usize = FSD_PENDING_IRP_CAP;
const RESERVED: u64 = 1;
const CAPTURED: u64 = 2;
const COPYING: u64 = 3;
const COPIED: u64 = 4;
const BLOCKED: u64 = 5;
/// Owned transitions: only the context that entered one touches the slot's data.
const CAPTURING: u64 = 6;
const RELEASING: u64 = 7;

#[derive(Clone, Copy)]
struct Snapshot {
    node: u64,
    node_generation: u64,
    source: u64,
    source_generation: u64,
    snapshot: u64,
    snapshot_generation: u64,
    length: u64,
}

const EMPTY_SNAPSHOT: Snapshot = Snapshot {
    node: 0,
    node_generation: 0,
    source: 0,
    source_generation: 0,
    snapshot: 0,
    snapshot_generation: 0,
    length: 0,
};

static PHASES: PhaseSlots<SLOT_COUNT> = PhaseSlots::new();
static mut SNAPSHOTS: [Snapshot; SLOT_COUNT] = [EMPTY_SNAPSHOT; SLOT_COUNT];
static GRAPH_RELEASED: [AtomicBool; SLOT_COUNT] = [const { AtomicBool::new(false) }; SLOT_COUNT];

/// Data of a slot whose phase the caller owns.
unsafe fn data(index: usize) -> &'static mut Snapshot {
    &mut (&mut *core::ptr::addr_of_mut!(SNAPSHOTS))[index]
}

/// A published slot met in the wrong phase is retained as BLOCKED, never reused. A slot in an
/// owned transition belongs to that context and is left alone.
fn block_published(index: usize) {
    let phase = PHASES.phase(index);
    if phase != CAPTURING && phase != COPYING && phase != RELEASING && phase != EMPTY {
        let _ = PHASES.transition(index, phase, BLOCKED);
    }
}

/// Retire an owned slot: empty on an exact free, otherwise retained as BLOCKED.
unsafe fn release(index: usize) -> bool {
    let slot = *data(index);
    if pool_free_exact(slot.snapshot, slot.snapshot_generation) {
        *data(index) = EMPTY_SNAPSHOT;
        GRAPH_RELEASED[index].store(false, Ordering::Release);
        PHASES.publish(index, EMPTY);
        true
    } else {
        PHASES.publish(index, BLOCKED);
        false
    }
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
    let Some(index) = PHASES.claim(canonical_irp_id) else {
        return false;
    };
    let unclaim = || PHASES.publish(index, EMPTY);
    if !component_pool_allocation_capacity(source).is_some_and(|capacity| length <= capacity) {
        unclaim();
        return false;
    }
    let source_generation = read_volatile((source - 8) as *const u64);
    if source_generation == 0 {
        unclaim();
        return false;
    }
    let snapshot = pool_alloc(length);
    if snapshot == 0 {
        unclaim();
        return false;
    }
    let snapshot_generation = read_volatile((snapshot - 8) as *const u64);
    *data(index) = Snapshot {
        node,
        node_generation,
        source,
        source_generation,
        snapshot,
        snapshot_generation,
        length,
    };
    GRAPH_RELEASED[index].store(false, Ordering::Release);
    PHASES.publish(index, RESERVED);
    true
}

/// Valid only before provider entry, when no completion can race this cleanup.
pub(super) unsafe fn abort_before_entry(canonical_irp_id: u64) -> bool {
    let Some((index, _)) = PHASES.find_published(canonical_irp_id) else {
        return false;
    };
    if !PHASES.transition(index, RESERVED, RELEASING) {
        block_published(index);
        return false;
    }
    release(index)
}

pub(super) unsafe fn capture(canonical_irp_id: u64, node: u64, node_generation: u64) -> bool {
    let Some((index, _)) = PHASES.find_published(canonical_irp_id) else {
        return false;
    };
    if !PHASES.transition(index, RESERVED, CAPTURING) {
        block_published(index);
        return false;
    }
    let slot = *data(index);
    if slot.node != node
        || slot.node_generation != node_generation
        || component_pool_allocation_capacity(slot.source)
            .is_none_or(|capacity| capacity < slot.length)
        || read_volatile((slot.source - 8) as *const u64) != slot.source_generation
    {
        PHASES.publish(index, BLOCKED);
        return false;
    }
    for index in 0..slot.length {
        let byte = read_volatile((slot.source + index) as *const u8);
        write_volatile((slot.snapshot + index) as *mut u8, byte);
    }
    PHASES.publish(index, CAPTURED);
    true
}

pub(super) unsafe fn copy(canonical_irp_id: u64, offset: u64, capacity: u64) -> (i32, u64) {
    let Some((index, _)) = PHASES.find_published(canonical_irp_id) else {
        return (STATUS_INVALID_PARAMETER, 0);
    };
    let slot = *data(index);
    if offset != 0
        || capacity != slot.length
        || component_pool_allocation_capacity(slot.snapshot)
            .is_none_or(|available| available < capacity)
        || read_volatile((slot.snapshot - 8) as *const u64) != slot.snapshot_generation
    {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    // The push crosses a transport boundary. Once attempted, a failed or lost reply cannot
    // authorize a second push from this owner.
    if !PHASES.transition(index, CAPTURED, COPYING) {
        return (STATUS_INVALID_PARAMETER, 0);
    }
    let pushed = pool_push_request_bytes(canonical_irp_id, slot.snapshot, 0, 0, capacity);
    let current = *data(index);
    if current.snapshot != slot.snapshot || current.snapshot_generation != slot.snapshot_generation {
        PHASES.publish(index, BLOCKED);
        return (STATUS_UNSUCCESSFUL, 0);
    }
    PHASES.publish(index, if pushed { COPIED } else { BLOCKED });
    if pushed {
        (STATUS_SUCCESS, capacity)
    } else {
        (STATUS_UNSUCCESSFUL, 0)
    }
}

pub(super) unsafe fn has_owner(canonical_irp_id: u64) -> bool {
    PHASES.owned(canonical_irp_id)
}

pub(super) unsafe fn graph_released(canonical_irp_id: u64) -> Option<bool> {
    PHASES.find_published(canonical_irp_id)
        .map(|(index, _)| GRAPH_RELEASED[index].load(Ordering::Acquire))
}

pub(super) unsafe fn mark_graph_released(
    canonical_irp_id: u64,
    node: u64,
    node_generation: u64,
) -> bool {
    let Some((index, phase)) = PHASES.find_published(canonical_irp_id) else {
        return false;
    };
    let slot = *data(index);
    if slot.node != node || slot.node_generation != node_generation || phase == RESERVED {
        // Retain the exact owner; a contradiction blocks it rather than reusing it.
        let _ = PHASES.transition(index, phase, BLOCKED);
        return false;
    }
    GRAPH_RELEASED[index].store(true, Ordering::Release);
    true
}

pub(super) unsafe fn acknowledge(canonical_irp_id: u64) -> bool {
    let Some((index, _)) = PHASES.find_published(canonical_irp_id) else {
        return false;
    };
    if !PHASES.transition(index, COPIED, RELEASING) {
        block_published(index);
        return false;
    }
    release(index)
}
