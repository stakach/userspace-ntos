//! Shared, per-physical-lane KIRQL receipts for privileged win32k CR8 reads.
//!
//! The provider's activation catalog is allocated in its private heap. The executive must never
//! follow that pointer. These fixed atomics live in the shared executive image and carry the exact
//! activation identity beside the current KIRQL. Only the provider writes its own stopped lane.

use core::sync::atomic::{AtomicU64, Ordering};
use nt_kernel_exec::x86_cr8::{Cr8ActivationIdentity, PublishedCr8Irql};
use nt_provider_wait::ProviderStackEventActivation;

const SLOTS: usize = crate::win32k_subsystem::WIN32K_LANE_CAPACITY + 1;

struct Slot {
    version: AtomicU64,
    lane_generation: AtomicU64,
    dispatch_id: AtomicU64,
    activation_generation: AtomicU64,
    irql: AtomicU64,
}

impl Slot {
    const fn new() -> Self {
        Self {
            version: AtomicU64::new(0),
            lane_generation: AtomicU64::new(0),
            dispatch_id: AtomicU64::new(0),
            activation_generation: AtomicU64::new(0),
            irql: AtomicU64::new(0),
        }
    }

    fn write(&self, value: Option<PublishedCr8Irql>) {
        self.version.fetch_add(1, Ordering::SeqCst);
        let identity = value.map(|receipt| receipt.activation);
        self.lane_generation.store(identity.map_or(0, |id| u64::from(id.lane_generation)), Ordering::SeqCst);
        self.dispatch_id.store(identity.map_or(0, |id| id.dispatch_id), Ordering::SeqCst);
        self.activation_generation.store(identity.map_or(0, |id| id.activation_generation), Ordering::SeqCst);
        self.irql.store(value.map_or(0, |receipt| u64::from(receipt.irql)), Ordering::SeqCst);
        self.version.fetch_add(1, Ordering::SeqCst);
    }

    fn read(&self, lane_id: u64) -> Option<PublishedCr8Irql> {
        let before = self.version.load(Ordering::SeqCst);
        if before & 1 != 0 { return None; }
        let lane_generation = u32::try_from(self.lane_generation.load(Ordering::SeqCst)).ok()?;
        let dispatch_id = self.dispatch_id.load(Ordering::SeqCst);
        let activation_generation = self.activation_generation.load(Ordering::SeqCst);
        let irql = u8::try_from(self.irql.load(Ordering::SeqCst)).ok()?;
        let after = self.version.load(Ordering::SeqCst);
        if before != after || lane_generation == 0 || dispatch_id == 0 || activation_generation == 0 || irql > 15 {
            return None;
        }
        Some(PublishedCr8Irql {
            activation: Cr8ActivationIdentity { lane_id, lane_generation, dispatch_id, activation_generation },
            irql,
        })
    }
}

static SLOTS_BY_LANE: [Slot; SLOTS] = [const { Slot::new() }; SLOTS];

fn slot(lane_id: u64) -> Option<&'static Slot> {
    let index = usize::try_from(lane_id.checked_sub(1)?).ok()?;
    SLOTS_BY_LANE.get(index)
}

fn identity(activation: ProviderStackEventActivation) -> Cr8ActivationIdentity {
    Cr8ActivationIdentity {
        lane_id: activation.lane_id,
        lane_generation: activation.lane.generation(),
        dispatch_id: activation.dispatch_id,
        activation_generation: activation.generation,
    }
}

pub(super) fn publish(activation: ProviderStackEventActivation, irql: u8) -> bool {
    if activation.lane_id == 0 || activation.dispatch_id == 0 || activation.generation == 0 || irql > 15 {
        return false;
    }
    let Some(slot) = slot(activation.lane_id) else { return false; };
    slot.write(Some(PublishedCr8Irql { activation: identity(activation), irql }));
    true
}

pub(super) fn retire(
    activation: ProviderStackEventActivation,
    parent: Option<(ProviderStackEventActivation, u8)>,
) -> bool {
    let Some(slot) = slot(activation.lane_id) else { return false; };
    if slot.read(activation.lane_id).and_then(|receipt| receipt.for_activation(identity(activation))).is_none() {
        return false;
    }
    if let Some((parent, irql)) = parent {
        if parent.lane_id != activation.lane_id || irql > 15 { return false; }
        slot.write(Some(PublishedCr8Irql { activation: identity(parent), irql }));
    } else {
        slot.write(None);
    }
    true
}

pub(super) fn read(lane_id: u64) -> Option<PublishedCr8Irql> {
    slot(lane_id)?.read(lane_id)
}

/// Derive the publication slot from the authenticated physical stack range, never a shared claim.
pub(super) fn lane_id_for_stack(stack_base: u64, stack_bytes: u64) -> Option<u64> {
    use crate::win32k_subsystem as w32;
    if stack_base == w32::WIN32K_STACK_VADDR && stack_bytes == w32::WIN32K_LANE_STACK_FRAMES * 0x1000 {
        return Some(w32::WIN32K_PRIMARY_STACK_LANE_ID);
    }
    let offset = stack_base.checked_sub(w32::WIN32K_LANE_ARENA_VADDR)?;
    if offset % w32::WIN32K_LANE_STRIDE != 0 || stack_bytes != w32::WIN32K_LANE_STACK_FRAMES * 0x1000 {
        return None;
    }
    let ordinal = offset / w32::WIN32K_LANE_STRIDE;
    (ordinal < w32::WIN32K_LANE_CAPACITY as u64).then_some(w32::WIN32K_PRIMARY_STACK_LANE_ID + ordinal + 1)
}
