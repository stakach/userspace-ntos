//! Bounded, atomic observation of exact SCSI provider-pump owners.
//!
//! A slot is diagnostic only. Its identity is captured after transfer admission and never
//! consulted to authorize dispatch, completion, or retirement.

use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScsiSrbPumpOwnerIdentity {
    pub(crate) sequence: u64,
    pub(crate) irp_id: u64,
    pub(crate) device_id: u64,
    pub(crate) instance: u64,
    pub(crate) reply_cap: u64,
    pub(crate) tcb: u64,
    pub(crate) caller_tid: u64,
    pub(crate) caller_generation: u64,
    pub(crate) route_badge: u64,
    pub(crate) route_endpoint: u64,
    pub(crate) entered_ticks: u64,
}

struct Slot {
    /// 0 = free, 1 = writer publishing, sequence + 2 = entered provider pump.
    /// The published value changes on every reuse, so a reader cannot accept an ABA slot.
    state: AtomicU64,
    irp_id: AtomicU64,
    device_id: AtomicU64,
    instance: AtomicU64,
    reply_cap: AtomicU64,
    tcb: AtomicU64,
    caller_tid: AtomicU64,
    caller_generation: AtomicU64,
    route_badge: AtomicU64,
    route_endpoint: AtomicU64,
    entered_ticks: AtomicU64,
}

impl Slot {
    const fn new() -> Self {
        Self {
            state: AtomicU64::new(0),
            irp_id: AtomicU64::new(0), device_id: AtomicU64::new(0),
            instance: AtomicU64::new(0), reply_cap: AtomicU64::new(0),
            tcb: AtomicU64::new(0), caller_tid: AtomicU64::new(0),
            caller_generation: AtomicU64::new(0), route_badge: AtomicU64::new(0),
            route_endpoint: AtomicU64::new(0), entered_ticks: AtomicU64::new(0),
        }
    }

    fn publish(&self, identity: ScsiSrbPumpOwnerIdentity) {
        // All fields are atomic because a nested census may race retirement and reuse.
        // Sequential consistency also orders their observations with the state transitions.
        self.irp_id.store(identity.irp_id, Ordering::SeqCst);
        self.device_id.store(identity.device_id, Ordering::SeqCst);
        self.instance.store(identity.instance, Ordering::SeqCst);
        self.reply_cap.store(identity.reply_cap, Ordering::SeqCst);
        self.tcb.store(identity.tcb, Ordering::SeqCst);
        self.caller_tid.store(identity.caller_tid, Ordering::SeqCst);
        self.caller_generation.store(identity.caller_generation, Ordering::SeqCst);
        self.route_badge.store(identity.route_badge, Ordering::SeqCst);
        self.route_endpoint.store(identity.route_endpoint, Ordering::SeqCst);
        self.entered_ticks.store(identity.entered_ticks, Ordering::SeqCst);
        self.state.store(identity.sequence + 2, Ordering::SeqCst);
    }

    fn snapshot(&self) -> Option<ScsiSrbPumpOwnerIdentity> {
        let published = self.state.load(Ordering::SeqCst);
        if published <= 1 { return None; }
        let identity = ScsiSrbPumpOwnerIdentity {
            sequence: published - 2,
            irp_id: self.irp_id.load(Ordering::SeqCst),
            device_id: self.device_id.load(Ordering::SeqCst),
            instance: self.instance.load(Ordering::SeqCst),
            reply_cap: self.reply_cap.load(Ordering::SeqCst),
            tcb: self.tcb.load(Ordering::SeqCst),
            caller_tid: self.caller_tid.load(Ordering::SeqCst),
            caller_generation: self.caller_generation.load(Ordering::SeqCst),
            route_badge: self.route_badge.load(Ordering::SeqCst),
            route_endpoint: self.route_endpoint.load(Ordering::SeqCst),
            entered_ticks: self.entered_ticks.load(Ordering::SeqCst),
        };
        (self.state.load(Ordering::SeqCst) == published).then_some(identity)
    }
}

pub(crate) struct ScsiSrbPumpOwners<const N: usize> {
    slots: [Slot; N],
    overflow: AtomicU64,
}

impl<const N: usize> ScsiSrbPumpOwners<N> {
    pub(crate) const fn new() -> Self {
        Self { slots: [const { Slot::new() }; N], overflow: AtomicU64::new(0) }
    }

    pub(crate) fn claim(
        &self,
        identity: ScsiSrbPumpOwnerIdentity,
    ) -> Option<ScsiSrbPumpOwnerClaim<'_, N>> {
        if identity.sequence == 0 || identity.sequence > u64::MAX - 2 {
            self.overflow.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        for slot in &self.slots {
            if slot.state.compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst).is_ok() {
                slot.publish(identity);
                return Some(ScsiSrbPumpOwnerClaim { slot, _pool: self });
            }
        }
        self.overflow.fetch_add(1, Ordering::Relaxed);
        None
    }

    pub(crate) fn snapshot(&self, index: usize) -> Option<ScsiSrbPumpOwnerIdentity> {
        self.slots.get(index)?.snapshot()
    }

    pub(crate) fn overflow_count(&self) -> u64 {
        self.overflow.load(Ordering::Relaxed)
    }
}

pub(crate) struct ScsiSrbPumpOwnerClaim<'a, const N: usize> {
    slot: &'a Slot,
    _pool: &'a ScsiSrbPumpOwners<N>,
}

impl<const N: usize> Drop for ScsiSrbPumpOwnerClaim<'_, N> {
    fn drop(&mut self) {
        self.slot.state.store(0, Ordering::SeqCst);
    }
}
