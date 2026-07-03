//! DPC objects + queue (spec §6.3). A `KDPC` is opaque driver storage; the runtime
//! keeps its metadata (routine, context, queued state) in a side table keyed by
//! the driver's `KDPC` pointer. A DPC can be queued once at a time; drained DPCs
//! run at `DISPATCH_LEVEL`.

use alloc::vec::Vec;

use crate::irql::{IrqlState, DISPATCH_LEVEL};
use crate::DriverCallbackInvoker;

/// `KeSetImportanceDpc` importance — drains highest-first.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum DpcImportance {
    Low,
    #[default]
    Medium,
    MediumHigh,
    High,
}

struct Dpc {
    ptr: u64,
    routine: u64,
    deferred_context: u64,
    queued: bool,
    arg1: u64,
    arg2: u64,
    importance: DpcImportance,
    target_processor: Option<u32>,
    sequence: u64,
}

/// The Driver Host's single DPC queue (spec §6.3: one per Driver Host).
#[derive(Default)]
pub struct DpcQueue {
    dpcs: Vec<Dpc>,
    next_seq: u64,
}

impl DpcQueue {
    pub fn new() -> Self {
        Self {
            dpcs: Vec::new(),
            next_seq: 0,
        }
    }

    fn slot(&mut self, ptr: u64) -> &mut Dpc {
        if let Some(i) = self.dpcs.iter().position(|d| d.ptr == ptr) {
            return &mut self.dpcs[i];
        }
        self.dpcs.push(Dpc {
            ptr,
            routine: 0,
            deferred_context: 0,
            queued: false,
            arg1: 0,
            arg2: 0,
            importance: DpcImportance::Medium,
            target_processor: None,
            sequence: 0,
        });
        self.dpcs.last_mut().unwrap()
    }

    /// `KeInitializeDpc(Dpc, Routine, DeferredContext)`.
    pub fn initialize(&mut self, ptr: u64, routine: u64, deferred_context: u64) {
        let d = self.slot(ptr);
        d.routine = routine;
        d.deferred_context = deferred_context;
        d.queued = false;
        d.importance = DpcImportance::Medium;
    }

    /// `KeInsertQueueDpc(Dpc, Arg1, Arg2)` — queue the DPC. Returns `false` if it
    /// was already queued (spec §6.3).
    pub fn insert(&mut self, ptr: u64, arg1: u64, arg2: u64) -> bool {
        let seq = self.next_seq;
        let d = self.slot(ptr);
        if d.queued {
            return false;
        }
        d.queued = true;
        d.arg1 = arg1;
        d.arg2 = arg2;
        d.sequence = seq;
        self.next_seq += 1;
        true
    }

    /// `KeRemoveQueueDpc(Dpc)` — dequeue. Returns `true` if it was queued.
    pub fn remove(&mut self, ptr: u64) -> bool {
        match self.dpcs.iter_mut().find(|d| d.ptr == ptr) {
            Some(d) if d.queued => {
                d.queued = false;
                true
            }
            _ => false,
        }
    }

    /// `KeSetImportanceDpc`.
    pub fn set_importance(&mut self, ptr: u64, importance: DpcImportance) {
        self.slot(ptr).importance = importance;
    }

    /// `KeSetTargetProcessorDpc`.
    pub fn set_target_processor(&mut self, ptr: u64, cpu: u32) {
        self.slot(ptr).target_processor = Some(cpu);
    }

    pub fn is_queued(&self, ptr: u64) -> bool {
        self.dpcs.iter().any(|d| d.ptr == ptr && d.queued)
    }

    pub fn queued_count(&self) -> usize {
        self.dpcs.iter().filter(|d| d.queued).count()
    }

    /// Pop the next ready DPC (highest importance, then FIFO), marking it unqueued,
    /// and return `(routine, dpc, deferred_context, arg1, arg2)`. Used by a Driver
    /// Host that must call the driver routine **without** holding a runtime borrow
    /// (spec §17); the callback may re-enter the runtime.
    pub fn take_ready(&mut self) -> Option<(u64, u64, u64, u64, u64)> {
        let i = self
            .dpcs
            .iter()
            .enumerate()
            .filter(|(_, d)| d.queued)
            .max_by(|(_, a), (_, b)| {
                a.importance
                    .cmp(&b.importance)
                    .then(b.sequence.cmp(&a.sequence))
            })
            .map(|(i, _)| i)?;
        let d = &mut self.dpcs[i];
        d.queued = false;
        Some((d.routine, d.ptr, d.deferred_context, d.arg1, d.arg2))
    }

    /// Drain up to `budget` queued DPCs, running each at `DISPATCH_LEVEL` (highest
    /// importance first, then FIFO). Returns the number run. `KeFlushQueuedDpcs`
    /// is `drain(.., usize::MAX)`.
    pub fn drain(
        &mut self,
        irql: &mut IrqlState,
        invoker: &mut dyn DriverCallbackInvoker,
        budget: usize,
    ) -> usize {
        let mut ran = 0;
        while ran < budget {
            // Highest importance, then lowest sequence (FIFO within a level).
            let pick = self
                .dpcs
                .iter()
                .enumerate()
                .filter(|(_, d)| d.queued)
                .max_by(|(_, a), (_, b)| {
                    a.importance
                        .cmp(&b.importance)
                        .then(b.sequence.cmp(&a.sequence))
                })
                .map(|(i, _)| i);
            let Some(i) = pick else { break };

            // Copy the metadata, mark unqueued, then call (spec §17: no runtime
            // borrow held across the driver callback).
            let d = &mut self.dpcs[i];
            d.queued = false;
            let (routine, ptr, ctx, a1, a2) =
                (d.routine, d.ptr, d.deferred_context, d.arg1, d.arg2);

            let old = irql.raise(DISPATCH_LEVEL);
            invoker.call_dpc(irql.current(), routine, ptr, ctx, a1, a2);
            irql.lower(old);
            ran += 1;
        }
        ran
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::irql::PASSIVE_LEVEL;
    use alloc::{vec, vec::Vec};

    #[derive(Default)]
    struct Recorder {
        dpc: Vec<(u8, u64, u64, u64, u64)>, // (irql, dpc, ctx, a1, a2)
    }
    impl DriverCallbackInvoker for Recorder {
        fn call_dpc(&mut self, irql: u8, _routine: u64, dpc: u64, ctx: u64, a1: u64, a2: u64) {
            self.dpc.push((irql, dpc, ctx, a1, a2));
        }
        fn call_work_item(&mut self, _irql: u8, _routine: u64, _dev: u64, _ctx: u64) {}
    }

    #[test]
    fn insert_once_remove_drain() {
        let mut q = DpcQueue::new();
        q.initialize(0xD1, 0x808, 0xC0FFEE);
        assert!(q.insert(0xD1, 1, 2)); // first insert succeeds
        assert!(!q.insert(0xD1, 9, 9)); // already queued
        assert!(q.is_queued(0xD1));

        assert!(q.remove(0xD1)); // was queued
        assert!(!q.remove(0xD1)); // no longer queued

        // Re-queue + drain.
        assert!(q.insert(0xD1, 7, 8));
        let mut irql = IrqlState::new();
        let mut rec = Recorder::default();
        assert_eq!(q.drain(&mut irql, &mut rec, usize::MAX), 1);
        assert_eq!(rec.dpc, vec![(DISPATCH_LEVEL, 0xD1, 0xC0FFEE, 7, 8)]);
        assert_eq!(irql.current(), PASSIVE_LEVEL); // restored
        assert!(!q.is_queued(0xD1)); // unqueued after run
                                     // Drain again: nothing to run.
        assert_eq!(q.drain(&mut irql, &mut rec, usize::MAX), 0);
    }

    #[test]
    fn importance_orders_drain() {
        let mut q = DpcQueue::new();
        q.initialize(0xA, 0, 0);
        q.initialize(0xB, 0, 0);
        q.initialize(0xC, 0, 0);
        q.set_importance(0xC, DpcImportance::High);
        // Insert A, B, C in FIFO order; C is high-importance so runs first.
        q.insert(0xA, 0, 0);
        q.insert(0xB, 0, 0);
        q.insert(0xC, 0, 0);
        let mut irql = IrqlState::new();
        let mut rec = Recorder::default();
        q.drain(&mut irql, &mut rec, usize::MAX);
        let order: Vec<u64> = rec.dpc.iter().map(|c| c.1).collect();
        assert_eq!(order, vec![0xC, 0xA, 0xB]); // High first, then FIFO
    }

    #[test]
    fn budget_limits_drain() {
        let mut q = DpcQueue::new();
        for p in [0xA, 0xB, 0xC] {
            q.initialize(p, 0, 0);
            q.insert(p, 0, 0);
        }
        let mut irql = IrqlState::new();
        let mut rec = Recorder::default();
        assert_eq!(q.drain(&mut irql, &mut rec, 2), 2);
        assert_eq!(q.queued_count(), 1); // one left
    }
}
