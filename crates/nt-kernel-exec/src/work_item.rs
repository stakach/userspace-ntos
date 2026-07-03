//! Work items (spec §6.6). Unlike DPCs, work-item callbacks run at
//! `PASSIVE_LEVEL`. Two flavours: `IO_WORKITEM` (runtime-allocated via
//! `IoAllocateWorkItem`, tied to a device object, `Routine(DeviceObject, Context)`)
//! and the static `WORK_QUEUE_ITEM` (`ExInitializeWorkItem`, `Routine(Parameter)`).

use alloc::vec::Vec;

use crate::irql::{IrqlState, PASSIVE_LEVEL};
use crate::DriverCallbackInvoker;

enum WorkKind {
    /// `IO_WORKITEM`, keyed by the runtime-allocated handle.
    Io { device_object: u64 },
    /// `WORK_QUEUE_ITEM`, keyed by the driver's storage pointer.
    Ex,
}

struct WorkItem {
    key: u64,
    kind: WorkKind,
    routine: u64,
    context: u64,
    queued: bool,
}

/// The Driver Host's work queue (spec §6.6).
pub struct WorkQueue {
    items: Vec<WorkItem>,
    next_handle: u64,
}

impl WorkQueue {
    /// `handle_base` is where `IoAllocateWorkItem` handles start (opaque
    /// `PIO_WORKITEM` values the driver stores + passes back).
    pub fn new(handle_base: u64) -> Self {
        Self {
            items: Vec::new(),
            next_handle: handle_base,
        }
    }

    /// `IoAllocateWorkItem(DeviceObject)` — allocate a work item tied to a device;
    /// returns its opaque handle.
    pub fn allocate(&mut self, device_object: u64) -> u64 {
        let handle = self.next_handle;
        self.next_handle += 16;
        self.items.push(WorkItem {
            key: handle,
            kind: WorkKind::Io { device_object },
            routine: 0,
            context: 0,
            queued: false,
        });
        handle
    }

    /// `IoQueueWorkItem(WorkItem, Routine, QueueType, Context)`. Returns `false` if
    /// already queued (queued-once).
    pub fn queue_io(&mut self, handle: u64, routine: u64, context: u64) -> bool {
        match self.items.iter_mut().find(|w| w.key == handle) {
            Some(w) if !w.queued => {
                w.routine = routine;
                w.context = context;
                w.queued = true;
                true
            }
            _ => false,
        }
    }

    /// `IoFreeWorkItem(WorkItem)` — release the work item (lifetime is tied to the
    /// device object projection, spec §6.6).
    pub fn free(&mut self, handle: u64) {
        self.items.retain(|w| w.key != handle);
    }

    /// `ExInitializeWorkItem(Item, Routine, Context)` — a static work item keyed by
    /// the driver's storage pointer.
    pub fn initialize_ex(&mut self, item_ptr: u64, routine: u64, context: u64) {
        if let Some(w) = self.items.iter_mut().find(|w| w.key == item_ptr) {
            w.routine = routine;
            w.context = context;
            w.queued = false;
        } else {
            self.items.push(WorkItem {
                key: item_ptr,
                kind: WorkKind::Ex,
                routine,
                context,
                queued: false,
            });
        }
    }

    /// `ExQueueWorkItem(Item, QueueType)` — returns `false` if already queued.
    pub fn queue_ex(&mut self, item_ptr: u64) -> bool {
        match self.items.iter_mut().find(|w| w.key == item_ptr) {
            Some(w) if !w.queued => {
                w.queued = true;
                true
            }
            _ => false,
        }
    }

    pub fn is_queued(&self, key: u64) -> bool {
        self.items.iter().any(|w| w.key == key && w.queued)
    }

    pub fn queued_count(&self) -> usize {
        self.items.iter().filter(|w| w.queued).count()
    }

    /// Drain up to `budget` queued work items, running each at `PASSIVE_LEVEL`.
    /// Returns the number run.
    pub fn drain(
        &mut self,
        irql: &mut IrqlState,
        invoker: &mut dyn DriverCallbackInvoker,
        budget: usize,
    ) -> usize {
        let mut ran = 0;
        while ran < budget {
            let Some(i) = self.items.iter().position(|w| w.queued) else {
                break;
            };
            // Copy metadata + mark unqueued before calling (spec §17). The callback
            // may free an IO work item (removing it), which is safe post-copy.
            let w = &mut self.items[i];
            w.queued = false;
            let routine = w.routine;
            let context = w.context;
            let io_device = match &w.kind {
                WorkKind::Io { device_object } => Some(*device_object),
                WorkKind::Ex => None,
            };

            let old = irql.raise(PASSIVE_LEVEL); // already PASSIVE; no-op raise
            match io_device {
                Some(dev) => invoker.call_work_item(irql.current(), routine, dev, context),
                None => invoker.call_ex_work_item(irql.current(), routine, context),
            }
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

    #[derive(Default)]
    struct Recorder {
        io: alloc::vec::Vec<(u8, u64, u64, u64)>, // (irql, routine, dev, ctx)
        ex: alloc::vec::Vec<(u8, u64, u64)>,      // (irql, routine, param)
    }
    impl DriverCallbackInvoker for Recorder {
        fn call_dpc(&mut self, _i: u8, _r: u64, _d: u64, _c: u64, _a1: u64, _a2: u64) {}
        fn call_work_item(&mut self, irql: u8, routine: u64, dev: u64, ctx: u64) {
            self.io.push((irql, routine, dev, ctx));
        }
        fn call_ex_work_item(&mut self, irql: u8, routine: u64, param: u64) {
            self.ex.push((irql, routine, param));
        }
    }

    #[test]
    fn io_work_item_runs_at_passive() {
        let mut wq = WorkQueue::new(0x9000);
        let h = wq.allocate(0xDE0);
        assert!(wq.queue_io(h, 0x808, 0xC7));
        assert!(!wq.queue_io(h, 0x808, 0xC7)); // queued-once
        assert!(wq.is_queued(h));

        let mut irql = IrqlState::new();
        let mut rec = Recorder::default();
        assert_eq!(wq.drain(&mut irql, &mut rec, usize::MAX), 1);
        assert_eq!(rec.io, alloc::vec![(PASSIVE_LEVEL, 0x808, 0xDE0, 0xC7)]);
        assert!(!wq.is_queued(h)); // unqueued after run
    }

    #[test]
    fn free_removes_work_item() {
        let mut wq = WorkQueue::new(0x9000);
        let h = wq.allocate(0xDE0);
        wq.free(h);
        assert!(!wq.queue_io(h, 0x808, 0)); // freed → cannot queue
    }

    #[test]
    fn ex_work_item_queued_once_and_runs() {
        let mut wq = WorkQueue::new(0x9000);
        wq.initialize_ex(0x5000, 0x808, 0x9999);
        assert!(wq.queue_ex(0x5000));
        assert!(!wq.queue_ex(0x5000)); // already queued
        let mut irql = IrqlState::new();
        let mut rec = Recorder::default();
        wq.drain(&mut irql, &mut rec, usize::MAX);
        assert_eq!(rec.ex.len(), 1);
        assert_eq!(rec.ex[0].0, PASSIVE_LEVEL);
    }
}
