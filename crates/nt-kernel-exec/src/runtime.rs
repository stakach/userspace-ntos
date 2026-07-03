//! The `KernelExecRuntime` (spec §7.1): the Driver Host's local execution runtime
//! tying together IRQL, spin locks, the DPC queue, timers, events, and work items,
//! with the event-loop drain hooks (spec §7.3) that run deferred driver callbacks
//! at deterministic points.

use crate::dpc::DpcQueue;
use crate::event::EventStore;
use crate::irql::IrqlState;
use crate::spin::SpinLockTable;
use crate::timer::{Clock, TimerQueue};
use crate::work_item::WorkQueue;
use crate::DriverCallbackInvoker;

/// The Driver Host's kernel execution runtime, generic over its clock source.
pub struct KernelExecRuntime<C: Clock> {
    irql: IrqlState,
    dpc: DpcQueue,
    timer: TimerQueue,
    events: EventStore,
    work: WorkQueue,
    spin: SpinLockTable,
    clock: C,
}

impl<C: Clock> KernelExecRuntime<C> {
    /// A fresh runtime over `clock`; `IoAllocateWorkItem` handles start at
    /// `work_handle_base`.
    pub fn new(clock: C, work_handle_base: u64) -> Self {
        Self {
            irql: IrqlState::new(),
            dpc: DpcQueue::new(),
            timer: TimerQueue::new(),
            events: EventStore::new(),
            work: WorkQueue::new(work_handle_base),
            spin: SpinLockTable::new(),
            clock,
        }
    }

    pub fn irql(&mut self) -> &mut IrqlState {
        &mut self.irql
    }
    pub fn dpc(&mut self) -> &mut DpcQueue {
        &mut self.dpc
    }
    pub fn timer(&mut self) -> &mut TimerQueue {
        &mut self.timer
    }
    pub fn events(&mut self) -> &mut EventStore {
        &mut self.events
    }
    pub fn work(&mut self) -> &mut WorkQueue {
        &mut self.work
    }
    pub fn spin(&mut self) -> &mut SpinLockTable {
        &mut self.spin
    }
    pub fn clock(&self) -> &C {
        &self.clock
    }
    pub fn clock_mut(&mut self) -> &mut C {
        &mut self.clock
    }

    /// `KeSetTimer[Ex]` against this runtime's clock.
    pub fn set_timer(
        &mut self,
        timer_ptr: u64,
        due_time: i64,
        period_ms: u32,
        dpc_ptr: Option<u64>,
    ) -> bool {
        self.timer
            .set(timer_ptr, due_time, period_ms, dpc_ptr, &self.clock)
    }

    /// Move any now-due timers' associated DPCs onto the DPC queue.
    pub fn expire_timers(&mut self) {
        for dpc_ptr in self.timer.run_due(&self.clock) {
            self.dpc.insert(dpc_ptr, 0, 0);
        }
    }

    /// Drain ready deferred work — expire due timers, then run queued DPCs (at
    /// `DISPATCH_LEVEL`) and work items (at `PASSIVE_LEVEL`) until quiescent or the
    /// `budget` of callbacks is exhausted (spec §7.3). Returns the number run.
    /// `budget` bounds a hostile driver that re-queues work forever (spec §7.3).
    pub fn drain_ready(&mut self, invoker: &mut dyn DriverCallbackInvoker, budget: usize) -> usize {
        let mut total = 0;
        while total < budget {
            self.expire_timers();
            let before = total;
            total += self.dpc.drain(&mut self.irql, invoker, budget - total);
            if total < budget {
                total += self.work.drain(&mut self.irql, invoker, budget - total);
            }
            if total == before {
                break; // nothing ran this round → quiescent
            }
        }
        total
    }

    /// Drain point after a driver dispatch returns (spec §7.3).
    pub fn on_after_driver_dispatch(&mut self, invoker: &mut dyn DriverCallbackInvoker) -> usize {
        self.drain_ready(invoker, 4096)
    }

    /// Drain point before the Driver Host blocks waiting for SURT (spec §7.3).
    pub fn on_before_block(&mut self, invoker: &mut dyn DriverCallbackInvoker) -> usize {
        self.drain_ready(invoker, 4096)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::irql::{DISPATCH_LEVEL, PASSIVE_LEVEL};
    use crate::timer::FakeClock;

    #[derive(Default)]
    struct TestInvoker {
        dpc_ran: u32,
        work_ran: u32,
        last_dpc_irql: u8,
        last_work_irql: u8,
    }
    impl DriverCallbackInvoker for TestInvoker {
        fn call_dpc(&mut self, irql: u8, _r: u64, _d: u64, _c: u64, _a1: u64, _a2: u64) {
            self.dpc_ran += 1;
            self.last_dpc_irql = irql;
        }
        fn call_work_item(&mut self, irql: u8, _r: u64, _d: u64, _c: u64) {
            self.work_ran += 1;
            self.last_work_irql = irql;
        }
    }

    #[test]
    fn dpc_drains_at_dispatch() {
        let mut rt = KernelExecRuntime::new(FakeClock::new(), 0x9000);
        rt.dpc().initialize(0xD1, 0x808, 0xC7);
        rt.dpc().insert(0xD1, 0, 0);
        let mut inv = TestInvoker::default();
        assert_eq!(rt.drain_ready(&mut inv, 100), 1);
        assert_eq!(inv.dpc_ran, 1);
        assert_eq!(inv.last_dpc_irql, DISPATCH_LEVEL);
    }

    #[test]
    fn timer_fires_then_dpc_drains() {
        let mut rt = KernelExecRuntime::new(FakeClock::new(), 0x9000);
        rt.dpc().initialize(0xD1, 0x808, 0xC7);
        rt.set_timer(0x700, -1000, 0, Some(0xD1));
        let mut inv = TestInvoker::default();
        // Not due yet.
        rt.drain_ready(&mut inv, 100);
        assert_eq!(inv.dpc_ran, 0);
        // Advance past the due time → timer queues DPC → drains at DISPATCH.
        rt.clock_mut().advance_100ns(2000);
        rt.drain_ready(&mut inv, 100);
        assert_eq!(inv.dpc_ran, 1);
        assert_eq!(inv.last_dpc_irql, DISPATCH_LEVEL);
    }

    #[test]
    fn work_item_drains_at_passive() {
        let mut rt = KernelExecRuntime::new(FakeClock::new(), 0x9000);
        let h = rt.work().allocate(0xDE0);
        rt.work().queue_io(h, 0x808, 0xC7);
        let mut inv = TestInvoker::default();
        rt.drain_ready(&mut inv, 100);
        assert_eq!(inv.work_ran, 1);
        assert_eq!(inv.last_work_irql, PASSIVE_LEVEL);
    }

    #[test]
    fn budget_bounds_drain() {
        // A hostile driver re-queuing work forever would livelock without the
        // budget; the cap bounds callbacks per drain (spec §7.3).
        let mut rt = KernelExecRuntime::new(FakeClock::new(), 0x9000);
        for i in 0..50u64 {
            rt.dpc().initialize(0x1000 + i, 0x808, 0);
            rt.dpc().insert(0x1000 + i, 0, 0);
        }
        let mut inv = TestInvoker::default();
        assert_eq!(rt.drain_ready(&mut inv, 10), 10); // budget caps it
        assert_eq!(inv.dpc_ran, 10);
    }
}
