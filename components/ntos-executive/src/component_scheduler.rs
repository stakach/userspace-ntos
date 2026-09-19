//! Bounded IRQ/DPC scheduling between receive slices of a retained component invocation.

use super::*;

static DEPTH: AtomicU64 = AtomicU64::new(0);
static YIELDS: AtomicU64 = AtomicU64::new(0);

pub(super) fn is_active() -> bool {
    DEPTH.load(Ordering::Acquire) != 0
}

/// Keeps PASSIVE work and projection retirement outside the entire component invocation.
/// IRQ isolation comes from the dedicated broker arenas, not a copy of an active request bank.
pub(crate) struct ComponentSchedulerScope {
    depth: u64,
}

impl ComponentSchedulerScope {
    pub(crate) fn enter() -> Self {
        Self {
            depth: DEPTH.fetch_add(1, Ordering::AcqRel) + 1,
        }
    }

    /// Caller has retained the exact yielded invocation before any scheduler effect. A kernel
    /// caller must also have claimed its canonical receive attempt and released coordinator borrows.
    pub(crate) unsafe fn service_irq_yield(&self, shared_va: u64) {
        let _message = crate::ipc_message::SavedMessageBuffer::capture();
        let _durable = crate::allocator::enter_durable();
        let yield_number = YIELDS.fetch_add(1, Ordering::Relaxed) + 1;
        crate::dispatcher_bootstrap::request_receive_checkpoint();
        let timer_work = crate::dispatcher_bootstrap::service_hosted_timer_work();
        let irq_lines = drain_pending_hosted_irqs_snapshot();
        let dpcs = drain_hosted_driver_dpcs();
        // Nested exchanges may reconcile earlier requests before these effects publish new demand.
        crate::dispatcher_bootstrap::request_receive_checkpoint();
        crate::dispatcher_bootstrap::prepare_receive()
            .expect("bootstrap timer admission failed before retained receive");
        if yield_number <= 16 {
            // Report canonical demand after the actual receive checkpoint.
            let deadline = crate::dispatcher_bootstrap::next_deadline(crate::nt_time_snapshot());
            print_str(b"[component-scheduler] receive continuation bank=0x");
            print_hex64(shared_va);
            print_str(b" yield=");
            print_u64(yield_number);
            print_str(b" timer-work=");
            print_u64(timer_work);
            print_str(b" irq-lines=");
            print_u64(irq_lines);
            print_str(b" dpcs=");
            print_u64(dpcs);
            match deadline {
                Ok(Some((target, source))) => {
                    print_str(b" bootstrap-deadline=");
                    print_u64(target);
                    print_str(b" source=");
                    print_u64(source);
                }
                Ok(None) => print_str(b" bootstrap-deadline=none"),
                Err(status) => {
                    print_str(b" bootstrap-deadline-status=0x");
                    print_hex64(status as u64);
                }
            }
            print_str(b"\n");
        }
    }
}

impl Drop for ComponentSchedulerScope {
    fn drop(&mut self) {
        let previous = DEPTH.fetch_sub(1, Ordering::AcqRel);
        assert_eq!(
            previous, self.depth,
            "component scheduler scope order violated"
        );
    }
}

pub(super) unsafe fn hosted_component_pump(
    channel: &crate::spawn_hosts::PumpChannel,
) -> crate::spawn_hosts::PumpResult {
    let scope = ComponentSchedulerScope::enter();
    let mut result = crate::spawn_hosts::component_pump(channel);
    while result.scheduler_yielded {
        scope.service_irq_yield(channel.shared_va);
        result = crate::spawn_hosts::component_pump_continue_receive(channel, &result)
            .expect("hosted IRQ yield must retain its exact receive continuation");
    }
    result
}
