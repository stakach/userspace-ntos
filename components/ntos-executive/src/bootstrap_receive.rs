//! Pre-runtime scheduling on the shared endpoint, never a parked provider's Reply.

use crate::*;
use crate::spawn_hosts::shared_ingress::owner::runtime as ingress;
use nt_component_suspension::IngressExecutionOwner;
use nt_user_host::bootstrap_receive::{BootstrapCoordinator, BootstrapReceiveFacts};

/// The supplied bounded pass returns only an exact acknowledged target completion. All other
/// progress leaves the target retained; neither a missing activation nor a timer tick is success.
pub(crate) unsafe fn drive<T: Copy + Eq>(
    target: T,
    mut pass: impl FnMut() -> Result<Option<bool>, u32>,
) -> Result<bool, u32> {
    let _saved = ipc_message::SavedMessageBuffer::capture();
    let mut owner = BootstrapCoordinator::new(target)
        .map_err(|_| nt_process::STATUS_INSUFFICIENT_RESOURCES)?;
    loop {
        owner.invalidate_checkpoint().expect("bootstrap receive remains entered");
        if let Some(initialized) = pass()? {
            owner.acknowledge(target, initialized).expect("exact bootstrap completion");
            // Completion is returned before any fallible timer checkpoint can discard it.
            return Ok(owner.take_completion().expect("acknowledged bootstrap target"));
        }
        if service_sec_image::component_execution_is_busy() {
            return Err(nt_status::NtStatus::DEVICE_BUSY.raw() as u32);
        }
        {
            let scope = driver_launch::ComponentSchedulerScope::enter();
            scope.service_irq_yield(0);
        }
        if ingress::service_autonomous().map_err(|_| nt_process::STATUS_UNSUCCESSFUL)? {
            continue;
        }
        // Timer/IRQ service can select a continuation. Run another bounded pass before sleep;
        // its pacing deadline still prevents an immediately reparked job from spinning.
        if let Some(initialized) = pass()? {
            owner.acknowledge(target, initialized).expect("exact bootstrap completion");
            return Ok(owner.take_completion().expect("acknowledged bootstrap target"));
        }
        if !dispatcher_bootstrap::request_receive_checkpoint() {
            return Err(nt_status::NtStatus::DEVICE_NOT_READY.raw() as u32);
        }
        dispatcher_bootstrap::prepare_receive()?;
        let facts = BootstrapReceiveFacts {
            bootstrap_owned: dispatcher_bootstrap::is_owned(),
            invocation_active: driver_launch::hosted_component_dispatch_active(),
            pass_active: service_sec_image::component_resume::is_running(),
            timer_delivery_active: TIMER_DELIVERY_GATE.is_active(),
            physical_execution_active: service_sec_image::component_execution_is_busy(),
            rearm_pending: dispatcher_bootstrap::receive_work_pending(),
        };
        // A tick observed during scheduler effects still needs scanning. It invalidates sleep,
        // not the retained target; active execution owners remain errors, never retry permission.
        if facts.needs_service() {
            continue;
        }
        let mut permit = owner.checkpoint(facts)
            .map_err(|_| nt_status::NtStatus::DEVICE_BUSY.raw() as u32)?;
        owner.enter_receive(&mut permit).expect("fresh bootstrap receive permit");
        // Root TCB is only a stable query probe. The ingress coordinator supplies its own Free
        // Reply and retains every component/hosted arrival before returning this observation.
        let arrival = ingress::receive(IngressExecutionOwner::Idle, 1, true)
            .expect("uncertain bootstrap receive retains its entered ownership");
        owner.finish_receive(&mut permit).expect("observed bootstrap arrival");
        match arrival {
            ingress::Arrival::Notification(message) => {
                spawn_hosts::pump_handle_executive_event_badge(message.badge());
            }
            ingress::Arrival::Hosted | ingress::Arrival::Call { .. } => {}
        }
    }
}
