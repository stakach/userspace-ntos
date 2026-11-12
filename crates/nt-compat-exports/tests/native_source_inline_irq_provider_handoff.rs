//! A retained Win32k syscall must give its runnable provider one dispatch after inline IRQ work.

const PUMP: &str = include_str!(
    "../../../components/ntos-executive/src/component_shared_pump.rs"
);
const SCHEDULER: &str = include_str!(
    "../../../components/ntos-executive/src/component_scheduler.rs"
);
const DRIVER: &str = include_str!(
    "../../../components/ntos-executive/src/driver_launch.rs"
);

#[test]
fn inline_irq_checkpoint_hands_the_exact_provider_a_dispatch_before_receiving_again() {
    let receive = PUMP
        .split_once("pub(super) unsafe fn receive(")
        .expect("shared physical receive")
        .1
        .split_once("pub(super) unsafe fn autonomous(")
        .expect("end of physical receive")
        .0;
    let checkpoint = receive
        .split_once("if inline_irq_checkpoint && irq_checkpoint {")
        .expect("inline IRQ checkpoint")
        .1
        .split_once("let owner_result = {")
        .expect("next physical receive")
        .0;
    let service = checkpoint
        .find("service_inline_irq_checkpoint(ch, route)")
        .expect("validate exact route and Reply around inline IRQ service");
    let handoff = checkpoint
        .find("crate::driver_launch::handoff_exact_component_once(ch.tcb)")
        .expect("RED: a notification-only receive must dispatch its runnable provider once");
    let next = checkpoint.find("continue;").expect("continue exact receive");
    assert!(service < handoff && handoff < next);
    assert!(SCHEDULER.contains("pub(crate) fn handoff_exact_component_once(tcb: u64) -> bool"));
    assert!(SCHEDULER.contains("sel4_rt::tcb_yield_to(tcb) == 0"));
    assert!(DRIVER.contains("pub(crate) use component_scheduler::handoff_exact_component_once;"));
}
