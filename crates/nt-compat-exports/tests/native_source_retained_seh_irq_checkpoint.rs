//! Regression for IRQ starvation while a hosted SEH exchange retains its Reply.
//! The native receiver cannot yield that one-shot exception walk as a new dispatch;
//! it must service a bounded IRQ checkpoint before entering the next blocking receive.

#[test]
fn retained_seh_receive_services_irq_before_blocking_without_replaying_reply() {
    let source = include_str!(
        "../../../components/ntos-executive/src/component_shared_pump.rs"
    );
    let start = source
        .find("pub(super) unsafe fn receive(")
        .expect("native shared receiver");
    let end = source[start..]
        .find("\npub(super) unsafe fn autonomous(")
        .expect("end of native shared receiver");
    let receive = &source[start..start + end];
    syn::parse_str::<syn::ItemFn>(receive).expect("parse the actual native receiver");

    let blocking = receive
        .find("runtime::receive(execution, ch.tcb, !timer_checkpoint)")
        .expect("physical receive selected by timer checkpoint");
    assert!(receive[..blocking].contains("let timer_checkpoint = !retained_seh"),
        "retained SEH must always use the blocking receive");
    assert!(
        receive[..blocking].contains("service_inline_irq_checkpoint(ch, route)"),
        "a retained SEH walk must service pending IRQ/timer work on its exact route before blocking"
    );
    assert!(
        receive[..blocking].contains("if inline_irq_checkpoint && irq_checkpoint {"),
        "a deferred IRQ can remain pending, so each observed arrival gets one checkpoint before receive"
    );
    assert!(
        !receive[..blocking].contains("irq_checkpoint || inline_irq_work_pending()"),
        "a level-triggered pending recheck would spin forever when the IRQ arena defers work"
    );

    let pump = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
    let retained = pump
        .split("unsafe fn pump_recv_retained_seh(ch: &PumpChannel) -> PumpMessage {")
        .nth(1)
        .expect("retained SEH receive")
        .split("\nunsafe fn pump_reply_recv_retained_seh(")
        .next()
        .unwrap();
    assert!(
        retained.contains("shared_pump::receive(ch, route, true)"),
        "the checkpoint must run in the retained receive path on the physical route"
    );
    let reply = pump
        .split("unsafe fn pump_reply_recv_retained_seh(")
        .nth(1)
        .expect("retained SEH reply")
        .split("\nunsafe fn pump_reply_recv_retained_cpu_fault(")
        .next()
        .unwrap();
    assert_eq!(reply.matches("shared_pump::reply_seh(").count(), 1);
    assert!(reply.contains("pump_recv_retained_seh(ch)"));
}

#[test]
fn non_yielding_syscall_receive_services_latched_irq_before_blocking() {
    let source = include_str!(
        "../../../components/ntos-executive/src/component_shared_pump.rs"
    );
    let receive = source
        .split("pub(super) unsafe fn receive(")
        .nth(1)
        .expect("native shared receiver")
        .split("\npub(super) unsafe fn autonomous(")
        .next()
        .unwrap();
    let blocking = receive
        .find("runtime::receive(execution, ch.tcb, !timer_checkpoint)")
        .expect("physical receive selected by timer checkpoint");
    assert!(receive[..blocking].contains("ch.caps.kind == ReqKind::Irp || ch.caps.kernel_irq_yield"),
        "non-yielding syscall channels must always use the blocking receive");
    assert!(
        receive[..blocking].contains("ReqKind::Syscall && !ch.caps.kernel_irq_yield"),
        "a syscall channel that cannot return a scheduler yield must checkpoint IRQ work inline"
    );
    assert!(
        receive[..blocking].contains("service_inline_irq_checkpoint(ch, route)"),
        "the exact retained dispatch must service the latched IRQ before another physical wait"
    );
}
