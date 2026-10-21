//! Physical IRQ ownership and lane-local IRQL for an inline driver CR8 read.

use nt_hosted_runtime::{
    select_hosted_irq_cr8_source, HostedIrqArenaConfig, HostedIrqArenaControl,
    HostedIrqCr8Source, HostedIrqLaneIdentity, HostedIrqTransactionClass,
};
use nt_kernel_exec::x86_cr8::{decode_cr8_read, project_cr8_read};

fn owner() -> HostedIrqCr8Source {
    HostedIrqCr8Source {
        lane: HostedIrqLaneIdentity::new(7, 9, 11).unwrap(),
        endpoint: 300,
        badge: 301,
        route_generation: 5,
        transaction: 17,
        tcb: 200,
        vspace: 400,
        reply: 500,
    }
}

#[test]
fn irq_cr8_source_requires_exact_lane_route_transaction_and_reply() {
    let live = owner();
    assert_eq!(select_hosted_irq_cr8_source(live, live), Some(live.lane));

    for stale in [
        HostedIrqCr8Source { lane: HostedIrqLaneIdentity { lane_generation: 12, ..live.lane }, ..live },
        HostedIrqCr8Source { lane: HostedIrqLaneIdentity { domain_cookie: 10, ..live.lane }, ..live },
        HostedIrqCr8Source { endpoint: 302, ..live },
        HostedIrqCr8Source { badge: 303, ..live },
        HostedIrqCr8Source { route_generation: 6, ..live },
        HostedIrqCr8Source { transaction: 18, ..live },
        HostedIrqCr8Source { tcb: 201, ..live },
        HostedIrqCr8Source { vspace: 401, ..live },
        HostedIrqCr8Source { reply: 501, ..live },
    ] {
        assert_eq!(select_hosted_irq_cr8_source(live, stale), None, "accepted {stale:?}");
    }
    assert_eq!(select_hosted_irq_cr8_source(
        HostedIrqCr8Source { reply: 0, ..live },
        HostedIrqCr8Source { reply: 0, ..live },
    ), None);
}

#[test]
fn keyboard_irq_cr8_read_projects_only_rip_and_rax_from_its_arena() {
    let live = owner();
    let control = HostedIrqArenaControl::new(HostedIrqArenaConfig {
        identity: live.lane,
        component_kpcr_va: 0x10_000,
        stack_low: 0x20_000,
        stack_high: 0x30_000,
        high_irql: 15,
    }).unwrap();
    control.worker_mark_ready(live.lane).unwrap();
    control.root_activate(live.lane).unwrap();
    let transaction = control.root_begin_transaction(
        live.lane, HostedIrqTransactionClass::Interrupt,
    ).unwrap();
    control.worker_raise_irql(live.lane, transaction, 0, 2).unwrap();
    assert_eq!(control.active_transaction(live.lane, live.transaction),
        Err(nt_hosted_runtime::HostedIrqArenaError::StaleTransaction));
    assert_eq!(control.active_transaction(live.lane, transaction.transaction), Ok(transaction));

    let selected = select_hosted_irq_cr8_source(live, live).unwrap();
    let irql = control.current_irql(selected).unwrap();
    assert_eq!(irql, 2);
    let mut registers = [0xfeed_u64; 20];
    registers[0] = 0x1000_e002_e4d;
    let before = registers;
    let read = decode_cr8_read(&[0x44, 0x0f, 0x20, 0xc0]).unwrap();
    let mask = project_cr8_read(&mut registers, read, irql).unwrap();
    assert_eq!(mask, (1 << 0) | (1 << 3));
    assert_eq!(registers[0], before[0] + 4);
    assert_eq!(registers[3], 2);
    for index in 1..20 {
        if index != 3 { assert_eq!(registers[index], before[index]); }
    }

    let stale = HostedIrqLaneIdentity { lane_generation: 12, ..live.lane };
    assert!(control.current_irql(stale).is_err());
}
