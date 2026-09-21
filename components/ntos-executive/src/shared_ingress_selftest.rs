//! Native mechanism fixture. No NT export, driver result or desktop evidence is synthesized.

use crate::spawn_hosts::shared_ingress::owner::runtime as ingress;
use crate::spawn_hosts::*;
use crate::*;
use ingress::{PhysicalDomain, PhysicalSource, PhysicalSourceKind};
use nt_component_suspension::peer_registry::PeerRoute;

pub(crate) const LABEL: u64 = 0x7e0;
const NESTED: u64 = 0x7e1;
const READY: [u64; 4] = [0x5348_4152, 1, 0, 0];
const WORKER_STACK: u64 = STACK_BASE + 0x10000;
const WORKER_IPC: u64 = STACK_BASE + 0x18000;

struct Fixture {
    source: PhysicalSource,
    route: Option<PeerRoute>,
    primary: Option<SpawnedComponent>,
    worker: Option<SpawnedComponentWorker>,
}

static mut FIXTURES: Vec<Fixture> = Vec::new();
static mut DOMAINS: nt_provider_wait::ProviderDomainCatalog =
    nt_provider_wait::ProviderDomainCatalog::new();

unsafe extern "C" fn entry(_: u64) -> ! {
    let mut next =
        crate::driver_launch::call_on4((LABEL << 12) | 4, READY[0], READY[1], READY[2], READY[3]);
    loop {
        if next.1 == 1 {
            // A real stack continuation waits in a nested Call until the executive releases it.
            let _ = crate::driver_launch::call_on4((NESTED << 12) | 4, 17, 29, 43, 71);
        }
        next = crate::driver_launch::call_on(LABEL << 12);
    }
}

unsafe fn verify(source: PhysicalSource) -> bool {
    (&*core::ptr::addr_of!(FIXTURES)).iter().any(|row| {
        if row.source != source {
            return false;
        }
        let PhysicalDomain::Provider { catalog, domain } = source.domain else {
            return false;
        };
        if (&*core::ptr::addr_of!(DOMAINS)).identity() != Some(catalog)
            || !(&*core::ptr::addr_of!(DOMAINS)).contains(domain)
        {
            return false;
        }
        row.primary.as_ref().is_some_and(|owner| {
            owner.tcb == source.tcb
                && owner.pml4 == source.pml4
                && owner.cnode != 0
                && owner.sched_context != 0
        }) || row.worker.as_ref().is_some_and(|owner| {
            owner.tcb == source.tcb
                && owner.pml4 == source.pml4
                && owner.cnode != 0
                && owner.sched_context != 0
        })
    })
}

unsafe fn channel(index: usize) -> PumpChannel {
    let row = &(&*core::ptr::addr_of!(FIXTURES))[index];
    let route = row.route.expect("fixture enrolled");
    let map_owner = (&*core::ptr::addr_of!(FIXTURES))
        .iter()
        .filter_map(|candidate| candidate.primary.as_ref())
        .find(|primary| primary.pml4 == row.source.pml4)
        .expect("fixture VSpace owner retained")
        .map_cap_bank
        .owner;
    PumpChannel {
        ingress_route: Some(route),
        physical_domain: None,
        fault_ep: route.endpoint(),
        pml4: row.source.pml4,
        code_va: 0,
        image_frames: 0,
        exec_code_va: 0,
        root_image_rights: 2,
        root_image_map_owner: map_owner,
        shared_va: 0,
        dispatch_label: LABEL,
        demand_cap: 256,
        trace_faults: true,
        initial: InitialAction::RecvFirst,
        tcb: row.source.tcb,
        reply_cap: ingress::current_reply(route).expect("fixture canonical Reply"),
        client_pi: 0,
        client_generation: 0,
        logical_caller: None,
        kernel_caller: None,
        caps: HostCaps::default(),
    }
}

unsafe fn enroll(index: usize, reply: u64) -> PeerRoute {
    let row = &(&*core::ptr::addr_of!(FIXTURES))[index];
    let (cnode, sc) = if let Some(primary) = &row.primary {
        (primary.cnode, primary.sched_context)
    } else {
        let worker = row.worker.as_ref().expect("fixture worker");
        (worker.cnode, worker.sched_context)
    };
    let route = ingress::register(row.source, reply, cnode, verify).expect("fixture registration");
    (&mut *core::ptr::addr_of_mut!(FIXTURES))[index].route = Some(route);
    ingress::start_protocol(route, cnode, sc).expect("fixture start ACK");
    ingress::ready_protocol(route, &channel(index), LABEL, READY).expect("fixture ready Call");
    route
}

unsafe fn primary() -> PeerRoute {
    let domain = (&mut *core::ptr::addr_of_mut!(DOMAINS))
        .register()
        .expect("fixture domain");
    let component = spawn_component_suspended(&ComponentDescriptor {
        entry,
        image_rights: Rights::Uniform(2),
        lazy_image: true,
        map_heap_pt: false,
        stack_base: STACK_BASE,
        stack_frames: STACK_FRAMES,
        stack_dedicated_pt: false,
        regions: &[],
        granted: GrantedCaps::default(),
        prio: 100,
        gs_base: None,
        caps: HostCaps::default(),
    });
    let source = PhysicalSource {
        domain: PhysicalDomain::Provider {
            catalog: (&*core::ptr::addr_of!(DOMAINS))
                .identity()
                .expect("fixture catalog"),
            domain,
        },
        kind: PhysicalSourceKind::Primary,
        pml4: component.pml4,
        tcb: component.tcb,
    };
    let rows = &mut *core::ptr::addr_of_mut!(FIXTURES);
    let index = rows.len();
    rows.push(Fixture {
        source,
        route: None,
        primary: Some(component),
        worker: None,
    });
    let reply = ingress::allocate_reply(source.tcb).expect("fixture initial Reply");
    enroll(index, reply)
}

unsafe fn existing_stack_pt(va: u64, _: u64) -> bool {
    // The primary constructor installed this exact stack/IPC leaf table already.
    va >= WORKER_STACK && va <= WORKER_IPC && (va >> 21) == (STACK_BASE >> 21)
}

unsafe fn secondary(primary: PeerRoute) -> PeerRoute {
    let source = ingress::physical_source(primary).expect("fixture primary source");
    let worker = spawn_shared_component_worker_suspended(
        &SharedVspaceWorkerDescriptor {
            entry,
            entry_arg: 0,
            pml4: source.pml4,
            stack_base: WORKER_STACK,
            stack_frames: STACK_FRAMES,
            ipc_buffer_va: WORKER_IPC,
            prio: 100,
            gs_base: None,
            ensure_paging: existing_stack_pt,
        },
        primary.endpoint(),
    );
    let reply = worker.reply_cap;
    let rows = &mut *core::ptr::addr_of_mut!(FIXTURES);
    let index = rows.len();
    rows.push(Fixture {
        source: PhysicalSource {
            domain: source.domain,
            kind: PhysicalSourceKind::DispatchWorker { ordinal: 1 },
            pml4: source.pml4,
            tcb: worker.tcb,
        },
        route: None,
        primary: None,
        worker: Some(worker),
    });
    enroll(index, reply)
}

pub(crate) unsafe fn receive(route: PeerRoute) {
    // Every fixture command has at most one next Call. Bound the number of unrelated events;
    // the external boot runner separately enforces its wall-clock deadline.
    let index = (&*core::ptr::addr_of!(FIXTURES))
        .iter()
        .position(|row| row.route == Some(route))
        .expect("fixture receive source");
    let mut faults = 0;
    for _ in 0..64 {
        match ingress::receive(
            ingress::receive_owner(route).expect("fixture receive owner"),
            route.identity().executor,
            true,
        )
        .expect("fixture receive")
        {
            ingress::Arrival::Call {
                route: sender,
                reply,
            } if sender == route => {
                let (_, message) = ingress::next_message(route)
                    .unwrap()
                    .expect("fixture retained Call");
                if message.info() != (6 << 12) | 4 {
                    return;
                }
                ingress::adopt(route, reply).expect("fixture fault ownership");
                let [ip, address, _, fsr] = message.registers();
                faults += 1;
                assert!(
                    crate::spawn_hosts::pump_service_vm_fault(
                        &channel(index),
                        6,
                        ip,
                        address,
                        fsr,
                        faults,
                        faults,
                    ),
                    "fixture retains unmapped fault without replay"
                );
                ingress::reply(route, ingress::current_reply(route).unwrap(), &[])
                    .expect("fixture fault Reply ACK");
            }
            ingress::Arrival::Notification(message) => {
                assert!(crate::spawn_hosts::pump_handle_executive_event_badge(message.badge()).0);
            }
            _ => panic!("unexpected source in isolated ingress fixture"),
        }
    }
    panic!("fixture event bound exceeded");
}

pub(crate) unsafe fn dispatch_once(route: PeerRoute) {
    let dispatch = ingress::admit(route).expect("fixture admission");
    let reply = ingress::current_reply(route).unwrap();
    ingress::reply(route, reply, &[0]).expect("fixture request ACK");
    assert_eq!(
        ingress::dispatch(route).unwrap(),
        dispatch,
        "ACK is not completion"
    );
    receive(route);
    ingress::complete(
        route,
        dispatch,
        ingress::current_reply(route).unwrap(),
        LABEL,
    )
    .expect("fixture completion");
}

unsafe fn delete(cap: u64) {
    assert_eq!(
        cnode_delete_recycle_r(cap),
        0,
        "fixture cleanup retains uncertain cap"
    );
}

unsafe fn cleanup(index: usize) {
    let route = (&*core::ptr::addr_of!(FIXTURES))[index]
        .route
        .expect("fixture route");
    ingress::retire(route).expect("fixture ordered retirement");
    assert!(
        ingress::physical_source(route).is_err(),
        "retired source cannot admit"
    );
    let row = &mut (&mut *core::ptr::addr_of_mut!(FIXTURES))[index];
    if let Some(worker) = &row.worker {
        delete(worker.sched_context);
        delete(worker.tcb);
        assert_eq!(cnode_delete_in_cnode_r(worker.cnode, CT_PML4), 0);
        delete(worker.cnode);
        delete(worker.raw_cnode);
        for offset in 0..worker.stack_frame_count {
            delete(worker.stack_frame_base + offset);
        }
        delete(worker.ipc_buffer_frame);
        row.worker = None;
    }
    if let Some(primary) = &row.primary {
        delete(primary.sched_context);
        delete(primary.tcb);
        assert_eq!(cnode_delete_in_cnode_r(primary.cnode, CT_PML4), 0);
        delete(primary.cnode);
        delete(primary.raw_cnode);
        for offset in 0..primary.stack_frame_count {
            delete(primary.stack_frame_base + offset);
        }
        assert_eq!(
            release_component_map_cap_bank(primary.map_cap_bank).failures,
            0
        );
        delete(primary.pml4);
        row.primary = None;
    }
}

pub(crate) unsafe fn run() {
    print_str(b"[shared-ingress-native] begin\n");
    let _durable = crate::allocator::enter_durable();
    assert!(
        (&*core::ptr::addr_of!(FIXTURES)).is_empty(),
        "fixture runs once"
    );
    (&mut *core::ptr::addr_of_mut!(FIXTURES))
        .try_reserve_exact(3)
        .expect("fixture receipts");
    let first = primary();
    let second = primary();
    let worker = secondary(first);
    assert_eq!(first.endpoint(), second.endpoint());
    assert_eq!(first.endpoint(), worker.endpoint());
    let dispatch = ingress::admit(first).expect("outer fixture admission");
    ingress::reply(first, ingress::current_reply(first).unwrap(), &[1]).unwrap();
    receive(first);
    let (incoming, message) = ingress::next_message(first).unwrap().expect("nested Call");
    assert_eq!(message.info(), (NESTED << 12) | 4);
    assert_eq!(message.registers(), [17, 29, 43, 71]);
    ingress::adopt(first, incoming).expect("nested Call adoption");
    let parent = ingress::nested::park_current().expect("park real outer continuation");
    assert!(parent.is_some());
    dispatch_once(second);
    dispatch_once(worker);
    ingress::nested::restore(parent).expect("restore exact parked owner");
    let reply = ingress::current_reply(first).unwrap();
    ingress::reply(first, reply, &[0]).expect("resume real outer continuation");
    receive(first);
    ingress::complete(
        first,
        dispatch,
        ingress::current_reply(first).unwrap(),
        LABEL,
    )
    .expect("outer completion");
    service_sec_image::bootstrap_wait_selftest::run(
        first,
        second,
        &*core::ptr::addr_of!(DOMAINS),
    );
    cleanup(2);
    cleanup(1);
    cleanup(0);
    for route in [first, second] {
        let source = (&*core::ptr::addr_of!(FIXTURES))
            .iter()
            .find(|row| row.route == Some(route))
            .expect("fixture tombstone")
            .source;
        let PhysicalDomain::Provider { catalog, domain } = source.domain else {
            unreachable!()
        };
        assert_eq!((&*core::ptr::addr_of!(DOMAINS)).identity(), Some(catalog));
        (&mut *core::ptr::addr_of_mut!(DOMAINS))
            .retire(domain, 0)
            .expect("fixture domain retirement");
    }
    print_str(b"[shared-ingress-native] PASS providers=2 workers=3 nested=1 retired=3\n");
}
