//! A retained registry interface publication can wait for a native WAL header recheck while
//! its caller's IRP Receive parent is parked. The exact recheck must make physical progress.

#[path = "../../nt-pnp-context/src/native_route_publication.rs"]
mod native_route_publication;

use native_route_publication::NativeRoutePublication;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Route {
    mount: u64,
    pdo: u64,
    generation: u64,
}

#[test]
fn registry_header_recheck_needs_the_published_exact_native_route() {
    let route = Route { mount: 17, pdo: 29, generation: 41 };
    let other_generation = Route { generation: 42, ..route };
    let initial = NativeRoutePublication::Absent.publish_initial(route).unwrap();
    assert_eq!(initial.published(), None);
    assert_eq!(initial.retained_recheck_route(), Some(route));
    assert!(initial.complete_initial(other_generation).is_err());

    let published = initial.complete_initial(route).unwrap();
    assert_eq!(published.published(), Some(route));
    let refreshing = published.begin_refresh(route).unwrap();
    assert_eq!(refreshing.published(), None);
    assert_eq!(refreshing.retained_recheck_route(), Some(route));
    assert_eq!(refreshing.abort_refresh(other_generation), None);
    assert_eq!(refreshing.abort_refresh(route), Some(published));
}

#[test]
fn retained_registry_recheck_is_serviced_by_exact_owner_inside_parked_receive() {
    let registry = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let receive = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");
    let native = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");

    // The provider mutation is already in Admitting. A numeric id by itself cannot authorize
    // arbitrary disk work; selection must come from the retained row and exact recheck owner.
    let selector = registry.find("pub(crate) fn pending_provider_header_recheck(")
        .expect("the retained provider row must expose its exact native header recheck id");
    let selector_body = &registry[selector..registry[selector..].find("\n}\n").unwrap() + selector + 2];
    assert!(selector_body.contains("Caller::Provider")
        && selector_body.contains("Phase::Admit")
        && selector_body.contains("admission_recheck_id()"));

    let receive_body = &receive[receive.find("pub(super) unsafe fn receive(").unwrap()..
        receive.find("unsafe fn autonomous_failure_diag(").unwrap()];
    let owner = receive_body.find("registry_mutation_work::pending_provider_header_recheck()")
        .expect("Receive must discover the exact retained registry recheck owner");
    let park = receive_body[owner..].find("runtime::nested::park_current()")
        .expect("the physical Receive parent must be parked before disk effects") + owner;
    let service = receive_body[park..].find("service_mounted_native_registry_recheck(")
        .expect("Receive must service the exact header recheck") + park;
    let restore = receive_body[service..].find("runtime::nested::restore(&mut parent)")
        .expect("the same Receive parent must be restored") + service;
    assert!(owner < park && park < service && service < restore);

    let service_start = native.find("pub(super) unsafe fn service_registry_recheck(")
        .expect("native block service must admit an exact registry header recheck");
    let service_body = &native[service_start..native[service_start..].find("\n}\n").unwrap()
        + service_start + 2];
    assert!(service_body.contains("service_registry_exact(id,")
        && service_body.contains("pending_provider_header_recheck")
        && service_body.contains("claim_registry_header_recheck")
        && !service_body.contains("claim_next_native_snapshot_io()")
        && !service_body.contains("retained_native_storage_recheck_route()"),
        "registry recheck must require the published route and claim only its exact id");
    let shared_start = native.find("unsafe fn service_registry_exact(")
        .expect("both exact registry services share one physical executor");
    let shared_body = &native[shared_start..native[shared_start..].find("\n}\n").unwrap()
        + shared_start + 2];
    let guard = shared_body.find("NativeServiceGuard::enter()")
        .expect("nested and outer block service must share one physical executor guard");
    let pending = shared_body.find("PENDING")
        .expect("nested service must inspect the existing single physical owner");
    let poll = shared_body.find("poll_pending()")
        .expect("an already-entered command must settle and ACK before a new claim");
    let route = shared_body.find("native_storage_route()")
        .expect("new registry claims require the Published route");
    let claim = shared_body.find("claim(id)").unwrap();
    assert!(guard < pending && pending < poll && poll < route && route < claim,
        "poll only the existing physical owner, then claim no unrelated new work");

    let outer = native.find("pub(super) unsafe fn service()")
        .expect("outer mounted block executor");
    let outer_body = &native[outer..native[outer..].find("\n}\n").unwrap() + outer + 2];
    assert!(outer_body.contains("NativeServiceGuard::enter()"));
    let snapshot = include_str!(
        "../../../components/ntos-executive/src/writable_fs/native_snapshot_io.rs"
    );
    let exact_claim = snapshot.find("pub(crate) unsafe fn claim_registry_header_recheck(")
        .expect("registry admission must claim by retained header recheck id");
    let exact_claim_body = &snapshot[exact_claim..snapshot[exact_claim..].find("\n}\n").unwrap()
        + exact_claim + 2];
    assert!(exact_claim_body.contains("claim_storage_io_for(id)")
        && !exact_claim_body.contains("claim_next_native_snapshot_io()"));
}

#[test]
fn retained_registry_wal_prepare_is_serviced_inside_parked_receive() {
    let registry = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
    let receive = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");
    let native = include_str!("../../../components/ntos-executive/src/mounted_native_block.rs");
    let snapshot = include_str!(
        "../../../components/ntos-executive/src/writable_fs/native_snapshot_io.rs"
    );

    // Once Admit reaches Durable, the provider's first WAL PREPARE returns DEVICE_BUSY
    // with an async effect retained by this row. The outer service loop cannot run while
    // Receive holds the caller, so the same parked parent must service that exact owner.
    let selector = registry.find("pub(crate) fn pending_provider_native_wal_io(")
        .expect("retained provider WAL owner must be discoverable during Receive");
    let selector_body = &registry[selector..registry[selector..].find("\n}\n").unwrap() + selector + 2];
    assert!(selector_body.contains("Caller::Provider")
        && selector_body.contains("Phase::Durable")
        && selector_body.contains("PersistenceOwner::Wal")
        && selector_body.contains("ACTIVE"),
        "selection must come from a quiescent retained provider WAL row");

    let receive_body = &receive[receive.find("pub(super) unsafe fn receive(").unwrap()..
        receive.find("unsafe fn autonomous_failure_diag(").unwrap()];
    let owner = receive_body.find("registry_mutation_work::pending_provider_native_wal_io()")
        .expect("Receive must inspect the retained provider WAL owner");
    let park = receive_body[owner..].find("runtime::nested::park_current()")
        .expect("park the physical Receive parent before native WAL effects") + owner;
    let service = receive_body[park..].find("service_mounted_native_registry_wal(")
        .expect("service the exact retained WAL owner") + park;
    let restore = receive_body[service..].find("runtime::nested::restore(&mut parent)")
        .expect("restore the same Receive parent") + service;
    assert!(owner < park && park < service && service < restore);

    let service_start = native.find("pub(super) unsafe fn service_registry_wal(")
        .expect("nested native service must admit the exact retained WAL owner");
    let service_body = &native[service_start..native[service_start..].find("\n}\n").unwrap()
        + service_start + 2];
    assert!(service_body.contains("service_registry_exact(id,")
        && service_body.contains("pending_provider_native_wal_io")
        && service_body.contains("claim_registry_wal_for")
        && !service_body.contains("claim_next_native_snapshot_io()"));
    let shared_start = native.find("unsafe fn service_registry_exact(")
        .expect("exact registry services share one physical executor");
    let shared_body = &native[shared_start..native[shared_start..].find("\n}\n").unwrap()
        + shared_start + 2];
    let guard = shared_body.find("NativeServiceGuard::enter()")
        .expect("nested and outer block services share the single physical executor");
    let pending = shared_body.find("PENDING")
        .expect("inspect any already-entered physical command first");
    let poll = shared_body.find("poll_pending()")
        .expect("settle the retained command before taking another");
    let route = shared_body.find("native_storage_route()")
        .expect("new WAL commands require a Published native route");
    let claim = shared_body.find("claim(id)")
        .expect("claim only the retained row's WAL command");
    assert!(guard < pending && pending < poll && poll < route && route < claim);
    assert!(!shared_body.contains("claim_next_native_snapshot_io()"),
        "nested Receive cannot claim unrelated mounted snapshot work");

    let exact_claim = snapshot.find("pub(crate) unsafe fn claim_registry_wal_for(")
        .expect("native snapshot adapter must expose an exact WAL owner claim");
    let exact_body = &snapshot[exact_claim..snapshot[exact_claim..].find("\n}\n").unwrap()
        + exact_claim + 2];
    assert!(exact_body.contains("claim_native_wal_io_for(id)")
        && !exact_body.contains("claim_next_native_snapshot_io()"));
}
