//! Hosted spin-style locks must not spin across lanes: a holder lane can be blocked in a root
//! call that the single-threaded root cannot answer while it services a spinning lane.

use std::path::Path;

fn native(name: &str) -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src").join(name)).expect("native source")
}

#[test]
fn every_hosted_spin_lock_family_parks_instead_of_spinning() {
    for file in ["hosted_driver_spin_lock.rs", "hosted_driver_queued_spin_lock.rs",
        "hosted_driver_ex_spin_lock.rs"]
    {
        let source = native(file);
        assert!(!source.contains("yield_now"), "{file} spins with yields across lanes");
        assert!(source.contains("hosted_driver_spin_wait::"), "{file} lacks the root-visible wait");
    }
    let launch = native("driver_launch.rs");
    let cancel = launch.split("fn acquire_cancel_spin_lock_word()").nth(1).unwrap()
        .split("fn release_cancel_spin_lock_word()").next().unwrap();
    assert!(cancel.contains("hosted_driver_spin_wait::acquire"));
    assert!(!launch.contains("while IO_CANCEL_SPIN_LOCK"), "the cancel lock still spins");
    let wait = native("hosted_driver_spin_wait.rs");
    assert!(wait.contains("park_hosted_driver_wait("), "contention must use the provider wait owner");
    assert!(wait.contains("holder-lane="), "contention traces name the holder lane");
}

// #423 (boots 44717077667, 44735317922): a DPC lane has no provider wait owner, so a DPC started
// while a lane of its domain holds a spin lock across a root call spins on a holder the root
// cannot answer. The root refuses to start the DPC first; it stays queued for the next pass.
#[test]
fn a_dpc_is_not_started_while_its_domain_holds_a_spin_lock() {
    const BROKER: &str =
        include_str!("../../../components/ntos-executive/src/hosted_irq_broker.rs");
    let dispatch = BROKER.split("unsafe fn dispatch_next_dpc(").nth(1).expect("DPC dispatch");
    let gate = dispatch.find("hosted_domain_dpc_may_start(owner.domain_id, owner.domain_cookie)")
        .expect("the DPC pass checks what the domain holds");
    let begin = dispatch.find("root_begin_transaction(").expect("transaction begin");
    assert!(gate < begin, "the refusal happens before the DPC lane is entered");
    assert!(dispatch[gate..begin].contains("HostedDpcRootDispatchOutcome::DeferredBusy"),
        "a refused DPC stays queued");
}

// 74aae474 checked the domain's IRQL byte, which other lanes rewrite: boot 1 of 44748352997 still
// spun. Every hosted spin lock family counts its acquisitions and releases instead.
#[test]
fn every_hosted_spin_lock_family_counts_what_the_domain_holds() {
    for (file, acquisitions, releases) in [
        ("hosted_driver_spin_lock.rs", 2, 1),
        ("hosted_driver_queued_spin_lock.rs", 1, 1),
        ("hosted_driver_ex_spin_lock.rs", 4, 4),
    ] {
        let source = native(file);
        assert_eq!(source.matches("hosted_driver_spin_wait::note_acquired()").count(), acquisitions,
            "{file}: every acquisition is counted");
        assert_eq!(source.matches("hosted_driver_spin_wait::note_released(lock)").count(), releases,
            "{file}: every release is counted");
    }
    let launch = native("driver_launch.rs");
    let cancel = launch.split("fn acquire_cancel_spin_lock_word()").nth(1).unwrap();
    let cancel = &cancel[..cancel.find("static WDM_FORWARD_CALL_TRACE_COUNT").unwrap()];
    assert!(cancel.contains("note_acquired()") && cancel.contains("note_released("),
        "the cancel spin lock is counted too");
    let gate = launch.split("unsafe fn hosted_domain_dpc_may_start(").nth(1).unwrap();
    assert!(gate[..gate.find("\n}\n").unwrap()].contains("SH_HOSTED_SPIN_LOCKS_HELD"),
        "the DPC gate reads the held count, not an IRQL byte");
}
