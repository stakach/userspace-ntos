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
