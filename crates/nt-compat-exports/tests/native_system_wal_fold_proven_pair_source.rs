//! The native SYSTEM fold must reuse its exact paired proof across both acknowledged passes.

const NATIVE: &str = include_str!(
    "../../../components/ntos-executive/src/writable_fs/system_wal_fold/native.rs"
);

#[test]
fn native_fold_uses_the_rechecked_pair_before_the_first_preflush() {
    let stage = NATIVE.split("unsafe fn advance_recheck()").nth(1).unwrap()
        .split("pub(super) unsafe fn fold_system_wal_native()").next().unwrap();
    assert!(stage.contains("take_rechecked_wal_continuation(id)"));
    assert!(stage.contains("new_from_rechecked_pair("),
        "RED: the first fold pass must consume the exact same-lease rechecked pair");
    assert!(!stage.contains("AsyncSnapshotCommit::new("),
        "a fresh commit scans both already verified payload slots");
    assert!(stage.contains("Err((error, image, proof))"),
        "a refused first constructor must return both its payload and proof");
}

#[test]
fn second_pass_reuses_the_first_acknowledged_proof_and_stalls_retain_owners() {
    let completion = NATIVE.split("pub(crate) unsafe fn complete(").nth(1).unwrap()
        .split("fn stall(").next().unwrap();
    let first_done = completion.find("finish_with_payload_and_paired_proof()").unwrap();
    let second = completion.find("new_from_verified_pair(")
        .expect("RED: the second pass must use the first pass's settled proof");
    assert!(first_done < second);
    assert!(!completion.contains("AsyncSnapshotCommit::new("),
        "the second pass must not rescan either payload slot");
    assert!(completion.contains("Err((error, image, pair))"),
        "a refused second constructor must retain its returned image and proof");
    assert!(NATIVE.contains("StalledState::SecondAdmission")
        && NATIVE.contains("_image: image, _pair: pair"),
        "both returned second-pass values must remain owned under the exact lease");
    assert!(NATIVE.contains("enum StalledState")
        && NATIVE.contains("Active(Active)")
        && NATIVE.contains("StalledState::Active(active)"),
        "an uncertain active cursor, exact lease, and proof must remain owned in a stalled fold");
}
