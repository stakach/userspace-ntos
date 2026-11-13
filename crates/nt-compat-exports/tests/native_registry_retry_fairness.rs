//! A refused SYSTEM mutation may not defer an independent retained row.

const WORK: &str = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");

#[test]
fn registry_retry_is_scoped_to_the_exact_mutation_row() {
    let row = WORK.split("struct Work {").nth(1).expect("retained mutation row");
    assert!(row.contains("retry_at:"), "each exact row needs its own retry deadline");
    let drive = WORK.split("unsafe fn redrive_inner(").nth(1).expect("registry redrive");
    assert!(drive.contains("select_ready_mutation("),
        "round-robin admission must skip only the refused row");
    assert!(drive.contains("earliest_mutation_retry("),
        "the shared PIT must receive the earliest retained row deadline");
    assert!(!drive.contains("if failed { RETRY_DELAY } else { 0 }"),
        "one busy mutation must not delay every independent row");
    let settle = WORK.split("pub(crate) unsafe fn complete_native_wal_io(").nth(1)
        .expect("exact native WAL completion");
    assert!(settle.contains("wake_mutation_row("),
        "native WAL settlement must wake its exact retained row");
}
