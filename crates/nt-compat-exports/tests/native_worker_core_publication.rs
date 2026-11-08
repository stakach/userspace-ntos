//! A worker's configured scheduler core must be the core published to the exact runtime owner.

fn source(path: &str) -> String {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    std::fs::read_to_string(root.join(path)).unwrap()
}

#[test]
fn worker_core_selection_reaches_scheduler_configuration_and_runtime_publication() {
    let main = source("components/ntos-executive/src/main.rs");
    let scheduler = source("components/ntos-executive/src/thread_sched_context.rs");
    let spawn = source("components/ntos-executive/src/hosted_thread_spawn.rs");
    let runtime = source("components/ntos-executive/src/hosted_thread_runtime.rs");

    assert!(main.contains("select_guest_worker_core("),
        "worker construction must select an inherited-affinity core");
    assert!(scheduler.contains("SLOT_SCHED_CONTROL + u64::from(self.core)"),
        "SC configuration must use the selected core's real SchedControl capability");
    assert!(main.contains("attach_sched_context_on_core(tcb, physical_core)"),
        "the selected core must configure the SC before binding the worker TCB");
    assert!(spawn.contains("fn physical_core(&self) -> u8"),
        "successful construction must carry its acknowledged core to publication");
    assert!(runtime.contains("spawn.physical_core()"),
        "the non-Copy runtime owner must publish the configured worker core");
}
