//! Path-addressed CM writes report registry changes (#405).
//!
//! `config_manager_set_value`, `set_dword` and `create_key` (VideoPort's DEVICEMAP\VIDEO, the
//! executive's CentralProcessor keys, driver registry commits) committed without reporting, so a
//! notify session on those keys never completed. Root security changes were also unreported.

const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const WORK: &str = include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");
const EXEC: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");

fn body<'a>(source: &'a str, start: &str) -> &'a str {
    source.split_once(start).unwrap().1.split_once("\n}\n").unwrap().0
}

#[test]
fn path_addressed_writes_queue_their_change_after_commit() {
    for (function, change) in [
        ("unsafe fn config_manager_set_value(", "CommittedChange::Values"),
        ("unsafe fn config_manager_set_dword(", "CommittedChange::Values"),
        ("unsafe fn config_manager_create_key_with_options(", "CommittedChange::KeyCreated"),
    ] {
        let body = body(MAIN, function);
        let commit = body.find(")?;").unwrap();
        let report = body.find("queue_path_committed_change(").unwrap();
        assert!(commit < report && body.contains(change), "{function}");
    }
    let create = body(MAIN, "unsafe fn config_manager_create_key(");
    assert!(create.contains("config_manager_create_key_with_options(path, false)"));
}

#[test]
fn a_queued_system_path_is_named_by_its_selected_physical_path() {
    let queue = body(WORK, "pub(crate) unsafe fn queue_path_committed_change(");
    assert!(queue.contains("config_manager_resolve_system_hive_path(path)"));
    assert!(queue.contains("resolved.physical_path"));
}

#[test]
fn root_key_security_changes_are_reported() {
    let set = body(EXEC, "fn set_registry_key_security_descriptor(");
    for root in ["target == MACHINE_ROOT_KEY", "target == USER_ROOT_KEY"] {
        let branch = set.split_once(root).unwrap().1.split_once("return Ok(());").unwrap().0;
        assert!(branch.contains("self.registry_target_security_changed(target)"), "{root}");
    }
}
