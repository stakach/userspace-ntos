//! The boot shell COM registration reaches native registry opens after setup starts. Keys seeded
//! into the mutable SOFTWARE hive must carry security at creation, including after WAL replay.
//! `nt-hive-core`'s CreateChild replay tests cover the durable descriptor payload; this test
//! checks that the native seed path actually uses that secured operation.

fn function_between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("native function start");
    let end = source[start..].find(end).expect("next native function") + start;
    &source[start..end]
}

#[test]
fn internally_seeded_shell_com_children_commit_inherited_security_with_the_key() {
    let source = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let provision = function_between(
        source,
        "fn provision_reactos_explorer_shell_com_classes(",
        "fn provision_reactos_print_setup(",
    );
    assert!(provision.contains("ExecJournalNonSystemSetupSeedTarget::new(self)"));

    let seed_target = function_between(
        source,
        "fn ensure_mutable_registry_key_by_path_journaled(",
        "fn mutable_registry_key(",
    );
    assert!(seed_target.contains("journal_create_mutable_subkey(parent, leaf)"));

    let creation = function_between(
        source,
        "fn journal_create_mutable_subkey(",
        "fn journal_delete_mutable_value(",
    );
    assert!(creation.contains("mutable_registry_key_security_descriptor"),
        "seeded child must derive its stored descriptor from its retained parent");
    assert!(creation.contains("assign_object_security_with_audit"),
        "seeded child must inherit security through the NT assignment contract");
    assert!(creation.contains("journal_create_secured_mutable_subkey"),
        "seeded child must use the secured durable creation path");
    let admission = include_str!("../../../components/ntos-executive/src/exec_registry_admission.rs");
    let secured_creation = function_between(
        admission,
        "fn journal_create_secured_mutable_subkey(",
        "\n}",
    );
    assert!(secured_creation.contains("HiveLogOp::CreateChild"),
        "the WAL must retain the child descriptor for reboot replay");
    assert!(secured_creation.contains("try_create_child"),
        "the live child and WAL must publish the same secured metadata");
    assert!(!creation.contains("HiveLogOp::CreateKey"),
        "legacy key creation drops security metadata on replay");
}

#[test]
fn previously_seeded_unsecured_children_are_repaired_durably() {
    let source = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
    let ensure = function_between(
        source,
        "fn ensure_mutable_registry_key_by_path_journaled(",
        "fn mutable_registry_key(",
    );
    assert!(ensure.contains("journal_set_mutable_key_security_descriptor"),
        "existing keys made by the old seed path need a journaled security repair");
}
