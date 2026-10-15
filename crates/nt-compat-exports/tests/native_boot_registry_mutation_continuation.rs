//! Boot SYSTEM mutations must retain their CM owner through uncertain transport.

use std::path::Path;

fn source(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

#[test]
fn bootstrap_cm_owner_retains_preparation_storage_and_exact_commit_receipt() {
    let owner = source("boot_registry_mutation_work.rs");
    for contract in [
        "CmMutationBeginAttempt",
        "SystemHiveMutationPreparation",
        "PreparedSystemHiveMutation",
        "SystemHiveMutationCommitReceipt",
        "commit_entered",
        "cm_mutation_transport::begin(",
        "cm_mutation_transport::prepare(",
        "cm_mutation_transport::commit(",
        "cm_mutation_transport::acknowledge(",
    ] {
        assert!(owner.contains(contract), "boot CM owner lost {contract}");
    }
    assert!(owner.contains("MutationPersistence"),
        "storage effects must stay with the same boot CM owner");
}

#[test]
fn boot_mutation_callers_cannot_use_the_one_shot_cm_path() {
    let acpi = source("acpi_platform.rs");
    let setup = source("exec_handler.rs");
    assert!(!acpi.contains("persist_and_publish_system_hive_mutation("),
        "ACPI root must retain its boot continuation through CM COMMIT and ACK");
    assert!(!setup.contains("persist_and_publish_system_hive_mutation("),
        "setup stages must retain their continuation through CM COMMIT and ACK");
}

#[test]
fn bootstrap_ack_barriers_keep_acpi_before_driver_plan_and_setup_in_order() {
    let main = source("main.rs");
    let acpi = main.find("publish_acpi_root_devnode_from_registry_policy()")
        .expect("ACPI root publication call");
    let driver_plan = main[acpi..].find("config_manager_query_driver_launch_plan(")
        .expect("boot driver selection") + acpi;
    assert!(acpi < driver_plan);

    let setup = source("exec_handler.rs");
    let activation = setup.find("unsafe fn activate_live_boot_policy(")
        .expect("boot setup activation");
    let setup = &setup[activation..];
    let timezone = setup.find("provision_reactos_time_zone_setup()").unwrap();
    let locale = setup.find("provision_default_user_locale()").unwrap();
    let network = setup.find("provision_reactos_network_setup()").unwrap();
    let print = setup.find("provision_reactos_print_setup()").unwrap();
    assert!(timezone < locale && locale < network && network < print,
        "boot setup stages must use fresh CM generations in their original order");
}

#[test]
fn acpi_boot_receive_refusal_retains_one_owner_and_blocks_driver_selection() {
    let acpi = source("acpi_platform.rs");
    let start = acpi.find("pub(crate) unsafe fn publish_acpi_root_devnode_from_registry_policy(")
        .expect("ACPI root publication");
    let acpi = &acpi[start..];
    let decision = acpi.find("config_manager_query_critical_device_binding(").unwrap();
    let gate = acpi.find("publish_boot_system_mutation(")
        .expect("ACPI boot must install retained CM work");
    assert!(decision < gate, "policy is captured once before retained work");
    assert!(!acpi[gate..].contains("sel4_rt::yield_now()"),
        "a physical receive refusal cannot be repaired by blind retry");

    let owner = source("boot_registry_mutation_work.rs");
    let admission = owner.find("if (*work_slot).is_none() {")
        .expect("one admission while no boot CM owner is installed");
    let reserve = owner[admission..].find("BootSystemMutationWork::reserve(").unwrap() + admission;
    let redrive = owner[reserve..].find("} else if *stage_slot != Some(stage) {").unwrap() + reserve;
    assert!(admission < reserve && reserve < redrive,
        "a repeated same-stage call must redrive the installed owner without a second BEGIN");
    assert!(owner.contains("boot_system_mutation_pending("),
        "a refusal must leave the exact stage visible for diagnosis or later outer redrive");

    let main = source("main.rs");
    let call = main.find("publish_acpi_root_devnode_from_registry_policy()")
        .expect("ACPI root gate");
    let plan = main[call..].find("config_manager_query_driver_launch_plan(").unwrap() + call;
    assert!(call < plan, "driver selection waits for the exact ACPI CM ACK");
}

#[test]
fn setup_constructor_waits_for_provider_registry_and_journal_quiescence() {
    let service = source("service_sec_image.rs");
    let constructor = service.find("let mut nt_handler = initialize_exec_nt_handler_once(")
        .expect("live handler construction");
    let prelude = &service[..constructor];
    let barrier = prelude.rfind("drain_boot_registry_before_handler_constructor()")
        .expect("provider registry quiescence before moving bootstrap Ps into handler");
    assert!(barrier < constructor);

    let owner = source("registry_mutation_work.rs");
    assert!(owner.contains("pub(crate) fn pending_count()"),
        "quiescence must observe the exact retained registry work count");
    let boot = source("boot_registry_mutation_work.rs");
    let start = boot.find("fn drain_boot_registry_before_handler_constructor()")
        .expect("bootstrap provider drain");
    let drain = &boot[start..];
    assert!(drain.contains("bootstrap_receive::drive("),
        "provider work needs the pre-constructor bootstrap scheduler");
    assert!(drain.contains("registry_mutation_work::pending_count()"));
    assert!(drain.contains("registry_journal::owns_volume()"),
        "storage ownership must also be clear before setup admission");
}

#[test]
fn setup_cm_stage_driver_cannot_reenter_the_handler_constructor() {
    let owner = source("boot_registry_mutation_work.rs");
    let start = owner.find("fn publish_setup_system_mutation(")
        .expect("CM-only retained setup stage driver");
    let end = owner[start..].find("pub(crate) unsafe fn ")
        .map(|offset| start + offset).unwrap_or(owner.len());
    let driver = &owner[start..end];
    assert!(driver.contains("BootSystemMutationWork::reserve("),
        "setup must retain one owner before its first CM effect");
    assert!(driver.contains("work.advance()"));
    assert!(driver.contains("BootMutationProgress::Complete"),
        "setup returns only after exact terminal acknowledgement");
    assert!(!driver.contains("bootstrap_receive::drive("));
    assert!(!driver.contains("registry_mutation_work::redrive_provider("));
    assert!(!driver.contains("service_autonomous("));
    assert!(!driver.contains("yield_now()"),
        "a transport refusal cannot trigger an unbounded retry under a handler borrow");

    let setup = source("exec_handler.rs");
    let helper = setup.find("fn persist_and_publish_system_mutations(")
        .expect("shared boot setup publication helper");
    let helper = &setup[helper..];
    assert!(helper.contains("publish_setup_system_mutation("),
        "all setup stages must use the CM-only retained owner");
}

#[test]
fn required_setup_collection_refusal_cannot_advance_to_later_stages() {
    let setup = source("exec_handler.rs");
    for (stage, end, marker) in [
        ("fn provision_reactos_network_setup(", "fn provision_reactos_explorer_shell_com_classes(",
            "[network-setup] SYSTEM mutation collection rejected a non-SYSTEM path"),
        ("fn provision_reactos_print_setup(", "fn provision_default_user_shell_folders(",
            "[print-setup] SYSTEM mutation collection rejected a non-SYSTEM path"),
    ] {
        let start = setup.find(stage).expect("required setup stage");
        let tail = &setup[start..];
        let stop = tail.find(end).unwrap_or(tail.len());
        let body = &tail[..stop];
        let refusal = body.find(marker).expect("collection refusal");
        let after = &body[refusal..];
        assert!(after.contains("panic!("),
            "{stage} must stop constructor progress on collection refusal");
        assert!(!after.split("panic!(").next().unwrap().contains("return;"),
            "{stage} must not treat rejected collection as an optional skip");
    }
}

#[test]
fn locale_local_publication_waits_for_confirmed_system_outcome() {
    let setup = source("exec_handler.rs");
    let start = setup.find("unsafe fn provision_default_user_locale(").unwrap();
    let end = setup[start..].find("fn is_dynamic_user_volatile_env_canon(")
        .expect("end of locale provision function") + start;
    let locale = &setup[start..end];
    let system_ack = locale.find("BootRegistryStage::Locale")
        .expect("locale SYSTEM mutation stage");
    let local_write = locale.find("self.ensure_mutable_registry_value_by_path(")
        .expect(".Default locale write");
    let atoms = locale.find("NT_SYSTEM_DEFAULT_LOCALE.store(")
        .expect("runtime locale publication");
    assert!(system_ack < local_write && system_ack < atoms,
        "local locale state must wait for the exact SYSTEM outcome");
    for marker in [
        r#"b"[locale-setup] installed NLS language query failed"#,
        r#"b"[locale-setup] .Default\\Control Panel\\International absent"#,
        r#"b"[locale-setup] .Default\\Control Panel\\International mutable write failed"#,
        r#"b"[locale-setup] CM HKLM\\...\\Nls\\Language open failed"#,
        r#"b"[locale-setup] SYSTEM mutation collection unavailable"#,
    ] {
        let at = locale.find(marker).expect("locale refusal");
        let after = &locale[at..];
        assert!(after.contains("panic!("), "locale refusal must stop setup: {marker}");
        assert!(!after.split("panic!(").next().unwrap().contains("return;"),
            "locale refusal must not advance to later setup stages: {marker}");
    }
}
