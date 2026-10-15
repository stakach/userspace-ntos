//! Native dynamic hive lifetime barriers, following ReactOS CmUnloadKey/CmShutdownSystem.

use std::path::Path;

fn source(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()))
}

#[test]
fn dirty_dynamic_hive_is_durable_before_ntunload_detaches_its_owner() {
    let source = source("exec_handler.rs");
    let start = source.find("unsafe fn nt_unload_key_ex(").expect("NtUnloadKey owner");
    let end = source[start..].find("fn registry_overlay_index(").unwrap() + start;
    let unload = &source[start..end];
    let journal_refusal = unload.find("hive.retained_value_journal().is_some()")
        .expect("retained mutation prevents unload");
    let checkpoint = unload.find("self.checkpoint_dynamic_mutable_hive(")
        .expect("dirty dynamic hive checkpoint");
    let durable = unload.find("crate::writable_fs::checkpoint_dirty_volume()")
        .expect("volume commit barrier");
    let detach = unload.find("self.hive_mounts.remove(index)")
        .expect("mount detachment");
    assert!(journal_refusal < checkpoint && checkpoint < durable && durable < detach,
        "NtUnloadKey must prove the exact dynamic hive durable before releasing its mount/slot");
    let checkpoint_refusal = &unload[checkpoint..durable];
    assert!(checkpoint_refusal.contains("NT_UNLOAD_KEY_REFUSED")
        && checkpoint_refusal.contains("return status"),
        "checkpoint refusal must retain the mount and slot");
    let commit_refusal = &unload[durable..detach];
    assert!(commit_refusal.contains("NT_UNLOAD_KEY_REFUSED")
        && commit_refusal.contains("return status"),
        "volume commit refusal must retain the mount and slot");
}

#[test]
fn shutdown_flushes_all_dynamic_hives_before_quiesce_teardown() {
    let handler = source("exec_handler.rs");
    let start = handler.find("fn checkpoint_dirty_dynamic_mutable_hives(")
        .expect("shutdown dynamic hive flush");
    let body = &handler[start..];
    assert!(body.contains("for hive_sel in HIVE_SEL_DYNAMIC"));
    assert!(body.contains("self.checkpoint_dynamic_mutable_hive(hive_sel, dirty)"));
    assert!(body.contains("return status"),
        "failed dynamic checkpoint must stop the shutdown barrier");

    let service = source("service_sec_image.rs");
    let start = service.find("fn checkpoint_boot_hives_at_quiesce(")
        .expect("shutdown hive barrier");
    let end = service[start..].find("#[path = \"service_section_pagein.rs\"]")
        .expect("end of shutdown hive barrier") + start;
    let quiesce = &service[start..end];
    let flush = quiesce.find("checkpoint_dirty_dynamic_mutable_hives()")
        .expect("dynamic hives included at shutdown");
    let commit = quiesce.find("crate::writable_fs::checkpoint_dirty_volume()")
        .expect("quiesce volume durability barrier");
    assert!(flush < commit, "dynamic hives must be checkpointed before volume commit");
    let call = service.find("checkpoint_boot_hives_at_quiesce(&mut nt_handler)").unwrap();
    let teardown = service[call..].find("dump_all_hosted_thread_quiesce(").unwrap() + call;
    assert!(call < teardown, "shutdown flush precedes quiesce teardown");
}
