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

#[test]
fn native_quiesce_proves_dirty_dynamic_hive_sidecars_without_async_checkpoint() {
    let handler = source("exec_handler.rs");
    let path_start = handler
        .find("fn mutable_hive_checkpoint_path_owned(")
        .expect("dynamic hive checkpoint path resolver");
    let path_end = handler[path_start..]
        .find("fn boot_mutable_hive_pending_bit(")
        .expect("end of path resolver") + path_start;
    let path = &handler[path_start..path_end];
    assert!(path.contains("mount.dynamic && mount.sel == hive_sel")
        && path.contains("mount.file.clone()"),
        "dynamic sidecar proof must resolve the exact mounted hive selector and source path");

    let verify = handler
        .find("fn verify_durable_v2_mutable_hives(")
        .expect("native boot and dynamic hive WAL durability proof");
    let verify_end = handler[verify..]
        .find("pub(crate) fn boot_mutable_hive_dirty_cells(")
        .expect("end of native hive proof") + verify;
    let body = &handler[verify..verify_end];
    let reserve = body.find("with_clean_v2_volume_at_quiesce(")
        .expect("clean snapshot and WAL fence held during proof");
    let selectors = body.find("HIVE_SEL_DYNAMIC")
        .expect("all dynamic hive slots are checked");
    let retained = body.find("retained_value_journal()")
        .expect("retained mutation refuses terminal quiesce");
    let dirty = body.find("dirty_count()")
        .expect("only dirty hives require a sidecar");
    let image = body.find("mutable_hive_checkpoint_path_owned(hive_sel)")
        .expect("sidecar is paired with exact mounted image");
    let sidecar = body.find("push_str(\".LOG\")")
        .expect("dynamic hive sidecar path");
    let proof = body.find("verify_published_hive_log_tail(")
        .expect("semantic sidecar tail proof");
    assert!(reserve < selectors && selectors < retained && retained < proof
        && dirty < proof && image < sidecar && sidecar < proof,
        "prove every dirty dynamic hive under the reserve after rejecting retained mutations");
    assert!(body[proof..].contains("hive.sequence"),
        "sidecar proof must cover the live hive sequence");
    assert!(!body.contains("checkpoint_dynamic_mutable_hive(")
        && !body.contains("checkpoint_dirty_volume()"),
        "terminal Native proof cannot start full-image or asynchronous checkpoint I/O");

    let service = source("service_sec_image.rs");
    let start = service.find("fn checkpoint_boot_hives_at_quiesce(").unwrap();
    let end = service[start..]
        .find("#[path = \"service_section_pagein.rs\"]")
        .unwrap() + start;
    let body = &service[start..end];
    let legacy = body.find("if legacy {").expect("legacy-only flush branch");
    let checkpoint = body.find("checkpoint_dirty_dynamic_mutable_hives()")
        .expect("legacy dynamic checkpoint");
    let native_proof = body.find("verify_durable_v2_mutable_hives()")
        .expect("Native dynamic sidecar proof");
    assert!(legacy < checkpoint && checkpoint < native_proof);
}
