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
