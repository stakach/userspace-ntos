//! GDI helper images load after the installed mount has transferred to native storage.
//! A direct Executive FAT read is fenced in that phase and cannot supply a PE snapshot.

const LOADER: &str = include_str!("../../../components/ntos-executive/src/win32k_image_loader.rs");
const INGRESS: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
const PUMP: &str = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
const WORK: &str = include_str!("../../../components/ntos-executive/src/gdi_routed_image_work.rs");

#[test]
fn native_gdi_image_load_routes_away_from_the_retired_boot_fat_owner() {
    let start = INGRESS.find("pub(crate) unsafe fn service_win32k_gdi_image_request(")
        .expect("authenticated GDI ingress");
    let body = &INGRESS[start..];
    let end = body.find("\n}").expect("GDI ingress end");
    let body = &body[..end];
    assert!(body.contains("BlockSourceKind::Boot")
        && body.contains("BlockSourceKind::Native")
        && body.contains("submit_routed_gdi_image"),
        "native GDI image loads must retain routed work instead of entering Boot FAT");
    let start = LOADER.find("fn load_installed_from_catalog(")
        .expect("routed catalog mapper");
    let source = &LOADER[start..];
    let end = source.find("\n}").expect("catalog mapper end");
    assert!(!source[..end].contains("fat_open_path(")
        && !source[..end].contains("fat_read_file("),
        "routed catalog mapping must not issue a Boot FAT read");
}

#[test]
fn gdi_source_call_retains_reply_until_mounted_file_snapshot_is_complete() {
    let start = PUMP.find("W32_GDI_LOAD_LABEL\n").expect("GDI provider branch");
    let branch = &PUMP[start..];
    let end = branch.find("W32_LPC_LABEL").expect("next provider branch");
    let branch = &branch[..end];
    assert!(branch.contains("SubmitResult::Deferred")
        && branch.contains("service_wait_yields"),
        "GDI provider Call must stay owned while mounted CREATE/READ IRPs are pending");

    let start = INGRESS.find("pub(crate) unsafe fn service_win32k_gdi_image_request(")
        .expect("authenticated GDI ingress");
    let body = &INGRESS[start..];
    let end = body.find("\n}").expect("GDI ingress end");
    assert!(body[..end].contains("park_retained_service")
        || body[..end].contains("submit_routed_gdi_image"),
        "authenticated GDI ingress must transfer exact provider Reply to retained routed work");
}

#[test]
fn quarantined_gdi_owner_does_not_arm_an_autonomous_retry_forever() {
    let start = WORK.find("pub(crate) fn next_deadline()")
        .expect("GDI retained work deadline");
    let body = &WORK[start..];
    let end = body.find("\n}").expect("deadline end");
    assert!(body[..end].contains("!work.indeterminate"),
        "only actionable GDI owners may arm the retry timer; quarantined owners stay retained");
}

#[test]
fn quarantined_gdi_owner_still_blocks_host_quiescence() {
    assert!(WORK.contains("pub(crate) fn has_outstanding()"),
        "quarantined GDI work needs an independent ownership gate");
    assert!(INGRESS.contains("!crate::gdi_routed_image_work::has_outstanding()"),
        "host quiescence cannot infer no owned Call from absence of a timer deadline");
}

#[test]
fn stopped_provider_call_retires_after_gdi_file_cleanup_without_waiting_for_a_reply() {
    let start = WORK.find("impl Work {").expect("retained GDI owner");
    let body = &WORK[start..];
    assert!(body.contains("acknowledge_retained_service_cancellation")
        && body.contains("Phase::ReadyReply =>")
        && body.contains("Phase::ReplyEntered =>")
        && body.contains("retained_service_cancelled"),
        "sealed stop must retire the exact GDI Call and requestor after semantic I/O cleanup");
}

#[test]
fn cancelled_post_map_gdi_effect_keeps_exact_owner_quarantined() {
    assert!(WORK.contains("mapped_effect: bool")
        && WORK.contains("self.mapped_effect || self.module != 0")
        && WORK.contains("self.indeterminate = true"),
        "a mapped image or acquired load ref cannot be rolled back on provider stop");
}
