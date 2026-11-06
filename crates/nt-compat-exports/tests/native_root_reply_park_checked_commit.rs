//! A newly admitted maintenance owner must never panic or reuse a Reply on park refusal.

const PARK: &str = include_str!("../../../components/ntos-executive/src/root_reply_park.rs");
const ROOT: &str = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");

#[test]
fn checked_root_reply_park_validates_before_mutating_pool_or_main_slot() {
    let body = PARK.split("fn try_commit(").nth(1)
        .expect("checked park commit")
        .split("pub(crate) unsafe fn quarantine_current_hosted_reply").next().unwrap();
    assert!(body.contains("REPLY_MAIN_SLOT.load"));
    assert!(body.contains("wait_reply_pool_find_cap"));
    assert!(body.contains("can_park_hosted_reply"));
    assert!(body.contains("wait_reply_pool_mark_used"));
    assert!(body.contains("REPLY_MAIN_SLOT.store"));
    assert!(!body.contains("assert!") && !body.contains("expect("),
        "checked commit cannot panic after the native hold entered");
}

#[test]
fn maintenance_admission_retains_owner_if_root_reply_park_refuses() {
    let admit = ROOT.split("unsafe fn admit_pending_win32k_dispatch(").nth(1).unwrap()
        .split("unsafe fn component_suspension_cancel_scope(").next().unwrap();
    assert!(admit.contains("reply_park.try_commit()"));
    assert!(admit.contains("retained_failure: true"));
}
