//! The real process/thread callouts can block on push locks. Their provider wait must retain
//! the same authenticated hosted caller and physical dispatch as an SSDT wait.

#[test]
fn hosted_ps_provider_callouts_admit_exact_wait_owner() {
    let native = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    let root = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");
    assert!(native.contains("WIN32K_REQUEST_PS_PROVIDER"));
    let activation = native.split("let hosted_owner = if ").nth(1)
        .expect("native dispatch must choose the retained wait owner")
        .split("let activation = if").next().unwrap();
    assert!(activation.contains("hosted_ps_owner")
        && activation.contains("hosted_wait_owner_at_dispatch(header)"),
        "Ps provider callout must bind the exact hosted wait owner before entering native code");
    assert!(native.contains("hosted_ps_owner && request_kind != WIN32K_REQUEST_PS_PROVIDER"),
        "the hosted owner bit must be exclusive to Ps provider controls");
    assert!(root.contains("WIN32K_REQUEST_HOSTED_PS_OWNER")
        && root.contains("client.logical_caller.is_some()"),
        "the root must stage the hosted owner claim only from an authenticated logical caller");
    let channel = root.split("let Some(mut ch) = win32k_lane_channel(").nth(1)
        .expect("native dispatch must enter a physical channel")
        .split(") else {").next().unwrap();
    assert!(channel.contains("WIN32K_REQUEST_PS_PROVIDER"),
        "the physical pump must admit the same Ps provider wait kind");
}
