//! A callback ID is scoped to one dispatch. Retained lane transfers need their own identity.

#[test]
fn nested_callbacks_do_not_reuse_their_dispatch_local_header_ids_as_lane_tokens() {
    let transfer = include_str!("../../../components/ntos-executive/src/component_callback_transfer.rs");
    assert!(transfer.contains("binding.external_token()"),
        "capture must return the retained frame's unique external transfer token");

    let glue = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");
    assert!(glue.contains("USER_CALLBACK_TRANSFER_IDS"),
        "the root must mint a distinct token for every active callback");
    for name in ["active_callback_lane_and_token", "pending_callback_token_on_lane"] {
        let body = glue.split(&format!("unsafe fn {name}(")).nth(1).unwrap()
            .split("\n}").next().unwrap();
        assert!(body.contains("frame.external_token()"),
            "{name} must use the retained frame token");
        assert!(!body.contains("callback_id"),
            "{name} must not treat a dispatch-local callback ID as an external token");
    }
    let resume = glue.split("unsafe fn resume_suspended_user_callback_component(")
        .nth(1).unwrap().split("\n}").next().unwrap();
    assert!(!resume.contains("let callback_token = u64::from(request.callback_id)"));
}
