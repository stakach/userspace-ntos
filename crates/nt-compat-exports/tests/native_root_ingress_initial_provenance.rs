//! The dormant ordinary root pass requires an initial GUI dispatch, not a resumed pump.

const CHANNEL: &str = include_str!("../../../components/ntos-executive/src/spawn_hosts.rs");
const GLUE: &str = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");
const RECEIVE: &str = include_str!("../../../components/ntos-executive/src/win32k_receive.rs");

#[test]
fn only_initial_ssdt_dispatch_mints_root_provenance() {
    assert!(CHANNEL.contains("initial_root_dispatch: Option<InitialRootDispatchProvenance>"));
    let initial = GLUE
        .split("let Some(mut ch) = win32k_lane_channel(")
        .nth(1)
        .expect("initial GUI dispatch")
        .split("let mut pr = crate::spawn_hosts::component_pump(&ch);")
        .next()
        .unwrap();
    assert!(initial.contains("ch.initial_root_dispatch ="));
    assert!(initial.contains("WIN32K_REQUEST_SSDT"));
    assert!(initial.contains("!nested_user_callback && outer_callback.is_none()"));
    assert_eq!(GLUE.matches("ch.initial_root_dispatch =").count(), 1,
        "only the initial GUI SSDT dispatch may mint this observation");

    let constructors = GLUE.split("Some(crate::spawn_hosts::PumpChannel {").nth(1).unwrap();
    assert!(constructors.split("caps: crate::spawn_hosts::HostCaps").next().unwrap()
        .contains("initial_root_dispatch: None"));
    for resumed in ["channel.caps.hosted_receive_yield = allow_receive_yield",
        "channel.caps.hosted_receive_yield = !pending.nested_user_callback"] {
        let paths: Vec<_> = GLUE.split(resumed).skip(1).collect();
        assert!(!paths.is_empty(), "resumed provider/callback path must remain visible");
        for path in paths {
            assert!(!path.split("component_pump(&channel)").next().unwrap().contains(
                "channel.initial_root_dispatch ="),
                "resumed callback/provider/LPC pump must not mint initial provenance");
        }
    }
}

#[test]
fn dormant_root_preflight_reauthenticates_token_and_live_owner() {
    let preflight = RECEIVE
        .split("pub(crate) unsafe fn prepare_root_ingress_yield(")
        .nth(1).unwrap()
        .split("pub(crate) unsafe fn ")
        .next().unwrap();
    for required in ["channel.initial_root_dispatch",
        "parent_route.route != provenance.route()", "parent_route.dispatch != provenance.dispatch()",
        "parent_route.binding.executor_id != provenance.tcb()",
        "parent_route.binding.reply_object != provenance.reply()"] {
        assert!(preflight.contains(required), "missing initial provenance check: {required}");
    }
    for required in ["runtime::channel_route(channel)", "runtime::dispatch(route)",
        "runtime::current_reply(route)", "lanes.is_dispatch_identity_active(dispatch)",
        "binding.executor_id != channel.tcb", "binding.reply_object != reply"] {
        assert!(CHANNEL.contains(required), "missing live owner recheck: {required}");
    }
    assert!(!preflight.contains("InitialRootDispatchProvenance::capture"),
        "provider pump must compare existing authenticated snapshot without reentering root capture");
}
