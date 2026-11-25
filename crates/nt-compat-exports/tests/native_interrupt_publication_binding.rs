//! Two devices in one hosted instance must not use the other's mutable IRQ bank.
//!
//! These decisions are compiled from the native executive module used by StartDevice
//! publication and IoDisconnectInterrupt. The installed connection is root-owned; the
//! instance's shared bank may have been overwritten by a later device dispatch.

#[path = "../../../components/ntos-executive/src/hosted_device_publication_decision.rs"]
mod native_decision;

use native_decision::{InstalledInterrupt, LiveInterruptProjection, StartPublication};
use syn::visit::Visit;

const KEYBOARD_INTERRUPT: u64 = 0x1000_e803_a10;
const MOUSE_INTERRUPT: u64 = 0x1000_e803_960;

fn installed(object: u64) -> InstalledInterrupt {
    InstalledInterrupt {
        object,
        interrupt_id: 99,
        grant_generation: 7,
    }
}

fn live(object: u64) -> LiveInterruptProjection {
    LiveInterruptProjection {
        object,
        pool_generation: 3,
        connection: Some((99, 7)),
    }
}

#[test]
fn delayed_keyboard_start_uses_its_installed_connection_after_mouse_overwrites_the_bank() {
    assert_eq!(
        native_decision::start_publication(
            Some(installed(KEYBOARD_INTERRUPT)),
            Some(live(KEYBOARD_INTERRUPT)),
        ),
        StartPublication::Installed,
        "a completed keyboard connection must not replay the mouse projection",
    );
    assert_eq!(
        native_decision::start_publication(
            Some(installed(MOUSE_INTERRUPT)),
            Some(live(MOUSE_INTERRUPT)),
        ),
        StartPublication::Installed,
        "a completed connection needs no second connect even when it is still in the bank",
    );
}

#[test]
fn device_without_live_projection_has_no_interrupt_request() {
    assert_eq!(
        native_decision::start_publication(None, None),
        StartPublication::NoInterrupt,
        "the mouse bank cannot cause a keyboard interrupt connect",
    );
}

#[test]
fn unresolved_exact_projection_cannot_be_replayed() {
    assert_eq!(
        native_decision::start_publication(
            None,
            Some(LiveInterruptProjection {
                object: KEYBOARD_INTERRUPT,
                pool_generation: 3,
                connection: None,
            }),
        ),
        StartPublication::Unresolved,
        "an exact pending projection must remain owned until its effect is known",
    );
}

#[test]
fn installed_connection_must_match_the_exact_live_projection() {
    assert_eq!(
        native_decision::start_publication(
            Some(installed(MOUSE_INTERRUPT)),
            Some(live(KEYBOARD_INTERRUPT)),
        ),
        StartPublication::Unresolved,
        "a live keyboard allocation cannot validate a different installed pointer",
    );
}

#[test]
fn installed_connection_must_match_the_projection_bound_tokens() {
    let mut projection = live(KEYBOARD_INTERRUPT);
    projection.connection = Some((100, 8));
    assert_eq!(
        native_decision::start_publication(Some(installed(KEYBOARD_INTERRUPT)), Some(projection)),
        StartPublication::Unresolved,
        "a matching address does not authenticate a different canonical grant",
    );
}

#[test]
fn root_disconnect_resolves_the_pointer_owner_even_during_mouse_dispatch() {
    let connections = [(11_u64, KEYBOARD_INTERRUPT), (12_u64, MOUSE_INTERRUPT)];
    assert_eq!(
        native_decision::disconnect_binding(KEYBOARD_INTERRUPT, connections),
        Some(11_u64),
        "the pointer's canonical connection owns the action, not the active mouse binding",
    );
    assert_eq!(native_decision::disconnect_binding(0, connections), None,);
}

#[test]
fn retiring_interrupt_connection_remains_retryable() {
    assert_eq!(
        native_decision::disconnect_binding(KEYBOARD_INTERRUPT, [(11_u64, KEYBOARD_INTERRUPT)],),
        Some(11_u64),
        "a retained Draining connection must still be found for the exact disconnect retry",
    );
}

#[test]
fn duplicate_live_pointer_owners_are_ambiguous() {
    assert_eq!(
        native_decision::disconnect_binding(
            KEYBOARD_INTERRUPT,
            [(11_u64, KEYBOARD_INTERRUPT), (12_u64, KEYBOARD_INTERRUPT)],
        ),
        None,
    );
}

#[test]
fn disconnecting_keyboard_does_not_clear_the_mouse_bank() {
    assert!(!native_decision::should_clear_shared_after_disconnect(
        KEYBOARD_INTERRUPT,
        MOUSE_INTERRUPT,
    ));
    assert!(native_decision::should_clear_shared_after_disconnect(
        MOUSE_INTERRUPT,
        MOUSE_INTERRUPT,
    ));
}

#[test]
fn delayed_start_does_not_reread_a_mutable_resource_snapshot() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let body = source
        .split_once("unsafe fn finish_hosted_start_publication(")
        .expect("native delayed StartDevice publication")
        .1
        .split_once("\nunsafe fn ")
        .expect("next native function")
        .0;
    assert!(body.contains("hosted_mmio_broker::validate_publication(binding, bus_owned_root_proof)?"));
    assert!(!body.contains("SH_ACTIVE_DEVICE_OBJECT"));
    assert!(!body.contains("record_hosted_mmio_usage("));
    assert!(
        !body.contains("refresh_hosted_device_resource_state(binding, sh)"),
        "a mutable active-device word is not an authenticated per-device snapshot",
    );
}

#[test]
fn native_call_sites_use_the_tested_binding_decisions() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/driver_launch.rs"
    ))
    .expect("native executive source parses");
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                if let Some(name) = path.path.segments.last() {
                    self.0.push(name.ident.to_string());
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let native_calls = |name: &str| {
        let function = source
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(item) if item.sig.ident == name => Some(item),
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing native function {name}"));
        let mut calls = Calls(Vec::new());
        calls.visit_block(&function.block);
        calls.0
    };
    assert!(native_calls("finish_hosted_start_publication").contains(&"start_publication".into()));
    assert!(native_calls("finish_hosted_start_publication").contains(&"validate_publication".into()));
    assert!(native_calls("finish_hosted_start_publication")
        .contains(&"refresh_hosted_device_interrupt_state_from_retained".into()));
    let broker = native_calls("service_hosted_driver_interrupt");
    assert!(broker.contains(&"disconnect_binding".into()));
    assert!(broker.contains(&"should_clear_shared_after_disconnect".into()));
    assert!(broker.contains(&"refresh_hosted_device_interrupt_state_from_retained".into()));
}
