//! USER resolves and owns process window-station/desktop bindings through its real callbacks.
//! ReactOS main.c InitThreadCallback calls IntResolveDesktop/UserSetProcessWindowStation;
//! winsta.c UserSetProcessWindowStation releases the owned previous prpwinsta reference.
//! Publishing cached bodies and handles directly into PROCESSINFO bypasses that ownership.

use syn::visit::Visit;

const WIN32K: &str = include_str!("../../../../components/ntos-executive/src/win32k_subsystem.rs");

#[derive(Default)]
struct ProductionBindings {
    functions: Vec<String>,
    calls: Vec<String>,
    statics: Vec<String>,
}

impl<'ast> Visit<'ast> for ProductionBindings {
    fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
        // Include calls and function-pointer references: removing the direct invocation must not
        // leave a callback capable of injecting the same borrowed PROCESSINFO fields later.
        if let Some(segment) = expression.path.segments.last() {
            self.calls.push(segment.ident.to_string());
        }
        syn::visit::visit_expr_path(self, expression);
    }
}

fn production_bindings() -> ProductionBindings {
    let file = syn::parse_file(WIN32K).expect("actual win32k source must parse");
    let mut bindings = ProductionBindings::default();
    for item in &file.items {
        match item {
            syn::Item::Fn(function) => {
                bindings.functions.push(function.sig.ident.to_string());
                bindings.visit_block(&function.block);
            }
            syn::Item::Impl(implementation) => bindings.visit_item_impl(implementation),
            syn::Item::Static(declaration) => {
                bindings.statics.push(declaration.ident.to_string());
                bindings.visit_expr(&declaration.expr);
            }
            _ => {}
        }
    }
    bindings
}

fn forbid_synthetic_binding(bindings: &ProductionBindings, names: &[&str]) {
    for name in names {
        assert!(
            !bindings.functions.iter().any(|function| function == name),
            "remove {name}: cached USER bodies/handles must not be injected as owned process bindings"
        );
        assert!(
            !bindings.calls.iter().any(|call| call == name),
            "remove every production call/reference to {name}; real USER callbacks must resolve bindings"
        );
    }
}

#[test]
fn process_window_station_is_not_injected_from_session_cache() {
    let bindings = production_bindings();
    forbid_synthetic_binding(&bindings, &["seed_inherited_process_window_station"]);
}

#[test]
fn process_startup_desktop_is_not_injected_from_default_cache() {
    let bindings = production_bindings();
    forbid_synthetic_binding(
        &bindings,
        &[
            "seed_process_startup_desktop_for_process",
            "seed_process_startup_desktop",
            "seed_default_startup_desktop_for_process",
        ],
    );
}

#[test]
fn selected_client_desktop_is_not_reasserted_from_global_or_startup_cache() {
    let bindings = production_bindings();
    forbid_synthetic_binding(
        &bindings,
        &[
            "selected_thread_desktop",
            "publish_thread_desktop_binding",
            "process_startup_desktop",
        ],
    );
}

#[test]
fn desktop_binding_has_no_session_global_latch_authority() {
    let bindings = production_bindings();
    for name in ["BOUND_DESK_BODY", "BOUND_DESK_PDESKINFO"] {
        assert!(
            !bindings.statics.iter().any(|declaration| declaration == name),
            "remove {name}: one client's desktop cannot be retained as session-wide binding authority"
        );
        assert!(
            !bindings.calls.iter().any(|reference| reference == name),
            "remove every production reference to {name}; the real USER binding remains process/thread scoped"
        );
    }
}

#[test]
fn set_thread_desktop_does_not_unlink_or_clear_binding_before_real_operation() {
    let bindings = production_bindings();
    forbid_synthetic_binding(&bindings, &["prepare_set_thread_desktop"]);
}
