//! The win32k shared callback and selected-context cells are one physical publication.
//! A different lane may use that publication while Receive or an external service wait is
//! suspended, so continuation must restore the exact owner's cells before native execution.

use syn::{visit::Visit, Expr, Item};

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name}"))
}

fn call_position(function: &syn::ItemFn, name: &str) -> Option<usize> {
    struct Calls<'a> {
        wanted: &'a str,
        next: usize,
        position: Option<usize>,
    }
    impl<'ast> Visit<'ast> for Calls<'_> {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = call.func.as_ref() {
                if path.path.segments.last().is_some_and(|part| part.ident == self.wanted) {
                    self.position.get_or_insert(self.next);
                }
            }
            self.next += 1;
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut calls = Calls {
        wanted: name,
        next: 0,
        position: None,
    };
    calls.visit_block(&function.block);
    calls.position
}

#[test]
fn receive_and_service_wait_restore_their_own_shared_publication_before_receiving() {
    let pending = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_pending_dispatch.rs"
    ))
    .unwrap();
    for name in ["PendingReceiveDispatch", "PendingServiceWaitDispatch"] {
        let fields = pending.items.iter().find_map(|item| match item {
            Item::Struct(record) if record.ident == name => Some(&record.fields),
            _ => None,
        }).unwrap_or_else(|| panic!("missing {name}"));
        assert!(fields.iter().any(|field| field.ident.as_ref().is_some_and(|id| id == "shared_resume")),
            "{name} must retain the callback header and selected context across a yield");
    }

    let bridge = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_glue.rs"
    ))
    .unwrap();
    let bridge_source = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");
    for name in ["PendingReceiveDispatch", "PendingServiceWaitDispatch"] {
        assert!(bridge_source.contains(&format!("{name} {{")));
    }
    assert!(bridge_source.contains("capture_shared_resume_snapshot"),
        "the initial yielded dispatch must retain its own shared publication");
    drop(bridge);

    let resume = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_receive.rs"
    ))
    .unwrap();
    for (name, continuation) in [
        ("resume_suspended_receive_component", "component_pump_continue_receive"),
        ("resume_suspended_service_wait_component", "component_pump_continue_service_wait"),
    ] {
        let function = function(&resume, name);
        let restore = call_position(function, "restore_shared_resume_snapshot")
            .unwrap_or_else(|| panic!("{name} must restore its exact shared publication"));
        let receive = call_position(function, continuation)
            .unwrap_or_else(|| panic!("{name} must continue the retained receive half"));
        assert!(restore < receive,
            "{name} must restore the callback header and selected context before native receive");
    }
}
