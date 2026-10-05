use syn::visit::Visit;

const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const HANDLER: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");

#[derive(Default)]
struct Calls(Vec<String>);
impl<'a> Visit<'a> for Calls {
    fn visit_expr_method_call(&mut self, expression: &'a syn::ExprMethodCall) {
        self.0.push(expression.method.to_string());
        syn::visit::visit_expr_method_call(self, expression);
    }
    fn visit_expr_call(&mut self, expression: &'a syn::ExprCall) {
        if let syn::Expr::Path(path) = &*expression.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, expression);
    }
}

fn focused_native_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/termination_port_notifications.rs");
    // The current implementation lives in main/handler. An absent extraction does not
    // cause compile failure: the assertions inspect the real existing implementation.
    std::fs::read_to_string(path).unwrap_or_default()
}

fn notification_calls() -> Calls {
    let focused = focused_native_source();
    for source in [&focused[..], MAIN] {
        let parsed = syn::parse_file(source).unwrap();
        for item in parsed.items {
            if let syn::Item::Fn(function) = item {
                if function.sig.ident == "notify_thread_termination_ports" {
                    let mut calls = Calls::default();
                    calls.visit_block(&function.block);
                    return calls;
                }
            }
        }
    }
    panic!("actual termination notification entrypoint");
}

#[test]
fn termination_registration_retains_real_broker_object_before_canonical_storage() {
    let focused = focused_native_source();
    let mut calls = Calls::default();
    if focused.is_empty() {
        struct Registration<'a>(&'a mut Calls);
        impl<'a> Visit<'a> for Registration<'_> {
            fn visit_arm(&mut self, arm: &'a syn::Arm) {
                if matches!(&arm.pat, syn::Pat::Path(path) if path.path.segments.last().unwrap().ident == "NtRegisterThreadTerminatePort")
                {
                    self.0.visit_expr(&arm.body);
                }
                syn::visit::visit_arm(self, arm);
            }
        }
        Registration(&mut calls).visit_file(&syn::parse_file(HANDLER).unwrap());
    } else {
        for item in syn::parse_file(&focused).unwrap().items {
            if let syn::Item::Fn(function) = item {
                if function.sig.ident == "register_native_thread_termination_port" {
                    calls.visit_block(&function.block);
                }
            }
        }
        let mut handler_calls = Calls::default();
        handler_calls.visit_file(&syn::parse_file(HANDLER).unwrap());
        assert!(handler_calls
            .0
            .iter()
            .any(|call| call == "register_native_thread_termination_port"));
    }
    let retained = calls.0.iter().position(|call| call == "retain_port_object");
    let stored = calls
        .0
        .iter()
        .position(|call| call == "register_thread_termination_port");
    assert!(
        retained.is_some(),
        "querying a user handle does not acquire a termination-port object reference"
    );
    assert!(
        stored.is_some() && retained < stored,
        "canonical registration owns the actual retained broker reference"
    );
}

#[test]
fn termination_delivery_keeps_registration_until_checked_delivery_and_release() {
    let calls = notification_calls();
    assert!(
        !calls
            .0
            .iter()
            .any(|call| call == "pop_thread_termination_port"),
        "removing the registration before delivery loses ownership on refusal/uncertainty"
    );
    for required in [
        "peek_thread_termination_port",
        "begin_thread_termination_port_delivery",
        "retained_request_port",
        "acknowledge_thread_termination_port_delivery",
        "begin_thread_termination_port_release",
        "release_port_object_with_lifetime",
        "acknowledge_thread_termination_port_release",
    ] {
        assert!(
            calls.0.iter().any(|call| call == required),
            "actual terminal owner boundary: {required}"
        );
    }
    let position = |name| calls.0.iter().position(|call| call == name).unwrap();
    assert!(position("begin_thread_termination_port_delivery") < position("retained_request_port"));
    assert!(
        position("retained_request_port")
            < position("acknowledge_thread_termination_port_delivery")
    );
    assert!(
        position("acknowledge_thread_termination_port_delivery")
            < position("release_port_object_with_lifetime")
    );
    assert!(
        position("begin_thread_termination_port_release")
            < position("release_port_object_with_lifetime")
    );
    assert!(
        position("release_port_object_with_lifetime")
            < position("acknowledge_thread_termination_port_release")
    );
}
