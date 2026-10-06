use syn::visit::Visit;

const FOCUSED: &str =
    include_str!("../../../components/ntos-executive/src/termination_port_notifications.rs");
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

fn notification_calls() -> Calls {
    for item in syn::parse_file(FOCUSED).unwrap().items {
        if let syn::Item::Fn(function) = item {
            if function.sig.ident == "notify_thread_termination_ports" {
                let mut calls = Calls::default();
                calls.visit_block(&function.block);
                return calls;
            }
        }
    }
    panic!("actual termination notification entrypoint");
}

#[test]
fn termination_registration_retains_real_broker_object_before_canonical_storage() {
    let mut calls = Calls::default();
    for item in syn::parse_file(FOCUSED).unwrap().items {
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
        "retained_request_port_outcome",
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
    assert!(
        position("begin_thread_termination_port_delivery")
            < position("retained_request_port_outcome")
    );
    assert!(
        position("retained_request_port_outcome")
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

#[test]
fn checked_broker_refusal_has_a_distinct_terminal_transition() {
    let calls = notification_calls();
    assert!(
        calls
            .0
            .iter()
            .any(|call| call == "retained_request_port_outcome"),
        "raw NtStatus cannot distinguish checked no-enqueue refusal from transport uncertainty"
    );
    assert!(calls.0.iter().any(|call| call == "acknowledge_thread_termination_port_refusal"),
        "known PORT_DISCONNECTED must settle delivery without fabricating delivery success or pinning the registration forever");
    #[derive(Default)]
    struct RefusalArm(bool);
    #[derive(Default)]
    struct RefusalPattern(bool);
    impl<'a> Visit<'a> for RefusalPattern {
        fn visit_pat_tuple_struct(&mut self, pattern: &'a syn::PatTupleStruct) {
            self.0 |= pattern.path.segments.last().unwrap().ident == "Refused";
            syn::visit::visit_pat_tuple_struct(self, pattern);
        }
        fn visit_pat_struct(&mut self, pattern: &'a syn::PatStruct) {
            self.0 |= pattern.path.segments.last().unwrap().ident == "Refused";
            syn::visit::visit_pat_struct(self, pattern);
        }
    }
    impl<'a> Visit<'a> for RefusalArm {
        fn visit_arm(&mut self, arm: &'a syn::Arm) {
            let mut pattern = RefusalPattern::default();
            pattern.visit_pat(&arm.pat);
            if pattern.0 {
                let mut calls = Calls::default();
                calls.visit_expr(&arm.body);
                self.0 |= calls
                    .0
                    .iter()
                    .any(|name| name == "acknowledge_thread_termination_port_refusal")
                    && !calls
                        .0
                        .iter()
                        .any(|name| name == "acknowledge_thread_termination_port_delivery");
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut refused = RefusalArm::default();
    refused.visit_file(&syn::parse_file(FOCUSED).unwrap());
    assert!(
        refused.0,
        "checked refusal must not be reported as a delivered notification"
    );
}
