use syn::visit::Visit;

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn cleanup_authenticates_physical_owner_before_canonical_retirement() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/provider_section_cleanup.rs"
    ))
    .unwrap();
    let mut calls = Calls::default();
    calls.visit_file(&file);
    let position = |name: &str| calls.0.iter().position(|call| call == name).unwrap();
    assert!(position("authenticate") < position("physical_win32k_provider"));
    assert!(position("physical_win32k_provider") < position("registry_live_handler_pointer"));
    assert!(position("registry_live_handler_pointer") < position("dereference"));
    assert!(position("registry_live_handler_pointer") < position("unmap"));
    assert!(!calls.0.iter().any(|call| matches!(call.as_str(),
        "resolve" | "capture_native_handle_caller" | "registry_live_handler")),
        "retained cleanup neither acquires live handle authority nor holds a handler borrow across IPC");
}

#[test]
fn physical_cleanup_admission_checks_runtime_and_provider_generations() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/provider_service_ingress.rs"
    ))
    .unwrap();
    let mut calls = Calls::default();
    calls.visit_file(&file);
    for required in [
        "channel_route",
        "current_reply",
        "dispatch",
        "physical_source",
        "validate_win32k_service_call",
        "win32k_physical_lane_for_channel",
        "current_win32k_provider_domain",
        "win32k_provider_domain_is_current",
    ] {
        assert!(
            calls.0.iter().any(|call| call == required),
            "retain {required} authority check"
        );
    }
    struct PhysicalFields(Vec<String>);
    impl<'ast> Visit<'ast> for PhysicalFields {
        fn visit_expr_binary(&mut self, expression: &'ast syn::ExprBinary) {
            if matches!(expression.op, syn::BinOp::Ne(_)) {
                if let (syn::Expr::Field(left), syn::Expr::Field(right)) =
                    (&*expression.left, &*expression.right)
                {
                    if matches!(&*left.base, syn::Expr::Path(path) if path.path.is_ident("source"))
                        && matches!(&*right.base, syn::Expr::Path(path) if path.path.is_ident("channel"))
                        && left.member == right.member
                    {
                        if let syn::Member::Named(name) = &left.member {
                            self.0.push(name.to_string());
                        }
                    }
                }
            }
            syn::visit::visit_expr_binary(self, expression);
        }
    }
    let mut fields = PhysicalFields(Vec::new());
    fields.visit_file(&file);
    assert_eq!(
        fields.0,
        ["tcb", "pml4"],
        "the exact physical sender and VSpace must agree"
    );
}

#[test]
fn retained_section_cleanup_is_selected_before_fresh_handle_admission() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/service_sec_image.rs"
    ))
    .unwrap();
    let function = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "service_win32k_section_create_request" => {
                Some(item)
            }
            _ => None,
        })
        .unwrap();
    struct Order {
        events: Vec<&'static str>,
    }
    impl<'ast> Visit<'ast> for Order {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                match path
                    .path
                    .segments
                    .last()
                    .unwrap()
                    .ident
                    .to_string()
                    .as_str()
                {
                    "authenticate_win32k_service_request" => self.events.push("live"),
                    "service_win32k_section_cleanup_request" => self.events.push("cleanup"),
                    _ => {}
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut order = Order { events: Vec::new() };
    order.visit_block(&function.block);
    assert_eq!(order.events, ["cleanup", "live"],
        "cleanup must authenticate retained provider/object ownership without first demanding a live handle caller");
}
