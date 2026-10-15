use syn::{visit::Visit, Expr, ImplItem, Item};

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src").join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn visit_function(file: &syn::File, name: &str, visitor: &mut impl for<'a> Visit<'a>) {
    for item in &file.items {
        match item {
            Item::Fn(function) if function.sig.ident == name => visitor.visit_block(&function.block),
            Item::Impl(implementation) => {
                for item in &implementation.items {
                    if let ImplItem::Fn(function) = item {
                        if function.sig.ident == name { visitor.visit_block(&function.block); }
                    }
                }
            }
            _ => {}
        }
    }
}

fn calls(file: &syn::File, name: &str) -> Vec<String> {
    let mut calls = Calls::default();
    visit_function(file, name, &mut calls);
    calls.0
}

#[test]
fn inline_mpr_uses_held_ack_instead_of_terminal_ack() {
    #[derive(Default)]
    struct HeldBranch(bool);
    impl<'ast> Visit<'ast> for HeldBranch {
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            struct Mpr(bool);
            impl<'ast> Visit<'ast> for Mpr {
                fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
                    if path.path.segments.last().is_some_and(|s| s.ident == "MoreProcessingRequired") {
                        self.0 = true;
                    }
                    syn::visit::visit_expr_path(self, path);
                }
            }
            let mut mpr = Mpr(false);
            mpr.visit_expr(&branch.cond);
            let mut functions = Calls::default();
            functions.visit_block(&branch.then_branch);
            if mpr.0 && functions.0.iter().any(|name| name == "acknowledge_inline_held") {
                assert!(!functions.0.iter().any(|name| name == "s_io_free_irp"),
                    "MPR returns source ownership without freeing its graph");
                self.0 = true;
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let file = source("driver_launch.rs");
    let mut branch = HeldBranch::default();
    visit_function(&file, "s_iof_call_driver", &mut branch);
    assert!(branch.0, "actual MPR receipt must select Held ACK rather than unconditional op2");
    let helper = calls(&source("hosted_forward_origin.rs"), "acknowledge_inline_held");
    assert!(helper.iter().any(|name| name == "call_on4"), "Held ACK is a real broker exchange");
}

#[test]
fn held_ack_preserves_exact_work_without_retirement_or_completion_replay() {
    for name in ["hosted_read_work.rs", "hosted_flush_work.rs", "hosted_query_information_work.rs"] {
        let file = source(name);
        let admission = calls(&file, "acknowledge_held");
        for required in ["instance_for_pump_channel", "hosted_driver_pump_caller_tcb",
            "resolve", "completion_command", "hold_inline"] {
            assert!(admission.iter().any(|name| name == required),
                "{name} Held ACK lacks exact source/physical/Reply admission: {required}");
        }
        for forbidden in ["retire_after_terminal", "release_pending_terminal", "release", "begin_terminal"] {
            assert!(!admission.iter().any(|name| name == forbidden),
                "Held ACK cannot settle terminal ownership in {name}: {forbidden}");
        }
        let held = calls(&file, "advance_inline_held");
        assert!(held.iter().any(|name| name == "completion_finished"),
            "{name} must wait for an actual later source completion");
        assert!(held.iter().any(|name| name == "retire_after_terminal"));
        for forbidden in ["begin_terminal", "dispatch_provider", "complete_hosted_irp", "publish_source"] {
            assert!(!held.iter().any(|name| name == forbidden),
                "{name} must not replay completion or lower dispatch after MPR: {forbidden}");
        }
        assert!(calls(&file, "advance").iter().any(|name| name == "advance_inline_held"));
        assert!(calls(&file, "ready_for_nested_step").iter().any(|name| name == "inline_held"));
    }
}

#[test]
fn each_forward_service_admits_distinct_op4_held_ack() {
    #[derive(Default)]
    struct HeldOperation(bool);
    impl<'ast> Visit<'ast> for HeldOperation {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if matches!(&arm.pat, syn::Pat::Lit(lit)
                if matches!(&lit.lit, syn::Lit::Int(number) if matches!(number.base10_parse::<u64>(), Ok(4)))) {
                let mut functions = Calls::default();
                functions.visit_expr(&arm.body);
                if functions.0.iter().any(|name| name == "acknowledge_held") { self.0 = true; }
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let file = source("driver_launch.rs");
    for name in ["service_hosted_read_forward", "service_hosted_flush_forward",
        "service_hosted_query_information_forward"] {
        let mut operation = HeldOperation::default();
        visit_function(&file, name, &mut operation);
        assert!(operation.0, "{name} needs op4 without abusing Pending/terminal ACK");
    }
}

#[test]
fn native_origin_embeds_the_tested_hold_policy_without_duplicate_boolean() {
    let file = source("hosted_forward_origin.rs");
    let fields = file.items.iter().find_map(|item| match item {
        Item::Struct(record) if record.ident == "HostedForwardOrigin" => Some(&record.fields),
        _ => None,
    }).unwrap();
    assert!(fields.iter().any(|field| matches!(&field.ty, syn::Type::Path(path)
        if path.path.segments.last().is_some_and(|s| s.ident == "HostedForwardInlineHold"))),
        "origin must own the actual tested phase policy, not duplicate its state");
    assert!(!fields.iter().any(|field| field.ident.as_ref().is_some_and(|name| name == "inline_held")
        && matches!(&field.ty, syn::Type::Path(path)
            if path.path.is_ident("bool"))));
    assert!(calls(&file, "hold_inline").iter().any(|name| name == "report_held"));
    assert!(calls(&file, "inline_held").iter().any(|name| name == "phase"));
}
