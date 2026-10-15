use syn::{visit::Visit, Expr, Item};

fn poll(name: &str) -> syn::ItemFn {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../components/ntos-executive/src/driver_launch.rs"
    ))
    .expect("current native hosted completion adapter");
    syn::parse_file(&source)
        .unwrap()
        .items
        .into_iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .expect("actual canonical completion poll")
}

#[derive(Default)]
struct Names(Vec<String>);

impl<'ast> Visit<'ast> for Names {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.0.push(ident.to_string());
    }
}

fn names(expression: &Expr) -> Vec<String> {
    let mut names = Names::default();
    names.visit_expr(expression);
    names.0
}

#[test]
fn original_caller_publication_waits_for_exact_forwarding_pin_retirement() {
    #[derive(Default)]
    struct Contract {
        copy_claim: bool,
        gate: bool,
        ready_restored: bool,
        inside_gate: bool,
        candidate: bool,
        selected_best: bool,
        publication: bool,
    }
    impl<'ast> Visit<'ast> for Contract {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if matches!(&local.pat, syn::Pat::Tuple(_))
                && matches!(local.init.as_ref().map(|init| &*init.expr),
                    Some(Expr::Try(try_expr)) if matches!(&*try_expr.expr,
                        Expr::Path(path) if path.path.is_ident("best")))
            {
                assert!(self.gate && self.candidate,
                    "publication must extract only an exactly admitted best candidate");
                self.selected_best = true;
            }
            if matches!(&local.pat, syn::Pat::Ident(ident) if ident.ident == "publishable") {
                assert!(self.copy_claim && !self.candidate && !self.publication,
                    "exact pin admission must follow the COPY claim and precede selection");
                struct GateCall<'ast>(Option<&'ast syn::ExprCall>);
                impl<'ast> Visit<'ast> for GateCall<'ast> {
                    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                        if matches!(&*call.func, Expr::Path(path)
                            if path.path.segments.last().is_some_and(|part|
                                part.ident == "caller_completion_publishable"))
                        {
                            assert!(self.0.is_none(), "one exact forwarding pin gate");
                            self.0 = Some(call);
                        }
                        syn::visit::visit_expr_call(self, call);
                    }
                }
                let mut gate_call = GateCall(None);
                gate_call.visit_expr(&local.init.as_ref().expect("publishable initializer").expr);
                let call = gate_call.0.expect("exact forwarding pin admission gate");
                assert_eq!(call.args.len(), 7, "exact caller projection tuple");
                for (index, required) in [
                    (0, "storage_instance"),
                    (1, "node"),
                    (2, "ready_state"),
                    (3, "canonical_irp_id"),
                    (4, "irp"),
                    (5, "source_ticket_id"),
                    (6, "source_ticket_generation"),
                ] {
                    assert!(names(&call.args[index]).iter().any(|name| name == required),
                        "argument {index} must retain {required}");
                }
                self.gate = true;
            }
            syn::visit::visit_local(self, local);
        }

        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            if matches!(&*expression.cond, Expr::Path(path) if path.path.is_ident("publishable")) {
                assert!(self.gate && self.ready_restored,
                    "candidate selection must follow exact pin admission and COPY restoration");
                assert!(expression.else_branch.is_none(),
                    "a pinned completion must not select or publish through an else branch");
                self.inside_gate = true;
                self.visit_block(&expression.then_branch);
                self.inside_gate = false;
            } else {
                syn::visit::visit_expr_if(self, expression);
            }
        }

        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "compare_exchange" {
                let arguments = call.args.iter().flat_map(names).collect::<Vec<_>>();
                if arguments.iter().any(|name| name == "copying_state") {
                    assert!(!self.gate, "COPY must be claimed before pin admission");
                    self.copy_claim = true;
                }
                if arguments.iter().any(|name| name == "published_state") {
                    assert!(self.gate && self.candidate && self.selected_best,
                        "PUBLISHED transition must follow admitted best extraction");
                    self.publication = true;
                }
            }
            if call.method == "store"
                && call.args.iter().any(|arg| names(arg).iter().any(|name| name == "ready_state"))
            {
                assert!(self.gate && !self.candidate,
                    "COPY restoration must follow pin admission and precede selection");
                self.ready_restored = true;
            }
            syn::visit::visit_expr_method_call(self, call);
        }

        fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
            if matches!(&*assignment.left, Expr::Path(path) if path.path.is_ident("best")) {
                assert!(self.inside_gate && self.ready_restored,
                    "best candidate must be selected only inside the admitted pin branch");
                self.candidate = true;
            }
            syn::visit::visit_expr_assign(self, assignment);
        }
    }
    let mut contract = Contract::default();
    contract.visit_item_fn(&poll("poll_hosted_completion_at_storage"));
    assert!(contract.copy_claim && contract.gate && contract.ready_restored
        && contract.candidate && contract.selected_best && contract.publication);
    let mut wrapper = Names::default();
    wrapper.visit_item_fn(&poll("poll_hosted_completion"));
    assert!(wrapper.0.iter().any(|name| name == "poll_hosted_completion_at_storage"));
    assert!(wrapper.0.iter().any(|name| name == "hosted_completion_storage_instance"));
}

#[test]
fn cleared_ticket_fields_cannot_bypass_retained_canonical_projection() {
    let source = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../components/ntos-executive/src/hosted_source_irp_ledger.rs"
    ))
    .unwrap();
    let helper = syn::parse_file(&source)
        .unwrap()
        .items
        .into_iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "caller_completion_publishable" => Some(function),
            _ => None,
        })
        .expect("actual retained projection publication policy");
    #[derive(Default)]
    struct Contract {
        locked: bool,
        domain: bool,
        guarded_zero: bool,
    }
    impl<'ast> Visit<'ast> for Contract {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*call.func {
                self.locked |= path.path.is_ident("lock");
                self.domain |= path.path.is_ident("instance_domain_identity");
            }
            syn::visit::visit_expr_call(self, call);
        }

        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            let condition = names(&expression.cond);
            if condition.iter().any(|name| name == "ticket_id")
                && condition.iter().any(|name| name == "ticket_generation")
            {
                assert!(self.locked && self.domain,
                    "zero ticket fields cannot bypass canonical projection/domain ownership");
                let mut body = Names::default();
                body.visit_block(&expression.then_branch);
                for required in ["caller_projections", "HostedCaller", "instance_index", "domain",
                    "node", "component_address", "raw_irp", "any"] {
                    assert!(body.0.iter().any(|name| name == required),
                        "zero-ticket acceptance must exclude canonical projection {required}");
                }
                struct Absence(bool);
                impl<'ast> Visit<'ast> for Absence {
                    fn visit_expr_unary(&mut self, expression: &'ast syn::ExprUnary) {
                        if matches!(expression.op, syn::UnOp::Not(_))
                            && matches!(&*expression.expr, Expr::MethodCall(call) if call.method == "any")
                        {
                            self.0 = true;
                        }
                        syn::visit::visit_expr_unary(self, expression);
                    }
                }
                let mut absence = Absence(false);
                absence.visit_block(&expression.then_branch);
                assert!(absence.0, "only absence of a retained projection permits zero-ticket publication");
                self.guarded_zero = true;
            }
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let mut contract = Contract::default();
    contract.visit_item_fn(&helper);
    assert!(contract.guarded_zero);
}
