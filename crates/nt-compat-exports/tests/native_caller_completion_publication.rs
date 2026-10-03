use syn::{visit::Visit, Expr, Item};

fn poll() -> syn::ItemFn {
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
            Item::Fn(function) if function.sig.ident == "poll_hosted_completion" => Some(function),
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
        gate: bool,
        candidate: bool,
        publication: bool,
    }
    impl<'ast> Visit<'ast> for Contract {
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            if let Expr::Unary(negated) = &*expression.cond {
                if matches!(negated.op, syn::UnOp::Not(_)) {
                    if let Expr::Call(call) = &*negated.expr {
                        if matches!(&*call.func, Expr::Path(path)
                            if path.path.segments.last().is_some_and(|part|
                                part.ident == "caller_completion_publishable"))
                        {
                            assert!(!self.candidate && !self.publication,
                                "pin admission must precede candidate selection and publication");
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
                            let mut body = Names::default();
                            body.visit_block(&expression.then_branch);
                            for forbidden in ["acknowledge_pending_irp_completion",
                                "release_pending_irp_graph_component", "store", "compare_exchange"] {
                                assert!(!body.0.iter().any(|name| name == forbidden),
                                    "a pinned completion must not acknowledge, free or publish");
                            }
                            struct Skip(bool);
                            impl<'ast> Visit<'ast> for Skip {
                                fn visit_expr_continue(&mut self, _: &'ast syn::ExprContinue) {
                                    self.0 = true;
                                }
                            }
                            let mut skip = Skip(false);
                            skip.visit_block(&expression.then_branch);
                            assert!(skip.0, "refusal must leave the node retained and scan another node");
                            self.gate = true;
                        }
                    }
                }
            }
            syn::visit::visit_expr_if(self, expression);
        }

        fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
            if matches!(&*assignment.left, Expr::Path(path) if path.path.is_ident("best")) {
                assert!(self.gate, "original caller publication lacks exact forwarding pin gate");
                self.candidate = true;
            }
            syn::visit::visit_expr_assign(self, assignment);
        }

        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            if path.path.is_ident("HOSTED_IRP_PUBLISHED") {
                assert!(self.gate, "READY must not become PUBLISHED while forwarding pins remain");
                self.publication = true;
            }
            syn::visit::visit_expr_path(self, path);
        }
    }
    let mut contract = Contract::default();
    contract.visit_item_fn(&poll());
    assert!(contract.gate && contract.candidate && contract.publication);
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
