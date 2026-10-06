//! The physical separation query and the eventual map must refer to the same canonical root.
use syn::visit::{self, Visit};

const SOURCE: &str =
    include_str!("../../../components/ntos-executive/src/exec_private_residency.rs");

fn method(owner: &str, name: &str) -> syn::ImplItemFn {
    let file = syn::parse_file(SOURCE).expect("actual private residency source parses");
    file.items
        .into_iter()
        .find_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            let syn::Type::Path(path) = item.self_ty.as_ref() else {
                return None;
            };
            if path.path.segments.last()?.ident != owner {
                return None;
            }
            item.items.into_iter().find_map(|item| match item {
                syn::ImplItem::Fn(function) if function.sig.ident == name => Some(function),
                _ => None,
            })
        })
        .unwrap_or_else(|| panic!("actual {owner}::{name} method"))
}

fn field(expression: &syn::Expr, base: &str, member: &str) -> bool {
    let syn::Expr::Field(expression) = expression else {
        return false;
    };
    let syn::Expr::Path(path) = expression.base.as_ref() else {
        return false;
    };
    path.path.is_ident(base)
        && matches!(&expression.member, syn::Member::Named(name) if name == member)
}

struct DestinationCheck<'a> {
    arguments: [(&'a str, &'a str); 3],
    guarded: bool,
}
impl<'ast> Visit<'ast> for DestinationCheck<'_> {
    fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
        struct Refusal<'a> {
            expected: &'a [(&'a str, &'a str); 3],
            found: bool,
        }
        impl<'ast> Visit<'ast> for Refusal<'_> {
            fn visit_expr_unary(&mut self, expression: &'ast syn::ExprUnary) {
                if matches!(expression.op, syn::UnOp::Not(_)) {
                    if let syn::Expr::MethodCall(call) = expression.expr.as_ref() {
                        let observer = matches!(call.receiver.as_ref(), syn::Expr::MethodCall(receiver)
                            if receiver.method == "hosted_vspace_observer");
                        if observer
                            && call.method == "matches_mapping_destination"
                            && call.args.len() == 3
                            && call
                                .args
                                .iter()
                                .zip(self.expected.iter())
                                .all(|(argument, (base, member))| field(argument, base, member))
                        {
                            self.found = true;
                        }
                    }
                }
                visit::visit_expr_unary(self, expression);
            }
        }
        let mut refusal = Refusal {
            expected: &self.arguments,
            found: false,
        };
        refusal.visit_expr(&branch.cond);
        struct ReturnsError(bool);
        impl<'ast> Visit<'ast> for ReturnsError {
            fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
                if matches!(expression.expr.as_deref(), Some(syn::Expr::Call(call))
                    if matches!(call.func.as_ref(), syn::Expr::Path(path) if path.path.is_ident("Err")))
                {
                    self.0 = true;
                }
            }
        }
        let mut returns = ReturnsError(false);
        returns.visit_block(&branch.then_branch);
        self.guarded |= refusal.found && returns.0;
        visit::visit_expr_if(self, branch);
    }
}

#[test]
fn actual_resident_map_destination_is_checked_against_the_canonical_journal() {
    let validate = method("ResidentIo", "validate_current");
    let mut check = DestinationCheck {
        arguments: [("target", "pi"), ("target", "process"), ("target", "pml4")],
        guarded: false,
    };
    check.visit_block(&validate.block);
    assert!(check.guarded,
        "ResidentIo must refuse when the actual target.pml4 differs from the exact canonical journal root, not merely compare it to ProcExec again");
    struct MapUsesDestination(bool);
    impl<'ast> Visit<'ast> for MapUsesDestination {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(call.func.as_ref(), syn::Expr::Path(path) if path.path.is_ident("page_map_r"))
                && call.args.len() == 4
                && field(&call.args[3], "target", "pml4")
            {
                self.0 = true;
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut map = MapUsesDestination(false);
    map.visit_block(&method("ResidentIo", "map_existing").block);
    assert!(
        map.0,
        "the checked root must be the actual PageMap destination"
    );
}

#[test]
fn captured_fault_preflight_checks_the_actual_selected_root_before_residency() {
    let function = method("ExecNtHandler", "service_captured_private_read_fault");
    struct CurrentSelection(bool);
    impl<'ast> Visit<'ast> for CurrentSelection {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "current") {
                struct Origin {
                    selected: bool,
                    procs: bool,
                }
                impl<'ast> Visit<'ast> for Origin {
                    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                        self.selected |= call.method == "get"
                            && call.args.len() == 1
                            && field(&call.args[0], "binding", "pi");
                        visit::visit_expr_method_call(self, call);
                    }
                    fn visit_expr_field(&mut self, expression: &'ast syn::ExprField) {
                        self.procs |= matches!(&expression.member, syn::Member::Named(name) if name == "procs");
                        visit::visit_expr_field(self, expression);
                    }
                }
                let mut origin = Origin {
                    selected: false,
                    procs: false,
                };
                if let Some(initializer) = &local.init {
                    origin.visit_expr(&initializer.expr);
                }
                self.0 |= origin.selected && origin.procs;
            }
            visit::visit_local(self, local);
        }
    }
    let mut current = CurrentSelection(false);
    current.visit_block(&function.block);
    let mut check = DestinationCheck {
        arguments: [
            ("binding", "pi"),
            ("binding", "process"),
            ("current", "pml4"),
        ],
        guarded: false,
    };
    // Require the refusing journal check before the shared residency call, not after effects.
    struct ResidencyCall(bool);
    impl<'ast> Visit<'ast> for ResidencyCall {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0 |= call.method == "private_page_residency";
            visit::visit_expr_method_call(self, call);
        }
    }
    for statement in &function.block.stmts {
        let mut effect = ResidencyCall(false);
        effect.visit_stmt(statement);
        if effect.0 {
            assert!(check.guarded,
                "captured resident fault must reject a different selected PML4 before entering residency; physical separation of another root is insufficient");
            assert!(
                current.0,
                "the checked current.pml4 must come from the actual selected ProcExec row"
            );
            return;
        }
        check.visit_stmt(statement);
    }
    panic!("actual captured fault residency call must remain integrated");
}
