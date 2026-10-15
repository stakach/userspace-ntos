//! Native interrupt projections must retire through captured allocation identity.

use syn::visit::Visit;

const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn function<'a>(source: &'a syn::File, name: &str) -> &'a syn::Block {
    source
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == name => Some(&*item.block),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing native export {name}"))
}

#[derive(Default)]
struct DirectPoolFrees(usize);

impl<'ast> Visit<'ast> for DirectPoolFrees {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if matches!(&*call.func, syn::Expr::Path(path)
            if path.path.segments.last().is_some_and(|part| part.ident == "pool_free"))
        {
            self.0 += 1;
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn assert_no_direct_pool_free(name: &str, explanation: &str) {
    let source = syn::parse_file(DRIVER).expect("native driver source parses");
    let mut frees = DirectPoolFrees::default();
    frees.visit_block(function(&source, name));
    assert_eq!(frees.0, 0, "{name}: {explanation}; direct pool frees: {}", frees.0);
}

#[test]
fn disconnect_interrupt_retires_captured_projection_identity() {
    assert_no_direct_pool_free(
        "s_io_disconnect_interrupt",
        "a driver can overwrite the shared active interrupt pointer; broker success for a \
         connection does not make that mutable pointer the exact allocation to free",
    );
}

#[test]
fn replacing_a_retiring_interrupt_tombstones_its_old_projection_after_canonical_retirement() {
    let source = syn::parse_file(DRIVER).expect("native driver source parses");
    struct Replacement(Vec<String>);
    impl<'ast> Visit<'ast> for Replacement {
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            let retiring = matches!(&*branch.cond, syn::Expr::Let(binding)
                if matches!(&*binding.pat, syn::Pat::TupleStruct(tuple)
                    if tuple.path.is_ident("Some")
                    && matches!(tuple.elems.first(), Some(syn::Pat::Ident(name))
                        if name.ident == "retiring")));
            if retiring {
                struct Calls(Vec<String>);
                impl<'ast> Visit<'ast> for Calls {
                    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                        if let syn::Expr::Path(path) = &*call.func {
                            if let Some(last) = path.path.segments.last() {
                                self.0.push(last.ident.to_string());
                            }
                        }
                        syn::visit::visit_expr_call(self, call);
                    }
                }
                let mut calls = Calls(Vec::new());
                calls.visit_block(&branch.then_branch);
                self.0 = calls.0;
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let mut replacement = Replacement(Vec::new());
    replacement.visit_block(function(&source, "publish_hosted_interrupt_connection_from_shared"));
    let position = |name: &str| replacement.0.iter().position(|call| call == name)
        .unwrap_or_else(|| panic!("replacement must call {name}"));
    assert!(position("admit_interrupt_projection_canonical_retirement")
        < position("retire_hosted_irq_connection"));
    assert!(position("retire_hosted_irq_connection")
        < position("mark_interrupt_projection_canonical_retired"),
        "the old raw interrupt address must become a tombstone after canonical release");
}

#[test]
fn definite_interrupt_connect_refusals_tombstone_the_escaped_projection() {
    let source = syn::parse_file(DRIVER).expect("native driver source parses");
    let body = function(&source, "publish_hosted_interrupt_connection_from_shared");
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                if let Some(last) = path.path.segments.last() {
                    self.0.push(last.ident.to_string());
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0.push(call.method.to_string());
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut calls = Calls(Vec::new());
    calls.visit_block(body);
    let cancel = "cancel_interrupt_projection_after_proven_no_effect";
    assert_eq!(calls.0.iter().filter(|call| call.as_str() == cancel).count(), 2,
        "both definite resource-manager connect refusal and acknowledged rollback retire the escaped projection");
    let connect = calls.0.iter().position(|call| call == "connect_interrupt_exact").unwrap();
    let rollback = calls.0.iter().position(|call| call == "disconnect_interrupt").unwrap();
    let cancels: Vec<_> = calls.0.iter().enumerate()
        .filter_map(|(index, call)| (call == cancel).then_some(index)).collect();
    assert!(connect < cancels[0] && rollback < cancels[1]);
}
