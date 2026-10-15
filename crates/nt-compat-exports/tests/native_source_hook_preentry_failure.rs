//! A known pre-entry hook dispatch failure must complete each parked source Reply.

use syn::visit::Visit;

const SOURCE: &str =
    include_str!("../../../components/ntos-executive/src/hosted_input_hook_live.rs");

struct ErrorArmCalls(Vec<String>);

impl<'ast> Visit<'ast> for ErrorArmCalls {
    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        if matches!(&*expression.expr, syn::Expr::Path(path)
            if path.path.is_ident("result"))
        {
            for arm in &expression.arms {
                if matches!(&arm.pat, syn::Pat::TupleStruct(pattern)
                    if pattern.path.is_ident("Err"))
                {
                    let mut calls = Calls::default();
                    calls.visit_expr(&arm.body);
                    self.0.extend(calls.0);
                }
            }
        }
        syn::visit::visit_expr_match(self, expression);
    }
}

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(name) = path.path.segments.last() {
                self.0.push(name.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn error_arm_calls(function: &str) -> Vec<String> {
    let file = syn::parse_file(SOURCE).expect("native source parses");
    let function = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == function => Some(item),
        _ => None,
    }).unwrap_or_else(|| panic!("missing native function {function}"));
    let mut calls = ErrorArmCalls(Vec::new());
    calls.visit_block(&function.block);
    calls.0
}

#[test]
fn known_preentry_failure_reaches_class_source_terminal() {
    assert!(error_arm_calls("advance_class_source").iter().any(|name| name == "class_terminal"),
        "class lower-edge Err must publish a terminal before releasing the source Reply");
}

#[test]
fn known_preentry_failure_reaches_port_source_terminal() {
    assert!(error_arm_calls("advance_port_source").iter().any(|name| name == "stage_port_terminal"),
        "port source Err must stage a terminal before releasing the source Reply");
}
