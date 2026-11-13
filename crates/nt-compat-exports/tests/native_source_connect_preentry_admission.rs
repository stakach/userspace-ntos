//! CONNECT preparation precedes provider entry; IRQ admission requires provider entry.

use syn::visit::Visit;

const CONNECT: &str =
    include_str!("../../../components/ntos-executive/src/hosted_connect_live.rs");
const PORT: &str =
    include_str!("../../../components/ntos-executive/src/hosted_input_connect_dispatch.rs");
const THUNK: &str =
    include_str!("../../../components/ntos-executive/src/hosted_class_callback_thunk.rs");
const REVERSE: &str =
    include_str!("../../../components/ntos-executive/src/hosted_reverse_class_projection.rs");

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

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn calls(block: &syn::Block) -> Vec<String> {
    let mut result = Calls::default();
    result.visit_block(block);
    result.0
}

fn function_calls(source: &str, name: &str) -> Vec<String> {
    let file = syn::parse_file(source).unwrap();
    let function = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(&*function.block),
        syn::Item::Impl(item) => item.items.iter().find_map(|member| match member {
            syn::ImplItem::Fn(method) if method.sig.ident == name => Some(&method.block),
            _ => None,
        }),
        _ => None,
    });
    calls(function.unwrap_or_else(|| panic!("missing native function {name}")))
}

#[test]
fn port_connect_preparation_checks_publication_without_requiring_provider_entry() {
    let submit = function_calls(CONNECT, "submit");
    let redrive = function_calls(CONNECT, "redrive");
    let redrive_inner = function_calls(CONNECT, "redrive_inner");
    let prepare = function_calls(PORT, "prepare");
    let irq = function_calls(THUNK, "admit_irq_request");
    let irq_reverse = function_calls(REVERSE, "validate_irq");

    assert!(submit.iter().any(|call| call == "prepare"));
    assert!(redrive.iter().any(|call| call == "redrive_inner"));
    assert!(redrive_inner.iter().any(|call| call == "begin_provider_entry"));
    assert!(redrive_inner.iter().any(|call| call == "nested_ready"));
    assert!(irq_reverse.iter().any(|call| call == "published_identity_without_manager"));
    assert!(irq.iter().any(|call| call == "validate_irq"));
    assert!(
        !prepare.iter().any(|call| call == "admit_irq_request"),
        "CONNECT preparation runs before provider entry and cannot use IRQ admission"
    );
    assert!(prepare.iter().any(|call| call == "validate_pre_entry"));
    let pre_entry = function_calls(THUNK, "validate_pre_entry");
    assert!(pre_entry.iter().any(|call| call == "validate"));
}
