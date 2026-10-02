use syn::visit::{self, Visit};
use syn::{ExprCall, Item};

#[derive(Default)]
struct OverlayCalls {
    secured: usize,
    raw: usize,
}

impl<'ast> Visit<'ast> for OverlayCalls {
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            if let Some(name) = path.path.segments.last().map(|segment| &segment.ident) {
                if name == "compose_system_hive_overlay_secured" {
                    self.secured += 1;
                } else if name == "compose_system_hive_overlay" {
                    self.raw += 1;
                }
            }
        }
        visit::visit_expr_call(self, call);
    }
}

#[test]
fn boot_system_overlay_assigns_generated_security_before_publication() {
    let file = syn::parse_file(include_str!("../../nt-hive-regf/src/lib.rs")).unwrap();
    let function = file.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "compose_boot_system_hive" => Some(function),
        _ => None,
    }).expect("boot SYSTEM composition entrypoint");
    let mut calls = OverlayCalls::default();
    calls.visit_block(&function.block);
    assert!(calls.secured != 0,
        "boot SYSTEM composition must assign inherited security to additive keys before publication");
    assert_eq!(calls.raw, 0,
        "boot SYSTEM composition must not publish additive keys through the raw overlay API");
}

// Access-time descriptor substitution remains an ownership review: inherited descriptors must
// already be retained in the composed hive, not synthesized while opening individual keys.
