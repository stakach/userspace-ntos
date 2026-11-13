//! The isolated CM service maps the shared executable image read-only.
//! Its diagnostics must not mutate statics stored in that image.

use std::collections::HashSet;
use syn::{visit::Visit, Expr, ExprMethodCall, Item};

struct StaticWriteAudit {
    statics: HashSet<String>,
    writes: Vec<String>,
}

impl<'ast> Visit<'ast> for StaticWriteAudit {
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if matches!(call.method.to_string().as_str(),
            "fetch_add" | "fetch_sub" | "store" | "swap" | "compare_exchange" | "compare_exchange_weak")
        {
            if let Expr::Path(path) = call.receiver.as_ref() {
                if let Some(name) = path.path.get_ident() {
                    if self.statics.contains(&name.to_string()) {
                        self.writes.push(name.to_string());
                    }
                }
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn isolated_cm_service_does_not_write_shared_image_statics() {
    let source = include_str!("../../../components/ntos-executive/src/cm_server.rs");
    let file = syn::parse_file(source).expect("CM service syntax");
    let statics = file.items.iter().filter_map(|item| match item {
        Item::Static(item) => Some(item.ident.to_string()),
        _ => None,
    }).collect();
    let mut audit = StaticWriteAudit { statics, writes: Vec::new() };
    audit.visit_file(&file);
    assert!(audit.writes.is_empty(),
        "isolated CM service writes read-only image statics: {:?}", audit.writes);
}
