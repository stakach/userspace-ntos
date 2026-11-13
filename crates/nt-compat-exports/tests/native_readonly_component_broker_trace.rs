//! A read-only component image can enter the shared broker before any font diagnostic is armed.
//! The idle broker path must only read diagnostic state; a write repeatedly faults that image.

use syn::{visit::Visit, BinOp, Expr, ExprMethodCall, Item};

fn is_trace_access(call: &ExprMethodCall, method: &str) -> bool {
    call.method.to_string() == method
        && matches!(call.receiver.as_ref(), Expr::Path(path)
            if path.path.is_ident("NEXT_FONT_BROKER_TRACE"))
}

fn is_zero(expression: &Expr) -> bool {
    matches!(expression, Expr::Lit(literal)
        if matches!(&literal.lit, syn::Lit::Int(value) if value.base10_parse::<u64>().ok() == Some(0)))
}

fn reads_nonzero_trace(expression: &Expr) -> bool {
    let Expr::Binary(binary) = expression else { return false };
    if !matches!(binary.op, BinOp::Ne(_)) { return false }
    let is_load = |expression: &Expr| {
        matches!(expression, Expr::MethodCall(call) if is_trace_access(call, "load"))
    };
    (is_load(&binary.left) && is_zero(&binary.right))
        || (is_zero(&binary.left) && is_load(&binary.right))
}

#[derive(Default)]
struct TraceWriteAudit {
    guarded: bool,
    writes: usize,
}

impl<'ast> Visit<'ast> for TraceWriteAudit {
    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        self.visit_expr(&expression.cond);
        let parent_guard = self.guarded;
        self.guarded |= reads_nonzero_trace(&expression.cond);
        self.visit_block(&expression.then_branch);
        self.guarded = parent_guard;
        if let Some((_, otherwise)) = &expression.else_branch {
            self.visit_expr(otherwise);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if ["swap", "store", "fetch_add", "fetch_sub", "compare_exchange"]
            .iter()
            .any(|method| is_trace_access(call, method))
        {
            self.writes += 1;
            assert!(self.guarded,
                "call_on4_raw writes font trace state on the unarmed path; read-only component images cannot service that fault");
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn unarmed_shared_broker_does_not_write_into_read_only_component_image() {
    let source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let file = syn::parse_file(source).expect("native broker syntax");
    let function = file.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "call_on4_raw" => Some(function),
        _ => None,
    }).expect("shared component broker entry");
    let mut audit = TraceWriteAudit::default();
    audit.visit_block(&function.block);
}
