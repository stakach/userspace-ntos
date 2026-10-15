use syn::{visit::Visit, Expr, Meta, Stmt};

fn attach_function() -> syn::ItemFn {
    let file = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_attach.rs"
    ))
    .expect("win32k attachment source parses");
    file.items
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "w32_client_attach" => Some(function),
            _ => None,
        })
        .expect("native attachment boundary")
}

fn path_ends(expression: &Expr, name: &str) -> bool {
    matches!(expression, Expr::Path(path)
        if path.path.segments.last().is_some_and(|segment| segment.ident == name))
}

#[derive(Default)]
struct Calls {
    names: Vec<String>,
    methods: Vec<String>,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*expression.func {
            if let Some(segment) = path.path.segments.last() {
                self.names.push(segment.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, expression);
    }

    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        self.methods.push(expression.method.to_string());
        syn::visit::visit_expr_method_call(self, expression);
    }
}

fn is_debug_trace(attribute: &syn::Attribute) -> bool {
    if !attribute.path().is_ident("cfg") {
        return false;
    }
    let Ok(Meta::NameValue(feature)) = attribute.parse_args::<Meta>() else {
        return false;
    };
    feature.path.is_ident("feature")
        && matches!(&feature.value, Expr::Lit(literal)
            if matches!(&literal.lit, syn::Lit::Str(value) if value.value() == "debug-trace"))
}

#[test]
fn complete_success_print_block_is_debug_only_without_gating_attachment_effects() {
    let attach = attach_function();
    assert!(
        attach.attrs.is_empty(),
        "attachment itself must remain unconditional"
    );
    let trace = attach
        .block
        .stmts
        .iter()
        .find_map(|statement| match statement {
            Stmt::Expr(Expr::Block(block), _) if block.attrs.iter().any(is_debug_trace) => {
                Some(block)
            }
            _ => None,
        })
        .expect("one debug-trace success output block");
    let mut guarded = Calls::default();
    guarded.visit_block(&trace.block);
    assert_eq!(
        guarded.names.len(),
        7,
        "gate all seven success print calls together"
    );
    assert!(
        guarded
            .names
            .iter()
            .all(|name| matches!(name.as_str(), "print_str" | "print_u64")),
        "the diagnostic block must not contain attachment effects"
    );
    assert_eq!(guarded.methods, ["map_or"]);
    let mut entire = Calls::default();
    entire.visit_block(&attach.block);
    assert_eq!(
        entire
            .names
            .iter()
            .filter(|name| matches!(name.as_str(), "print_str" | "print_u64"))
            .count(),
        7,
        "no success print fragment may escape the trace gate"
    );
    assert!(entire
        .names
        .iter()
        .any(|name| name == "detach_attached_client_process"));
    assert!(entire.methods.iter().any(|name| name == "recover"));
}

#[test]
fn switch_counter_is_unconditional_and_follows_exact_owner_publication() {
    let attach = attach_function();
    let publication = attach
        .block
        .stmts
        .iter()
        .position(|statement| {
            let Stmt::Expr(Expr::Assign(assign), _) = statement else {
                return false;
            };
            if !assign.attrs.is_empty() {
                return false;
            }
            let Expr::Unary(dereference) = &*assign.left else {
                return false;
            };
            let Expr::Macro(address) = &*dereference.expr else {
                return false;
            };
            let Expr::Call(value) = &*assign.right else {
                return false;
            };
            address
                .mac
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "addr_of_mut")
                && address.mac.tokens.to_string() == "ATTACHED_OWNER"
                && path_ends(&value.func, "Some")
                && value.args.len() == 1
                && path_ends(&value.args[0], "owner")
        })
        .expect("unconditional exact owner publication");
    let Stmt::Expr(Expr::MethodCall(counter), _) = &attach.block.stmts[publication + 1] else {
        panic!("switch counter must immediately follow owner publication")
    };
    assert!(counter.attrs.is_empty());
    assert!(path_ends(&counter.receiver, "ATTACH_SWITCHES"));
    assert_eq!(counter.method, "fetch_add");
    assert_eq!(counter.args.len(), 2);
    assert!(matches!(&counter.args[0], Expr::Lit(literal)
        if matches!(&literal.lit, syn::Lit::Int(value) if value.base10_parse::<u64>().unwrap() == 1)));
    assert!(path_ends(&counter.args[1], "Relaxed"));
}
