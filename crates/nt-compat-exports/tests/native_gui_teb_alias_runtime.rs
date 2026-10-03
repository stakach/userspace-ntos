use syn::{visit::Visit, Expr, Item};

fn source(name: &str) -> syn::File {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    }).expect("actual native GUI service")
}

fn method<'a>(file: &'a syn::File, name: &str) -> &'a syn::ImplItemFn {
    file.items.iter().find_map(|item| {
        let Item::Impl(implementation) = item else { return None; };
        implementation.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
            _ => None,
        })
    }).expect("generation-bound registered-runtime GUI TEB resolver")
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn gui_teb_alias_comes_from_exact_executable_runtime_not_a_role_allowlist() {
    let file = source("exec_handler.rs");
    let resolver = method(&file, "hosted_gui_thread_teb_alias_for");
    let mut calls = Calls::default();
    calls.visit_block(&resolver.block);
    let validation = calls.0.iter().position(|name| name == "validate_provider_logical_caller")
        .expect("validate retained pi/process/thread lifetime/badge/runtime binding");
    let runtime = calls.0.iter().position(|name| name == "executable_by_badge")
        .expect("read the actual executable registered runtime for every thread role");
    assert!(validation < runtime, "retained authority is validated before selecting an alias");
    struct Projection { alias: bool, role: bool, nonzero: bool }
    impl<'ast> Visit<'ast> for Projection {
        fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
            let alias = |expression: &Expr| matches!(expression, Expr::Field(field)
                if matches!(&field.member, syn::Member::Named(name) if name == "teb_alias"));
            let zero = |expression: &Expr| matches!(expression, Expr::Lit(literal)
                if matches!(&literal.lit, syn::Lit::Int(value)
                    if matches!(value.base10_parse::<u64>(), Ok(0))));
            self.nonzero |= matches!(binary.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_))
                && ((alias(&binary.left) && zero(&binary.right))
                    || (zero(&binary.left) && alias(&binary.right)));
            syn::visit::visit_expr_binary(self, binary);
        }
        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            self.alias |= matches!(&field.member, syn::Member::Named(name) if name == "teb_alias");
            self.role |= matches!(&field.member, syn::Member::Named(name) if name == "role");
            syn::visit::visit_expr_field(self, field);
        }
        fn visit_path(&mut self, path: &'ast syn::Path) {
            self.role |= path.segments.iter().any(|part| part.ident == "HostedThreadRole");
        }
    }
    let mut projection = Projection { alias: false, role: false, nonzero: false };
    projection.visit_block(&resolver.block);
    assert!(projection.alias, "return the registered runtime's retained TEB alias");
    assert!(projection.nonzero, "an executable runtime without a published TEB alias fails closed");
    assert!(!projection.role, "CsrApi, TpWorker, Main and other executable roles use the same authority");
}

#[test]
fn gui_copyout_revalidates_the_same_captured_logical_owner_before_both_alias_reads() {
    struct Aliases { calls: usize, exact: usize, legacy: usize }
    impl<'ast> Visit<'ast> for Aliases {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "hosted_gui_thread_teb_alias_for" {
                self.calls += 1;
                self.exact += usize::from(call.args.len() == 1
                    && matches!(&call.args[0], Expr::Path(path) if path.path.is_ident("logical")));
            }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            self.legacy += usize::from(matches!(&*call.func, Expr::Path(path)
                if path.path.is_ident("hosted_gui_thread_teb_alias_for")));
            syn::visit::visit_expr_call(self, call);
        }
    }
    let file = source("hosted_gui_client_info.rs");
    let mut aliases = Aliases { calls: 0, exact: 0, legacy: 0 };
    aliases.visit_block(&function(&file, "service").block);
    assert_eq!(aliases.calls, 2, "initial admission and post-map revalidation both resolve actual runtime");
    assert_eq!(aliases.exact, 2, "both reads carry the captured process/thread generation owner");
    assert_eq!(aliases.legacy, 0, "no numeric role-based resolver may bypass lifetime validation");
}

#[test]
fn obsolete_role_based_teb_alias_projection_is_removed() {
    let file = source("service_sec_image.rs");
    assert!(!file.items.iter().any(|item| matches!(item,
        Item::Fn(function) if function.sig.ident == "hosted_gui_thread_teb_alias_for")),
        "remove the obsolete role-based projection rather than leaving a second source of TEB identity");
}
