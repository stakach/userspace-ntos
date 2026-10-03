use syn::{visit::Visit, Expr, Item};

fn source(name: &str) -> syn::File {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src").join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn named(expression: &Expr, name: &str) -> bool {
    matches!(expression, Expr::Path(path) if path.path.is_ident(name))
}

#[test]
fn main_constructor_captures_only_the_teb_alias_it_actually_installed() {
    struct Constructor { found: usize, exact: usize }
    impl<'ast> Visit<'ast> for Constructor {
        fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
            if expression.path.is_ident("MainThreadRuntime") {
                self.found += 1;
                self.exact += usize::from(expression.fields.iter().any(|field| {
                    matches!(&field.member, syn::Member::Named(name) if name == "teb_alias")
                        && matches!(&field.expr, Expr::MethodCall(call)
                            if call.method == "then_some" && named(&call.receiver, "setup_env")
                                && call.args.len() == 1 && named(&call.args[0], "scr_base"))
                }));
            }
            syn::visit::visit_expr_struct(self, expression);
        }
    }
    let file = source("img_spawn.rs");
    let mut constructor = Constructor { found: 0, exact: 0 };
    constructor.visit_file(&file);
    assert_eq!(constructor.found, 1);
    assert_eq!(constructor.exact, 1,
        "constructor must retain its real scratch TEB alias, absent when setup_env installed no TEB");
}

#[test]
fn main_runtime_rejects_missing_or_replaced_alias_before_publishing_mechanism() {
    let file = source("hosted_thread_runtime.rs");
    let implementation = file.items.iter().find_map(|item| match item {
        Item::Impl(item) if matches!(&*item.self_ty, syn::Type::Path(path)
            if path.path.is_ident("HostedThreadRuntimeTable")) => Some(item),
        _ => None,
    }).unwrap();
    let method = implementation.items.iter().find_map(|item| match item {
        syn::ImplItem::Fn(method) if method.sig.ident == "register_main" => Some(method),
        _ => None,
    }).unwrap();
    assert!(method.sig.inputs.iter().any(|argument| matches!(argument,
        syn::FnArg::Typed(argument) if matches!(&*argument.pat, syn::Pat::Ident(name)
            if name.ident == "teb_alias"))), "registration must consume the constructor's exact alias");
    struct Publication { events: Vec<&'static str>, guarded: bool, rejecting: bool, zero: bool, replacement: bool }
    impl<'ast> Visit<'ast> for Publication {
        fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
            let zero = |value: &Expr| matches!(value, Expr::Lit(literal)
                if matches!(&literal.lit, syn::Lit::Int(value)
                    if matches!(value.base10_parse::<u64>(), Ok(0))));
            self.zero |= matches!(binary.op, syn::BinOp::Eq(_))
                && ((named(&binary.left, "teb_alias") && zero(&binary.right))
                    || (zero(&binary.left) && named(&binary.right, "teb_alias")));
            self.replacement |= matches!(binary.op, syn::BinOp::Ne(_))
                && ((named(&binary.left, "teb_alias") && !zero(&binary.right))
                    || (named(&binary.right, "teb_alias") && !zero(&binary.left)));
            syn::visit::visit_expr_binary(self, binary);
        }
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            self.visit_expr(&expression.cond);
            struct AliasCondition(bool);
            impl<'ast> Visit<'ast> for AliasCondition {
                fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
                    self.0 |= path.path.is_ident("teb_alias");
                }
            }
            let mut condition = AliasCondition(false);
            condition.visit_expr(&expression.cond);
            let previous = self.guarded;
            self.guarded |= condition.0;
            self.visit_block(&expression.then_branch);
            self.guarded = previous;
            if let Some((_, branch)) = &expression.else_branch { self.visit_expr(branch); }
        }
        fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
            if self.guarded && expression.expr.as_ref().is_some_and(|value| named(value, "None")) {
                self.events.push("reject-alias");
                self.rejecting = true;
            }
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "store" { self.events.push("store"); }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
            if matches!(&*assignment.left, Expr::Field(field)
                if matches!(&field.member, syn::Member::Named(name) if name == "teb_alias"))
                && named(&assignment.right, "teb_alias") { self.events.push("publish-alias"); }
            if matches!(&*assignment.left, Expr::Field(field)
                if matches!(&field.member, syn::Member::Named(name) if name == "mechanism"))
                && named(&assignment.right, "mechanism") { self.events.push("publish-mechanism"); }
            syn::visit::visit_expr_assign(self, assignment);
        }
    }
    let mut publication = Publication { events: Vec::new(), guarded: false, rejecting: false, zero: false, replacement: false };
    publication.visit_block(&method.block);
    let position = |name| publication.events.iter().position(|event| *event == name).unwrap();
    assert!(publication.rejecting);
    assert!(publication.zero && publication.replacement,
        "registration must reject zero aliases and replacement of an existing alias");
    assert!(position("reject-alias") < position("store"), "alias refusal precedes runtime publication");
    assert!(position("store") < position("publish-alias"));
    assert!(position("store") < position("publish-mechanism"));
}

#[test]
fn gdi_flush_resolves_the_captured_dispatch_owner_using_the_same_runtime_accessor() {
    struct Flush { locals: usize, logical: usize, aliases: usize, exact: usize }
    impl<'ast> Visit<'ast> for Flush {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "gdi_teb_alias") {
                self.locals += 1;
                if let Some(initializer) = &local.init { self.visit_expr(&initializer.expr); }
            }
        }
        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            self.logical += usize::from(named(&field.base, "dispatch_client")
                && matches!(&field.member, syn::Member::Named(name) if name == "logical_caller"));
            syn::visit::visit_expr_field(self, field);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "hosted_gui_thread_teb_alias_for" {
                self.aliases += 1;
                self.exact += usize::from(call.args.len() == 1 && named(&call.args[0], "logical"));
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    struct Locals(Flush);
    impl<'ast> Visit<'ast> for Locals {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            self.0.visit_local(local);
            syn::visit::visit_local(self, local);
        }
    }
    let file = source("service_sec_image.rs");
    let mut flush = Locals(Flush { locals: 0, logical: 0, aliases: 0, exact: 0 });
    flush.visit_file(&file);
    assert_eq!(flush.0.locals, 1);
    assert_eq!(flush.0.logical, 1, "GDI flush must retain the dispatch's captured thread generation");
    assert_eq!(flush.0.aliases, 1);
    assert_eq!(flush.0.exact, 1, "GDI and CLIENTINFO must share exact runtime alias authority");
}
