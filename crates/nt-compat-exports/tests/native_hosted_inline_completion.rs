use syn::{visit::Visit, Expr, ImplItem, Item};

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn calls(file: &syn::File, name: &str) -> Vec<String> {
    let mut calls = Calls::default();
    for item in &file.items {
        match item {
            Item::Fn(function) if function.sig.ident == name => calls.visit_block(&function.block),
            Item::Impl(implementation) => {
                for item in &implementation.items {
                    if let ImplItem::Fn(function) = item {
                        if function.sig.ident == name { calls.visit_block(&function.block); }
                    }
                }
            }
            _ => {}
        }
    }
    calls.0
}

#[test]
fn inline_ack_accepts_exact_caller_completion_without_driver_free_intent() {
    for name in ["hosted_read_work.rs", "hosted_flush_work.rs", "hosted_query_information_work.rs"] {
        let functions = calls(&source(name), "acknowledge");
        assert!(functions.iter().any(|name| name == "completion_finished"),
            "inline ACK must use exact owner-specific terminal proof in {name}");
        assert!(!functions.iter().any(|name| name == "callback_requested_free"),
            "Caller completion cannot be gated by Driver IoFree intent in {name}");
    }
}

#[derive(Default)]
struct FreeGuard {
    owner_guards: usize,
    guarded_free: usize,
    receipt_scope: bool,
    unguarded_free: usize,
    bypass_guards: usize,
}
impl<'ast> Visit<'ast> for FreeGuard {
    fn visit_block(&mut self, block: &'ast syn::Block) {
        let prior = self.receipt_scope;
        for statement in &block.stmts {
            if let syn::Stmt::Local(local) = statement {
                if let Some(init) = &local.init {
                    let mut calls = Calls::default();
                    calls.visit_expr(&init.expr);
                    if calls.0.iter().any(|name| name == "complete_hosted_irp_with_owner") {
                        self.receipt_scope = true;
                    }
                }
            }
            self.visit_stmt(statement);
        }
        self.receipt_scope = prior;
    }
    fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
        struct DriverOwner(bool);
        impl<'ast> Visit<'ast> for DriverOwner {
            fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
                if path.path.segments.last().is_some_and(|s| s.ident == "DriverLocal") {
                    self.0 = true;
                }
                syn::visit::visit_expr_path(self, path);
            }
        }
        let mut owner = DriverOwner(false);
        owner.visit_expr(&branch.cond);
        struct Bypass(bool);
        impl<'ast> Visit<'ast> for Bypass {
            fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
                if matches!(binary.op, syn::BinOp::Or(_)) { self.0 = true; }
                syn::visit::visit_expr_binary(self, binary);
            }
        }
        let mut bypass = Bypass(false);
        bypass.visit_expr(&branch.cond);
        if self.receipt_scope && owner.0 && bypass.0 { self.bypass_guards += 1; }
        if owner.0 { self.owner_guards += 1; }
        self.visit_expr(&branch.cond);
        self.visit_block(&branch.then_branch);
        if owner.0 { self.owner_guards -= 1; }
        if let Some((_, other)) = &branch.else_branch { self.visit_expr(other); }
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if self.receipt_scope && matches!(&*call.func, Expr::Path(path)
            if path.path.segments.last().is_some_and(|s| s.ident == "s_io_free_irp")) {
            if self.owner_guards != 0 { self.guarded_free += 1; }
            else { self.unguarded_free += 1; }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn inline_driver_free_uses_claim_derived_completion_owner() {
    let file = source("driver_launch.rs");
    let functions = calls(&file, "s_iof_call_driver");
    assert!(functions.iter().any(|name| name == "complete_hosted_irp_with_owner"),
        "inline completion must consume a typed successful-claim owner receipt");
    let mut guard = FreeGuard::default();
    for item in &file.items {
        if let Item::Fn(function) = item {
            if function.sig.ident == "s_iof_call_driver" { guard.visit_block(&function.block); }
        }
    }
    assert!(guard.guarded_free > 0,
        "inline explicit free must exclude CanonicalCaller using DriverLocal receipt");
    assert_eq!(guard.unguarded_free, 0,
        "every explicit free after the typed receipt requires DriverLocal ownership");
    assert_eq!(guard.bypass_guards, 0,
        "major-function or other OR branches must not bypass receipt ownership");
    let typed = calls(&file, "complete_hosted_irp_with_owner");
    assert_eq!(typed.iter().filter(|name| *name == "claim_pending_irp_completion").count(), 1,
        "storage owner must derive from one exact generation-bearing completion claim");
    assert!(calls(&file, "complete_hosted_irp").iter().any(|name| name == "complete_hosted_irp_with_owner"),
        "legacy outcome wrapper must share the same authoritative walk");
}
