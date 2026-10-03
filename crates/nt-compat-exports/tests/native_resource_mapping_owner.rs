use std::path::PathBuf;
use syn::{visit::Visit, Expr, Item, ItemFn};

fn source(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .expect("native resource ownership boundary")
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[derive(Default)]
struct JoinedArm {
    found: bool,
    continued: bool,
}
impl<'ast> Visit<'ast> for JoinedArm {
    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        if matches!(&arm.pat, syn::Pat::TupleStruct(pattern)
            if pattern.path.segments.last().unwrap().ident == "Joined")
        {
            self.found = true;
            let mut calls = Calls::default();
            calls.visit_expr(&arm.body);
            assert!(
                !calls.0.iter().any(|call| matches!(
                    call.as_str(),
                    "copy_cap_r" | "page_map_r" | "cnode_delete_recycle_r" | "begin_map"
                )),
                "joining an equivalent owned leaf must not replace or delete it"
            );
            struct Continued(bool);
            impl<'ast> Visit<'ast> for Continued {
                fn visit_expr_continue(&mut self, _: &'ast syn::ExprContinue) {
                    self.0 = true;
                }
            }
            let mut continued = Continued(false);
            continued.visit_expr(&arm.body);
            self.continued = continued.0;
        }
        syn::visit::visit_arm(self, arm);
    }
}

#[test]
fn attested_backing_and_retained_effect_precede_resource_page_map() {
    let file = source("hosted_resource_mapping.rs");
    let mapping = function(&file, "map_run");
    let mut calls = Calls::default();
    calls.visit_block(&mapping.block);
    let position = |name: &str| calls.0.iter().position(|call| call == name).unwrap();
    assert!(position("hosted_pnp_mapping_frame") < position("prepare"));
    assert!(position("checked_frame_address") < position("prepare"));
    assert!(position("prepare") < position("copy_cap_r"));
    assert!(position("copy_cap_r") < position("attach_cap"));
    assert!(position("attach_cap") < position("begin_map"));
    assert!(position("begin_map") < position("page_map_r"));
    assert!(position("page_map_r") < position("acknowledge_map"));
    assert!(calls.0.iter().any(|call| call == "mark_map_uncertain"));
    let mut joined = JoinedArm::default();
    joined.visit_block(&mapping.block);
    assert!(
        joined.found && joined.continued,
        "equivalent join skips native mapping effects"
    );
}

#[derive(Default)]
struct FrameReplyGuard {
    exact_information: bool,
    aligned: bool,
}
impl<'ast> Visit<'ast> for FrameReplyGuard {
    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        if matches!(binary.op, syn::BinOp::Ne(_)) {
            self.exact_information |= matches!((&*binary.left, &*binary.right),
                (Expr::Path(path), Expr::Lit(literal)) if path.path.is_ident("information")
                && matches!(&literal.lit, syn::Lit::Int(value)
                    if matches!(value.base10_parse::<u64>(), Ok(1))));
            self.aligned |= matches!(&*binary.left, Expr::Binary(mask)
                if matches!(mask.op, syn::BinOp::BitAnd(_))
                    && matches!(&*mask.left, Expr::Path(path) if path.path.is_ident("physical")));
        }
        syn::visit::visit_expr_binary(self, binary);
    }
}

#[test]
fn frame_address_query_does_not_accept_unverified_reply_registers() {
    let file = source("hosted_resource_mapping.rs");
    let mut guard = FrameReplyGuard::default();
    guard.visit_block(&function(&file, "checked_frame_address").block);
    assert!(
        guard.exact_information && guard.aligned,
        "zero/error/malformed replies cannot attest a physical page or authorize equivalent joins"
    );
}

#[test]
fn final_owner_deletion_ack_precedes_ledger_retirement() {
    let file = source("hosted_resource_mapping.rs");
    let mut calls = Calls::default();
    calls.visit_block(&function(&file, "release").block);
    let position = |name: &str| calls.0.iter().position(|call| call == name).unwrap();
    assert!(position("begin_release") < position("cnode_delete_recycle_r"));
    assert!(position("cnode_delete_recycle_r") < position("acknowledge_delete"));
    assert!(calls.0.iter().any(|call| call == "mark_delete_uncertain"));
}

#[test]
fn memory_and_dma_paths_share_one_resource_mapping_owner() {
    let file = source("driver_launch.rs");
    for obsolete in [
        "hosted_resource_map_caps_mut",
        "record_hosted_resource_map_cap",
    ] {
        assert!(
            !file
                .items
                .iter()
                .any(|item| matches!(item, Item::Fn(function)
            if function.sig.ident == obsolete)),
            "remove obsolete independent cap ownership"
        );
    }
    let mut run = Calls::default();
    run.visit_block(&function(&file, "map_hosted_resource_frame_run").block);
    assert_eq!(run.0, ["map_run"]);
    let mut grant = Calls::default();
    grant.visit_block(&function(&file, "grant_hosted_device_resources").block);
    assert!(grant
        .0
        .iter()
        .any(|call| call == "map_hosted_resource_frame_run"));
    assert!(
        !grant.0.iter().any(|call| call == "page_map_r"),
        "initial resources cannot bypass the shared mapping owner"
    );
}
