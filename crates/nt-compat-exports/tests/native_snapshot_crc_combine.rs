use std::path::PathBuf;

use syn::{visit::Visit, FnArg, ImplItem, Item, ReturnType, Type};

fn source(relative: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[derive(Default)]
struct Calls {
    payload_traversals: usize,
    combinations: usize,
    streaming_commits: usize,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "write_snapshot_payload_to_sink" {
            self.payload_traversals += 1;
        }
        if call.method == "commit_next_streaming" {
            self.streaming_commits += 1;
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "crc32c_combine" && call.args.len() == 3)
            {
                self.combinations += 1;
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn memfs_snapshot_combines_captured_crc_without_a_third_payload_traversal() {
    let file = source("../nt-fs/src/fs.rs");
    let methods: Vec<_> = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(implementation) => Some(&implementation.items),
            _ => None,
        })
        .flatten()
        .filter_map(|item| match item {
            ImplItem::Fn(method) if method.sig.ident == "commit_snapshot_to_store" => Some(method),
            _ => None,
        })
        .collect();
    assert_eq!(methods.len(), 1, "inspect the actual MemFs commit method");
    let mut calls = Calls::default();
    calls.visit_block(&methods[0].block);
    assert_eq!(
        calls.payload_traversals, 2,
        "retain the sizing/CRC pass and final write, not an intermediate full serialization"
    );
    assert_eq!(calls.combinations, 1, "combine the captured finalized CRCs");
    assert_eq!(
        calls.streaming_commits, 1,
        "keep the existing final stream validation and publication protocol"
    );
    let body = &methods[0].block;
    let combination = local_initializer(body, "store_payload_crc");
    let syn::Expr::Call(combination) = combination else {
        panic!("the checksum passed to the store must come from the combination");
    };
    assert!(path_named(&combination.func, "crc32c_combine"));
    assert_eq!(combination.args.len(), 3);
    let syn::Expr::Call(header_crc) = &combination.args[0] else {
        panic!("combine the encoded header's checksum");
    };
    assert!(path_named(&header_crc.func, "crc32c"));
    assert_eq!(header_crc.args.len(), 1);
    assert!(
        matches!(&header_crc.args[0], syn::Expr::Reference(reference)
        if path_named(&reference.expr, "header"))
    );
    assert!(path_named(&combination.args[1], "payload_crc"));
    assert!(path_named(&combination.args[2], "payload_len_u64"));
    let commit = strip_try(local_initializer(body, "generation"));
    let syn::Expr::MethodCall(commit) = commit else {
        panic!("generation must be the actual streaming commit result");
    };
    assert_eq!(commit.method, "commit_next_streaming");
    assert!(path_named(&commit.args[2], "store_payload_crc"));
}

fn local_initializer<'a>(body: &'a syn::Block, name: &str) -> &'a syn::Expr {
    body.stmts.iter().find_map(|statement| match statement {
        syn::Stmt::Local(local) if matches!(&local.pat, syn::Pat::Ident(id) if id.ident == name) => {
            local.init.as_ref().map(|init| &*init.expr)
        }
        _ => None,
    }).unwrap_or_else(|| panic!("missing actual local {name}"))
}

fn path_named(expression: &syn::Expr, name: &str) -> bool {
    matches!(expression, syn::Expr::Path(path)
        if path.path.segments.last().is_some_and(|segment| segment.ident == name))
}

fn strip_try(expression: &syn::Expr) -> &syn::Expr {
    match expression {
        syn::Expr::Try(expression) => &expression.expr,
        expression => expression,
    }
}

fn contains_mismatch(expression: &syn::Expr, left: &str, right: &str) -> bool {
    match expression {
        syn::Expr::Binary(binary) if matches!(binary.op, syn::BinOp::Ne(_)) => {
            path_named(&binary.left, left) && path_named(&binary.right, right)
        }
        syn::Expr::Binary(binary) if matches!(binary.op, syn::BinOp::Or(_)) => {
            contains_mismatch(&binary.left, left, right)
                || contains_mismatch(&binary.right, left, right)
        }
        _ => false,
    }
}

#[test]
fn final_stream_validation_still_precedes_commit_header_publication() {
    let file = source("../nt-fs/src/snapshot_store.rs");
    let method = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(implementation) => Some(&implementation.items),
            _ => None,
        })
        .flatten()
        .find_map(|item| match item {
            ImplItem::Fn(method) if method.sig.ident == "commit_next_streaming" => Some(method),
            _ => None,
        })
        .expect("actual store streaming commit method");
    let validation = method
        .block
        .stmts
        .iter()
        .position(|statement| {
            matches!(statement, syn::Stmt::Expr(syn::Expr::If(branch), _)
            if contains_mismatch(&branch.cond, "written", "payload_len")
                && contains_mismatch(&branch.cond, "actual_crc", "payload_crc")
                && branch.then_branch.stmts.iter().any(|statement|
                    matches!(statement, syn::Stmt::Expr(syn::Expr::Return(ret), _)
                        if matches!(&ret.expr, Some(expr)
                            if matches!(&**expr, syn::Expr::Call(call)
                                if path_named(&call.func, "Err")
                                    && call.args.iter().any(|arg| path_named(arg, "Corrupt")))))))
        })
        .expect("actual length and CRC mismatches must refuse publication");
    let finish = method
        .block
        .stmts
        .iter()
        .position(|statement| {
            matches!(statement, syn::Stmt::Local(local)
            if local.init.as_ref().is_some_and(|init|
                matches!(strip_try(&init.expr), syn::Expr::MethodCall(call)
                    if call.method == "finish" && path_named(&call.receiver, "writer"))))
        })
        .expect("actual writer finish");
    let publication = method
        .block
        .stmts
        .iter()
        .position(|statement| {
            matches!(statement, syn::Stmt::Expr(expr, _)
            if matches!(strip_try(expr), syn::Expr::MethodCall(call)
                if call.method == "write_sector" && path_named(&call.args[0], "slot_base")))
        })
        .expect("actual commit-header write");
    assert!(finish < validation && validation < publication);
}

fn scalar_type(ty: &Type, expected: &str) -> bool {
    matches!(ty, Type::Path(path) if path.qself.is_none() && path.path.is_ident(expected))
}

#[test]
fn shared_codec_exposes_finalized_crc_combination_with_u64_byte_length() {
    let file = source("../nt-config-store/src/codec.rs");
    let function = file.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "crc32c_combine" => Some(function),
        _ => None,
    });
    assert!(
        function.is_some(),
        "shared codec needs a real crc32c_combine implementation, not a MemFs-local CRC variant"
    );
    let function = function.unwrap();
    assert!(matches!(function.vis, syn::Visibility::Public(_)));
    let types: Vec<_> = function
        .sig
        .inputs
        .iter()
        .filter_map(|argument| match argument {
            FnArg::Typed(argument) => Some(&*argument.ty),
            FnArg::Receiver(_) => None,
        })
        .collect();
    assert_eq!(types.len(), 3);
    assert!(scalar_type(types[0], "u32"));
    assert!(scalar_type(types[1], "u32"));
    assert!(scalar_type(types[2], "u64"));
    assert!(matches!(
        &function.sig.output,
        ReturnType::Type(_, ty) if scalar_type(ty, "u32")
    ));
}
