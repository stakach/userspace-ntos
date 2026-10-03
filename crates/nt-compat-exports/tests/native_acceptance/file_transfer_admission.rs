//! NT5 read.c/write.c reference the File before probing any user argument.

use syn::visit::Visit;

#[derive(Default)]
struct Paths(Vec<String>);
impl<'ast> Visit<'ast> for Paths {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        if let Some(segment) = path.segments.last() {
            self.0.push(segment.ident.to_string());
        }
        syn::visit::visit_path(self, path);
    }
    fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
        self.0.push(expression.method.to_string());
        syn::visit::visit_expr_method_call(self, expression);
    }
}

fn service_branch(name: &str) -> syn::Block {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_handler.rs"
    )).unwrap();
    struct Find<'a> { name: &'a str, block: Option<syn::Block> }
    impl<'ast> Visit<'ast> for Find<'_> {
        fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
            for arm in &expression.arms {
                if matches!(&arm.pat, syn::Pat::Path(path)
                    if path.path.segments.last().is_some_and(|part| part.ident == self.name))
                {
                    let syn::Expr::Unsafe(body) = &*arm.body else {
                        panic!("native transfer service must have its explicit unsafe boundary");
                    };
                    assert!(self.block.is_none());
                    self.block = Some(body.block.clone());
                }
            }
            syn::visit::visit_expr_match(self, expression);
        }
    }
    let mut find = Find { name, block: None };
    find.visit_file(&file);
    find.block.expect("native transfer service")
}

fn assert_admission_before_user_effects(service: &str, capture: &str, local_guards: &[&str]) {
    let block = service_branch(service);
    let statements: Vec<_> = block.stmts.iter().map(|statement| {
        let mut paths = Paths::default();
        paths.visit_stmt(statement);
        paths.0
    }).collect();
    let first_effect = statements.iter().position(|paths| paths.iter().any(|path| matches!(
        path.as_str(), "probe_file_io_output" | "probe_copy_output" | "xas_read"
            | "try_zeroed_transfer_buffer"
    ))).expect("transfer probes or copies user memory");
    let capture_position = statements.iter().position(|paths|
        paths.iter().any(|path| path == "capture_hosted_file_transfer")
    ).expect("exact hosted capture and promoted retry authority");
    assert!(capture_position < first_effect,
        "{service} must capture File authority before IOSB/buffer/offset/key access or allocation");
    assert!(statements[..first_effect].iter().any(|paths|
        paths.iter().any(|path| path == "capture_local_file_io_reference")),
        "local File bodies must also be retained before reentrant probes");
    assert!(!statements[first_effect..].iter().any(|paths|
        paths.iter().any(|path| path == "local_file_io_route_for")),
        "local dispatch must use its admitted route, not relookup a replaced handle");
    #[derive(Default)]
    struct Returns(bool);
    impl<'ast> Visit<'ast> for Returns {
        fn visit_expr_return(&mut self, _: &'ast syn::ExprReturn) { self.0 = true; }
    }
    for guard in std::iter::once(capture).chain(local_guards.iter().copied()) {
        let early_return = block.stmts[..first_effect].iter().any(|statement| {
            let syn::Stmt::Expr(syn::Expr::If(expression), _) = statement else { return false; };
            let mut condition = Paths::default();
            condition.visit_expr(&expression.cond);
            let mut returns = Returns::default();
            returns.visit_block(&expression.then_branch);
            returns.0 && condition.0.iter().any(|path| path == guard)
        });
        assert!(early_return,
            "{service} must return {guard} admission failure before probing and without IOSB publication");
    }
}

#[test]
fn read_file_admission_precedes_iosb_buffer_offset_and_key_probes() {
    assert_admission_before_user_effects(
        "NtReadFile", "hosted_read_capture", &["disk_file", "overlay_read_access"],
    );
}

#[test]
fn write_file_admission_precedes_iosb_buffer_offset_and_key_probes() {
    assert_admission_before_user_effects(
        "NtWriteFile", "hosted_write_capture", &["overlay_write_access"],
    );
}

#[test]
fn local_probe_reference_has_balanced_body_ownership_without_handler_borrow() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_local_file_io.rs"
    )).unwrap();
    let capture = file.items.iter().filter_map(|item| match item {
        syn::Item::Impl(implementation) => Some(implementation),
        _ => None,
    }).flat_map(|implementation| &implementation.items).find_map(|item| match item {
        syn::ImplItem::Fn(method) if method.sig.ident == "capture_local_file_io_reference" => Some(method),
        _ => None,
    }).expect("local admission reference acquisition");
    let mut paths = Paths::default();
    paths.visit_block(&capture.block);
    assert!(paths.0.iter().any(|path| path == "retain_local_file_io_reference"));
    assert!(!paths.0.iter().any(|path| path == "begin_local_file_io"),
        "probing retains a body but must not clear its event or begin transfer");
    let guard = file.items.iter().find_map(|item| match item {
        syn::Item::Struct(structure) if structure.ident == "LocalFileIoReference" => Some(structure),
        _ => None,
    }).unwrap();
    assert!(guard.fields.iter().any(|field| matches!(&field.ty, syn::Type::Ptr(pointer)
        if pointer.mutability.is_some()
        && matches!(&*pointer.elem, syn::Type::Path(path) if path.path.is_ident("ExecNtHandler")))),
        "no handler borrow may cross reentrant user-memory probing");
    let drop = file.items.iter().find_map(|item| match item {
        syn::Item::Impl(implementation)
            if implementation.trait_.as_ref().is_some_and(|(_, path, _)| path.is_ident("Drop"))
                && matches!(&*implementation.self_ty, syn::Type::Path(path)
                    if path.path.is_ident("LocalFileIoReference")) => Some(implementation),
        _ => None,
    }).expect("admission body reference is released on every return");
    let mut paths = Paths::default();
    paths.visit_item_impl(drop);
    assert_eq!(paths.0.iter().filter(|path| *path == "release_local_file_io_reference").count(), 1);
}
