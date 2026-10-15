//! Stack reservation geometry is not proof that an executive mirror is mapped.
use syn::visit::Visit;

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*expression.func {
            if let Some(name) = path.path.segments.last() {
                self.0.push(name.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, expression);
    }
}

fn assert_recorded_route(name: &str) {
    let source = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/img_spawn.rs"
    )).unwrap();
    let function = source.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    }).expect("native client copy boundary");
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    assert!(!calls.0.iter().any(|name| matches!(name.as_str(),
        "smss_mirror" | "wl_listener_stack_contains")),
        "{name} cannot use computed mirror geometry or named-thread routing as mapped authority");
    assert!(calls.0.iter().any(|name| matches!(name.as_str(),
        "recorded_frame_copyin" | "recorded_frame_copyout" | "with_recorded_frame_alias"
        | "client_copyin_process_mapped_impl" | "client_copyout_mapped_impl"
        | "admit_client_copy_backing" | "admit_client_copyout_backing")),
        "{name} must retain an exact recorded-frame admission boundary");
}

#[test]
fn loader_copyout_never_prefers_unmapped_primary_mirror_to_grown_worker_frame() {
    assert_recorded_route("smss_copyout");
    assert_recorded_route("client_write_process_mapped_for");
}

#[test]
fn loader_copyin_uses_recorded_stack_backing_without_role_or_geometry_fallback() {
    assert_recorded_route("smss_copyin");
    assert_recorded_route("client_copyin_process_mapped_impl");
}

#[test]
fn critical_section_diagnostics_use_recorded_backing_not_computed_stack_mirror() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/service_sec_image.rs"
    )).unwrap();
    struct Diagnostic(bool);
    impl<'ast> Visit<'ast> for Diagnostic {
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            let tagged = expression.then_branch.stmts.iter().any(|statement|
                matches!(statement, syn::Stmt::Expr(syn::Expr::Call(call), _)
                    if matches!(call.args.first(), Some(syn::Expr::Lit(literal))
                        if matches!(&literal.lit, syn::Lit::ByteStr(bytes)
                            if bytes.value() == b"[cs-diag] label=3 exc#="))));
            if tagged {
                struct Paths(Vec<String>);
                impl<'ast> Visit<'ast> for Paths {
                    fn visit_path(&mut self, path: &'ast syn::Path) {
                        if let Some(name) = path.segments.last() { self.0.push(name.ident.to_string()); }
                        syn::visit::visit_path(self, path);
                    }
                }
                let mut paths = Paths(Vec::new());
                paths.visit_block(&expression.then_branch);
                assert!(!paths.0.iter().any(|name| matches!(name.as_str(),
                    "ACTIVE_STACK_BASE" | "ACTIVE_STACK_SIZE" | "ACTIVE_STACK_MIRROR" | "read_volatile")),
                    "diagnostics must not fault the executive through inferred stack mirrors");
                assert!(paths.0.iter().any(|name| name == "read_fault_stack_word"),
                    "diagnostic reads use the shared retained backing boundary");
                self.0 = true;
            }
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let mut diagnostic = Diagnostic(false);
    diagnostic.visit_file(&file);
    assert!(diagnostic.0, "critical-section diagnostic boundary exists");
}
