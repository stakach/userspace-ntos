use syn::visit::Visit;

fn function(name: &str) -> syn::ItemFn {
    syn::parse_file(include_str!("../../nt-ntdll-dll/src/on_target.rs"))
        .unwrap()
        .items
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .expect("actual native loader function")
}

#[derive(Default)]
struct Calls(Vec<(String, Vec<syn::Expr>)>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0.push((
                path.path.segments.last().unwrap().ident.to_string(),
                call.args.iter().cloned().collect(),
            ));
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn recursive_snap_and_forwarders_retain_one_caller_owned_expansion_context() {
    for name in [
        "snap_module",
        "load_and_snap_dependency",
        "snap_descriptor_against",
        "resolve_export_addr",
        "publish_import_reference_edges",
    ] {
        let function = function(name);
        assert!(function.sig.inputs.iter().any(|argument| matches!(argument,
            syn::FnArg::Typed(argument) if matches!(&*argument.pat,
                syn::Pat::Ident(identifier) if identifier.ident == "expansion"))));
        let mut calls = Calls::default();
        calls.visit_block(&function.block);
        for (callee, arguments) in calls.0 {
            if [
                "snap_module",
                "load_and_snap_dependency",
                "snap_descriptor_against",
                "resolve_export_addr",
                "publish_import_reference_edges",
            ]
            .contains(&callee.as_str())
            {
                assert!(
                    matches!(arguments.last(), Some(syn::Expr::Path(path))
                    if path.path.is_ident("expansion")),
                    "{name} must forward the actual shared context to {callee}"
                );
            }
        }
        struct ExpansionConstruction(bool);
        impl<'ast> Visit<'ast> for ExpansionConstruction {
            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if let syn::Expr::Path(path) = &*call.func {
                    if path
                        .path
                        .segments
                        .iter()
                        .any(|segment| segment.ident == "ReferenceExpansion")
                    {
                        self.0 = true;
                    }
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        let mut construction = ExpansionConstruction(false);
        construction.visit_block(&function.block);
        assert!(
            !construction.0,
            "recursive helpers must not reset expansion state"
        );
    }
}

#[test]
fn native_acquisition_publication_consumes_weights_before_any_count_store() {
    let source = include_str!("../../nt-ntdll-dll/src/on_target.rs");
    assert!(!source.contains("collect_reference_modules_dfs"));
    for name in ["publish_import_reference_edges", "ldr_add_ref_dll"] {
        let mut calls = Calls::default();
        calls.visit_block(&function(name).block);
        let weighted = calls
            .0
            .iter()
            .position(|call| call.0 == "ldr_plan_module_references")
            .unwrap();
        let publish = calls
            .0
            .iter()
            .position(|call| call.0 == "write_unaligned")
            .unwrap();
        assert!(weighted < publish);
        assert!(calls
            .0
            .iter()
            .filter(|call| call.0 == "ldr_plan_module_references")
            .all(|call| matches!(call.1.last(), Some(syn::Expr::Field(field))
                if matches!(&field.member, syn::Member::Named(name) if name == "releases"))));
    }
}
