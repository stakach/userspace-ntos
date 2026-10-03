//! Native caller authority must survive the system-image service boundary.

use syn::{visit::Visit, Expr, Item, ItemFn};

fn function(source: &str, name: &str) -> ItemFn {
    syn::parse_file(source)
        .expect("native source must parse")
        .items
        .into_iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing native function {name}"))
}

#[derive(Default)]
struct Calls(Vec<(String, Vec<Expr>)>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() {
                self.0.push((segment.ident.to_string(), call.args.iter().cloned().collect()));
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn calls(function: &ItemFn) -> Calls {
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    calls
}

fn is_name(expression: &Expr, name: &str) -> bool {
    matches!(expression, Expr::Path(path) if path.path.is_ident(name))
}

fn passes_source(function: &ItemFn, callee: &str) {
    assert!(calls(function).0.iter().any(|(name, arguments)| {
        name == callee && arguments.iter().any(|argument| is_name(argument, "source"))
    }), "{} must pass authenticated PhysicalSource to {callee}", function.sig.ident);
}

#[test]
fn native_gdi_loader_uses_authenticated_physical_source() {
    let ingress_source = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let driver_source = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    let glue_source = include_str!("../../../components/ntos-executive/src/win32k_glue.rs");
    let loader_source = include_str!("../../../components/ntos-executive/src/win32k_image_loader.rs");
    let ingress = function(ingress_source, "service_win32k_gdi_image_request");
    assert!(calls(&ingress).0.iter().any(|(name, arguments)| {
        name == "physical_source" && arguments.len() == 1 && is_name(&arguments[0], "route")
    }), "GDI ingress must derive caller VSpace from its authenticated route");
    passes_source(&ingress, "service_win32k_gdi_image_request");
    passes_source(&function(driver_source, "service_win32k_gdi_image_request"), "service_gdi_image_request");
    passes_source(&function(glue_source, "service_gdi_image_request"), "service_request");

    let loader = function(loader_source, "service_request");
    struct CallerPml4(bool);
    impl<'ast> Visit<'ast> for CallerPml4 {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "pml4")
                && local.init.as_ref().is_some_and(|init| {
                    matches!(&*init.expr, Expr::Field(field)
                        if is_name(&field.base, "source")
                            && matches!(&field.member, syn::Member::Named(name) if name == "pml4"))
                })
            {
                self.0 = true;
            }
            syn::visit::visit_local(self, local);
        }
    }
    let mut caller_pml4 = CallerPml4(false);
    caller_pml4.visit_block(&loader.block);
    assert!(calls(&loader).0.iter().any(|(name, arguments)| {
        name == "load_installed" && arguments.iter().any(|argument| {
            (caller_pml4.0 && is_name(argument, "pml4")) || matches!(argument, Expr::Field(field)
                if is_name(&field.base, "source")
                    && matches!(&field.member, syn::Member::Named(name) if name == "pml4"))
        })
    }), "GDI load must map into the retained physical caller VSpace");
    for source in [glue_source, loader_source] {
        assert!(!source.contains("WIN32K_GDI_LOADER_PML4"), "ambient loader VSpace is not caller authority");
        assert!(!source.contains("fn register_win32k_gdi_loader"), "ambient loader registration must be removed");
    }
}
