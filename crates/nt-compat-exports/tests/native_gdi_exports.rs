use nt_compat_exports::{ExportRegistry, ExportStatus, ImportOutcome};
use syn::visit::Visit;

#[test]
fn dxg_core_imports_have_canonical_module_metadata() {
    let registry = ExportRegistry::new();
    for name in ["memcpy", "memmove", "memset", "PsGetCurrentThreadProcessId"] {
        assert!(matches!(registry.resolve("ntoskrnl.exe", name),
            ImportOutcome::Available(ExportStatus::Implemented | ExportStatus::Partial)),
            "dxg.sys core import ntoskrnl.exe!{name} must have real canonical metadata");
        assert_eq!(registry.resolve("hal.dll", name), ImportOutcome::Missing);
        assert_eq!(registry.resolve("unknownmodule.dll", name), ImportOutcome::Missing);
    }
}

#[test]
fn generic_gdi_resolver_does_not_use_primary_image_import_lists() {
    let source = include_str!("../../../components/ntos-executive/src/win32k_image_loader.rs");
    let source = syn::parse_file(source).unwrap();
    let function = source.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "resolve_import" => Some(function),
        _ => None,
    }).unwrap();
    #[derive(Default)]
    struct Boundary { primary_lists: Vec<String>, qualified_lookup: bool }
    impl<'ast> Visit<'ast> for Boundary {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            for segment in &path.path.segments {
                let name = segment.ident.to_string();
                if matches!(name.as_str(), "WIN32K_NTOSKRNL_IMPORTS" | "WIN32K_HAL_IMPORTS") {
                    self.primary_lists.push(name);
                }
            }
            syn::visit::visit_expr_path(self, path);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|segment| segment.ident == "export_addr_for_module"))
                && call.args.len() == 2
            {
                self.qualified_lookup = true;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut boundary = Boundary::default();
    boundary.visit_block(&function.block);
    assert!(boundary.primary_lists.is_empty(),
        "generic system-image resolution cannot use one primary image's import contract: {:?}", boundary.primary_lists);
    assert!(boundary.qualified_lookup, "generic core resolution must use module-qualified export authority");
}

#[test]
fn current_thread_process_id_uses_the_thread_owner_client_id() {
    let source = include_str!("../../../components/ntos-executive/src/win32k_subsystem.rs");
    let source = syn::parse_file(source).unwrap();
    let function = source.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "s_current_thread_process_id" => Some(function),
        _ => None,
    }).expect("thread owner PID needs its own native adapter, not the routed process PID alias");
    #[derive(Default)]
    struct OwnerRead { owner_offset: bool, routed_pid: bool }
    impl<'ast> Visit<'ast> for OwnerRead {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            for segment in &path.path.segments {
                self.owner_offset |= segment.ident == "ETHREAD_CLIENT_ID_PROCESS";
                self.routed_pid |= segment.ident == "WIN32K_CURRENT_PROCESS_ID";
            }
            syn::visit::visit_expr_path(self, path);
        }
    }
    let mut read = OwnerRead::default();
    read.visit_block(&function.block);
    assert!(read.owner_offset, "PsGetCurrentThreadProcessId must read ETHREAD.Cid.UniqueProcess");
    assert!(!read.routed_pid, "routed process PID is not thread owner authority while attached");
}
