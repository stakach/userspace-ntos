use nt_compat_exports::{ExportRegistry, ExportStatus, ImportOutcome};
use syn::visit::Visit;

#[test]
fn breakpoint_imports_have_real_ntos_only_metadata() {
    let registry = ExportRegistry::new();
    for name in ["DbgBreakPoint", "DbgBreakPointWithStatus"] {
        assert_eq!(
            registry.resolve("ntoskrnl.exe", name),
            ImportOutcome::Available(ExportStatus::Implemented),
            "native breakpoint import must resolve to a real trap: {name}"
        );
        assert_eq!(registry.resolve("hal.dll", name), ImportOutcome::Missing);
    }
}

#[test]
fn both_hosted_registries_bind_shared_native_breakpoints() {
    for (path, function) in [
        ("driver_launch.rs", "register_fsd_trampolines"),
        ("win32k_subsystem.rs", "register_trampolines"),
    ] {
        let source = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../components/ntos-executive/src")
                .join(path),
        ).unwrap();
        let source = syn::parse_file(&source).unwrap();
        let function = source.items.iter().find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == function => Some(item),
            _ => None,
        }).unwrap();
        for name in ["DbgBreakPoint", "DbgBreakPointWithStatus"] {
            struct Binding<'a> { name: &'a str, found: bool }
            impl<'ast> Visit<'ast> for Binding<'_> {
                fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                    if call.method == "bind" && call.args.len() == 2 {
                        let named = matches!(&call.args[0], syn::Expr::Lit(lit)
                            if matches!(&lit.lit, syn::Lit::Str(value) if value.value() == self.name));
                        struct NativePath<'a> { name: &'a str, found: bool }
                        impl<'ast> Visit<'ast> for NativePath<'_> {
                            fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
                                let parts: Vec<_> = path.path.segments.iter()
                                    .map(|part| part.ident.to_string()).collect();
                                self.found |= parts == ["crate", "debug_traps", self.name];
                                syn::visit::visit_expr_path(self, path);
                            }
                        }
                        let mut native = NativePath { name: self.name, found: false };
                        native.visit_expr(&call.args[1]);
                        self.found |= named && native.found;
                    }
                    syn::visit::visit_expr_method_call(self, call);
                }
            }
            let mut binding = Binding { name, found: false };
            binding.visit_block(&function.block);
            assert!(binding.found, "{path} must bind {name} to the shared trap leaf");
        }
    }
}

#[test]
fn amd64_trap_leaves_preserve_status_and_alias_the_instruction() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/debug_traps.rs");
    let source = std::fs::read_to_string(path)
        .expect("shared native debugger trap module must exist");
    let source = syn::parse_file(&source).unwrap();
    let declarations = source.items.iter().find_map(|item| match item {
        syn::Item::ForeignMod(item) if item.abi.name.as_ref()
            .is_some_and(|name| name.value() == "win64") => Some(item),
        _ => None,
    }).expect("native trap declarations must use the Win64 ABI");
    for (name, arity) in [("DbgBreakPoint", 0), ("DbgBreakPointWithStatus", 1)] {
        let declaration = declarations.items.iter().find_map(|item| match item {
            syn::ForeignItem::Fn(item) if item.sig.ident == name => Some(item),
            _ => None,
        }).unwrap();
        assert_eq!(declaration.sig.inputs.len(), arity);
        assert!(matches!(declaration.sig.output, syn::ReturnType::Default));
        if arity == 1 {
            assert!(matches!(&declaration.sig.inputs[0], syn::FnArg::Typed(argument)
                if matches!(&*argument.ty, syn::Type::Path(ty) if ty.path.is_ident("u32"))),
                "breakpoint status is an NT ULONG, not a pointer-sized argument");
        }
    }
    let assembly = source.items.iter().find_map(|item| match item {
        syn::Item::Macro(item) if item.mac.path.segments.last()
            .is_some_and(|part| part.ident == "global_asm") => {
                Some(syn::parse2::<syn::LitStr>(item.mac.tokens.clone()).unwrap().value())
            }
        _ => None,
    }).expect("breakpoint exports must use real leaf assembly");
    let lines: Vec<_> = assembly.lines().map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('.')).collect();
    assert_eq!(lines, [
        "DbgBreakPoint:", "int3", "ret",
        "DbgBreakPointWithStatus:", "RtlpBreakWithStatusInstruction:", "int3", "ret",
    ], "status must remain in ECX at the aliased int3; neither export may be a no-op");
}
