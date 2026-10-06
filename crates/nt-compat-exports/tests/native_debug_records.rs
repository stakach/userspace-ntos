use syn::{visit::Visit, Expr, Item};

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*expression.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, expression);
    }
}

#[test]
fn hosted_debug_formats_before_one_record_write_without_ipc_or_byte_syscalls() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src");
    let focused = root.join("hosted_debug_print.rs");
    let path = if focused.exists() {
        focused
    } else {
        root.join("driver_launch.rs")
    };
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    let formatter = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "format_debug_driver" => Some(function),
            _ => None,
        })
        .expect("driver debug formatter");
    let mut calls = Calls::default();
    calls.visit_block(&formatter.block);
    let format = calls
        .0
        .iter()
        .position(|call| call == "format_narrow")
        .unwrap();
    let records: Vec<_> = calls
        .0
        .iter()
        .enumerate()
        .filter_map(|(index, call)| (call == "print_record").then_some(index))
        .collect();
    assert_eq!(records.len(), 1, "DbgPrint must submit one captured record");
    assert!(
        format < records[0],
        "formatting cannot interleave serial effects"
    );
    let mut all_calls = Calls::default();
    all_calls.visit_file(&file);
    if file
        .items
        .iter()
        .any(|item| matches!(item, Item::Struct(item) if item.ident == "DebugPrintfOutput"))
    {
        panic!("the old per-character debug sink must be removed");
    }
    assert!(!calls
        .0
        .iter()
        .any(|call| matches!(call.as_str(), "call_on4" | "debug_put_char")));
}

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../components/ntos-executive/src/{name}.rs"));
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap()
}

#[test]
fn both_kernel_registries_use_the_same_variadic_debug_export_binding() {
    let driver = source("driver_launch");
    let win32k = source("win32k_subsystem");
    for (file, name) in [(&driver, "register_fsd_trampolines"), (&win32k, "register_trampolines")] {
        let mut calls = Calls::default();
        calls.visit_block(&function(file, name).block);
        assert_eq!(calls.0.iter().filter(|call| *call == "bind_debug_exports").count(), 1,
            "{name} must use the shared Win64 debug export boundary");
    }
    let helper = function(&driver, "bind_debug_exports");
    #[derive(Default)]
    struct Bindings(Vec<(String, Vec<String>)>);
    impl<'ast> Visit<'ast> for Bindings {
        fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
            if expression.method == "bind" && expression.args.len() == 2 {
                if let Expr::Lit(literal) = &expression.args[0] {
                    if let syn::Lit::Str(name) = &literal.lit {
                        #[derive(Default)]
                        struct Paths(Vec<String>);
                        impl<'ast> Visit<'ast> for Paths {
                            fn visit_expr_path(&mut self, expression: &'ast syn::ExprPath) {
                                self.0.push(expression.path.segments.last().unwrap().ident.to_string());
                            }
                        }
                        let mut paths = Paths::default();
                        paths.visit_expr(&expression.args[1]);
                        self.0.push((name.value(), paths.0));
                    }
                }
            }
            syn::visit::visit_expr_method_call(self, expression);
        }
    }
    let mut bindings = Bindings::default();
    bindings.visit_block(&helper.block);
    for (name, gate) in [
        ("DbgPrint", "hosted_dbg_print_gate"),
        ("DbgPrintEx", "hosted_dbg_print_ex_gate"),
        ("vDbgPrintEx", "s_vdbg_print_ex"),
        ("vDbgPrintExWithPrefix", "s_vdbg_print_ex_with_prefix"),
    ] {
        let values: Vec<_> = bindings.0.iter().filter(|(export, _)| export == name).collect();
        assert_eq!(values.len(), 1, "one authoritative binding required for {name}");
        assert!(values[0].1.iter().any(|path| path == gate), "{name} lost its actual argument ABI");
    }
}

#[test]
fn win32k_removes_raw_format_and_fragmented_debug_printers() {
    let win32k = source("win32k_subsystem");
    assert!(!win32k.items.iter().any(|item| matches!(item,
        Item::Fn(function) if function.sig.ident == "s_dbg_print"
            || function.sig.ident == "s_vdbg_print_ex_with_prefix")),
        "Win32k must not retain separate raw-format or byte-output debug implementations");
}

#[test]
fn fsd_pipe_and_control_diagnostics_delegate_captured_records() {
    let driver = source("driver_launch");
    struct ProducerCalls {
        pipe: usize,
        control: usize,
        old_markers: usize,
    }
    impl<'ast> Visit<'ast> for ProducerCalls {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*call.func {
                let names: Vec<_> = path.path.segments.iter().map(|s| s.ident.to_string()).collect();
                if names == ["fsd_diagnostics", "pipe_rw"] { self.pipe += 1; }
                if names == ["fsd_diagnostics", "control_failure"] { self.control += 1; }
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_lit_byte_str(&mut self, literal: &'ast syn::LitByteStr) {
            let bytes = literal.value();
            if bytes.starts_with(b"[fsd-pipe-rw]") || bytes.starts_with(b"[fsd-control-failure]") {
                self.old_markers += 1;
            }
        }
    }
    let mut calls = ProducerCalls { pipe: 0, control: 0, old_markers: 0 };
    calls.visit_block(&function(&driver, "trace_pipe_rw_result").block);
    calls.visit_block(&function(&driver, "run_irp").block);
    assert_eq!(calls.pipe, 1, "captured pipe snapshots need one atomic diagnostic producer");
    assert_eq!(calls.control, 1, "captured control failure needs one atomic diagnostic producer");
    assert_eq!(calls.old_markers, 0, "component sites must not emit fragmented record prefixes");
}

#[test]
fn fsd_diagnostic_formatters_are_bounded_atomic_and_mark_overflow() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/fsd_diagnostics.rs");
    assert!(path.exists(), "focused FSD diagnostic capture boundary is absent");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    for name in ["pipe_rw", "control_failure"] {
        let mut calls = Calls::default();
        calls.visit_block(&function(&file, name).block);
        assert_eq!(calls.0.iter().filter(|call| *call == "emit").count(), 1);
    }
    let mut all = Calls::default();
    all.visit_file(&file);
    assert!(!all.0.iter().any(|call| matches!(call.as_str(),
        "print_str" | "debug_put_char" | "print_u64" | "print_hex" | "print_hex64"
        | "print_pipe_ccb_view" | "print_dcerpc_pdu_view" | "read_volatile" | "read_unaligned")),
        "format captured values only, without fragments or new provider memory reads");
    let mut emission = Calls::default();
    emission.visit_block(&function(&file, "emit").block);
    assert_eq!(emission.0.iter().filter(|call| *call == "print_record").count(), 1);
    #[derive(Default)]
    struct Overflow { checked: bool, marker: bool, bounded: bool }
    impl<'ast> Visit<'ast> for Overflow {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.checked |= call.method == "overflowed";
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_lit_byte_str(&mut self, literal: &'ast syn::LitByteStr) {
            self.marker |= literal.value() == b"[record-truncated]\n";
        }
        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
            for segment in &path.path.segments {
                if segment.ident == "RecordBuffer" {
                    if let syn::PathArguments::AngleBracketed(args) = &segment.arguments {
                        self.bounded |= args.args.iter().any(|arg| matches!(arg,
                            syn::GenericArgument::Const(Expr::Lit(literal))
                            if matches!(&literal.lit, syn::Lit::Int(n) if n.base10_parse::<usize>().is_ok_and(|n| n > 0 && n <= 4096))));
                    }
                }
            }
            syn::visit::visit_type_path(self, path);
        }
    }
    let mut overflow = Overflow::default();
    overflow.visit_file(&file);
    assert!(overflow.checked && overflow.marker && overflow.bounded,
        "bounded captured records must explicitly mark overflow rather than emit valid-looking truncation");
}

#[test]
fn executive_hex_identity_is_one_fixed_width_scalar_not_two_prefixed_halves() {
    let main = source("main");
    let formatter = function(&main, "print_hex_u64");
    let mut calls = Calls::default();
    calls.visit_block(&formatter.block);
    assert!(!calls.0.iter().any(|call| call == "print_hex"),
        "two u32 printers emit two 0x prefixes instead of one exact u64 identity");
    assert_eq!(calls.0.iter().filter(|call| *call == "print_str").count(), 1);
}

#[test]
fn executive_record_anchor_is_installed_after_mapping_before_component_activation() {
    let allocator = source("allocator");
    let mut calls = Calls::default();
    calls.visit_block(&function(&allocator, "initialize_heap_limit").block);
    assert!(!calls.0.iter().any(|call| call == "initialize_component"));
    let main = source("main");
    let mut startup = Calls::default();
    startup.visit_block(&function(&main, "_start").block);
    let mapped = startup.0.iter().position(|call| call == "map_cluster_pt").unwrap();
    let installed = startup.0.iter().position(|call| call == "initialize_root").unwrap();
    let first_spawn = startup.0.iter().position(|call| call.starts_with("spawn_")).unwrap();
    assert!(mapped < installed && installed < first_spawn);
    let serial = source("serial_records");
    let mut installation = Calls::default();
    installation.visit_block(&function(&serial, "initialize_root").block);
    let page_map = installation.0.iter().position(|call| call == "page_map_r").unwrap();
    let anchor_write = installation.0.iter().position(|call| call == "write_volatile").unwrap();
    assert!(page_map < anchor_write, "Root owns the anchor page before publication");
}

#[test]
fn component_debug_initialization_never_mutates_shared_read_only_image_state() {
    let serial = source("serial_records");
    let image_statics: Vec<_> = serial.items.iter().filter_map(|item| match item {
        Item::Static(item) => Some(item.ident.to_string()),
        _ => None,
    }).collect();
    struct Stores<'a> { image_statics: &'a [String], writes: Vec<String> }
    impl<'ast> Visit<'ast> for Stores<'_> {
        fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
            if expression.method == "store" {
                if let Expr::Path(path) = &*expression.receiver {
                    let name = path.path.segments.last().unwrap().ident.to_string();
                    if self.image_statics.contains(&name) { self.writes.push(name); }
                }
            }
            syn::visit::visit_expr_method_call(self, expression);
        }
    }
    let mut stores = Stores { image_statics: &image_statics, writes: Vec::new() };
    if let Some(initializer) = serial.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "initialize_component" => Some(function),
        _ => None,
    }) {
        stores.visit_block(&initializer.block);
    }
    assert!(stores.writes.is_empty(),
        "component image frames are shared read-only; role initialization wrote {:?}", stores.writes);
}

#[test]
fn diagnostic_anchor_uses_private_ipc_tail_outside_the_kernel_abi() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src");
    let serial = std::fs::read_to_string(root.join("serial_records.rs")).unwrap();
    assert!(serial.contains("4096 - core::mem::size_of::<usize>()"));
    assert!(serial.contains("ANCHOR_OFFSET >= sel4_rt::IPC_BUFFER_SIZE_BYTES"));
    assert!(serial.contains("ANCHOR_OFFSET % core::mem::align_of::<usize>() == 0"));
    assert!(serial.contains("actual_ipc_va != crate::IPCBUF_VADDR"));
    let read = serial.find("let anchor = core::ptr::read_volatile").unwrap();
    let zero = serial[read..].find("if anchor == 0").unwrap() + read;
    let dereference = serial.find("anchor as *mut LineBuffer<4096>").unwrap();
    assert!(read < zero && zero < dereference);
    assert!(!serial.contains("allocator::"), "zero-heap domains must not read heap metadata");
    let spawn = std::fs::read_to_string(root.join("spawn_hosts.rs")).unwrap();
    assert!(spawn.contains("component_retype(b\"ipcbuf-retype\", OBJ_X86_4K_PAGE, PAGING_BITS, ipcbuf)"));
    assert!(spawn.contains("page_map_r(ipcbuf, IPCBUF_VADDR, RW_NX, pml4)"));
}
