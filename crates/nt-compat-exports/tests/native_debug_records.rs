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
