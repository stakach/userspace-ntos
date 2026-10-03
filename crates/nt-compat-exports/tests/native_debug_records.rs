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
fn executive_record_role_is_cleared_at_the_common_component_initializer() {
    let allocator = source("allocator");
    let mut calls = Calls::default();
    calls.visit_block(&function(&allocator, "initialize_heap_limit").block);
    assert_eq!(
        calls.0.first().map(String::as_str),
        Some("initialize_component")
    );
    for name in ["initialize_mapped_heap", "initialize_reserved_heap"] {
        let mut calls = Calls::default();
        calls.visit_block(&function(&allocator, name).block);
        assert!(calls.0.iter().any(|call| call == "initialize_heap_limit"));
    }
    let main = source("main");
    let mut startup = Calls::default();
    startup.visit_block(&function(&main, "_start").block);
    assert_eq!(
        startup.0.first().map(String::as_str),
        Some("initialize_root")
    );
}
