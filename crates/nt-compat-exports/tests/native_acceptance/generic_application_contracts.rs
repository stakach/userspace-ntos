use syn::visit::Visit;

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src").join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[derive(Default)]
struct Names { calls: Vec<String>, paths: Vec<String> }
impl<'ast> Visit<'ast> for Names {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.calls.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.paths.extend(path.segments.iter().map(|segment| segment.ident.to_string()));
        syn::visit::visit_path(self, path);
    }
}

fn function(file: &syn::File, name: &str) -> syn::Block {
    struct Find<'a> { name: &'a str, found: Option<syn::Block> }
    impl<'ast> Visit<'ast> for Find<'_> {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            if item.sig.ident == self.name { self.found = Some((*item.block).clone()); }
            syn::visit::visit_item_fn(self, item);
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            if item.sig.ident == self.name { self.found = Some(item.block.clone()); }
            syn::visit::visit_impl_item_fn(self, item);
        }
    }
    let mut find = Find { name, found: None };
    find.visit_file(file);
    find.found.unwrap_or_else(|| panic!("missing exact native contract {name}"))
}

#[test]
fn query_value_name_capture_is_checked_and_not_selected_by_application_role() {
    struct Query(Option<syn::Expr>);
    impl<'ast> Visit<'ast> for Query {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            let mut names = Names::default();
            names.visit_pat(&arm.pat);
            if names.paths.iter().any(|name| name == "NtQueryValueKey") {
                self.0 = Some((*arm.body).clone());
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let file = source("exec_handler.rs");
    let mut query = Query(None);
    query.visit_file(&file);
    let mut names = Names::default();
    names.visit_expr(&query.0.expect("actual NtQueryValueKey service arm"));
    assert!(names.calls.iter().any(|name| name == "capture_registry_value_name"),
        "Application and NativeApplication must use the same checked capture as other callers");
    assert!(!names.calls.iter().any(|name| matches!(name.as_str(),
        "current_process_uses_pe_backed_registry_strings" | "smss_read_ustr" | "read_ustr_pe")),
        "role-selected resident/PE readers can silently turn failed capture into a partial/default name");
}

#[test]
fn registry_value_name_capture_retains_exact_process_and_propagates_read_status() {
    let body = function(&source("exec_registry_value_name.rs"), "capture_registry_value_name");
    let mut names = Names::default();
    names.visit_block(&body);
    assert!(names.calls.iter().any(|name| name == "capture_process_identity"));
    assert!(names.calls.iter().any(|name| name == "process_memory_read_status"),
        "full descriptor/payload reads preserve native GUARD/ACCESS statuses");
    assert!(!names.calls.iter().any(|name| matches!(name.as_str(),
        "smss_copyin" | "smss_read_ustr" | "read_ustr_pe" | "current_hosted_process_role")));
    struct Fallible(bool);
    impl<'ast> Visit<'ast> for Fallible {
        fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
            let mut names = Names::default();
            names.visit_expr(&expression.expr);
            self.0 |= names.calls.iter().any(|name| name == "process_memory_read_status");
            syn::visit::visit_expr_try(self, expression);
        }
    }
    let mut fallible = Fallible(false);
    fallible.visit_block(&body);
    assert!(fallible.0, "unreadable names must fail, not truncate or query the default value");
}

#[test]
fn generic_native_gui_conversion_is_not_denied_by_callback_role_or_thread_role() {
    let file = source("win32k_glue.rs");
    for name in ["client_callback_supported_for_api", "main_gui_callback_teb_alias"] {
        let body = function(&file, name);
        let mut names = Names::default();
        names.visit_block(&body);
        assert!(!names.calls.iter().any(|name| name == "uses_win32_client_gdi"),
            "{name} must retain actual conversion/runtime authority, not PE-native or historical process-role eligibility");
        assert!(!names.paths.iter().any(|name| matches!(name.as_str(),
            "InteractiveLogon" | "InteractiveShell" | "InteractiveShellBootstrap")),
            "no named image role may authorize generic GUI callbacks");
    }
    let body = function(&file, "main_gui_callback_teb_alias");
    let mut names = Names::default();
    names.visit_block(&body);
    assert!(!names.paths.iter().any(|name| matches!(name.as_str(), "Main" | "TpWorker")),
        "the exact published runtime owns the TEB alias for every admitted thread kind");
}

#[test]
fn callback_role_encoding_can_roundtrip_generic_application_metadata() {
    let file = source("win32k_glue.rs");
    let body = function(&file, "callback_process_role_code");
    let mut names = Names::default();
    names.visit_block(&body);
    for role in ["Application", "NativeApplication"] {
        assert!(names.paths.iter().any(|name| name == role),
            "generic metadata must survive a parked continuation without an unhandled enum or named-role substitution");
    }
    let body = function(&file, "callback_process_role_from_code");
    let mut names = Names::default();
    names.visit_block(&body);
    for role in ["Application", "NativeApplication"] {
        assert!(names.paths.iter().any(|name| name == role), "missing generic role decoder {role}");
    }
}
