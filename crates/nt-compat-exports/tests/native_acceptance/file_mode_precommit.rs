use syn::visit::Visit;

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src").join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function(file: &syn::File, name: &str) -> (syn::Signature, syn::Block) {
    struct Find<'a> { name: &'a str, found: Option<(syn::Signature, syn::Block)> }
    impl<'ast> Visit<'ast> for Find<'_> {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            if item.sig.ident == self.name {
                self.found = Some((item.sig.clone(), (*item.block).clone()));
            }
            syn::visit::visit_item_fn(self, item);
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            if item.sig.ident == self.name {
                self.found = Some((item.sig.clone(), item.block.clone()));
            }
            syn::visit::visit_impl_item_fn(self, item);
        }
    }
    let mut find = Find { name, found: None };
    find.visit_file(file);
    find.found.unwrap_or_else(|| panic!("missing focused native contract {name}"))
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

#[test]
fn root_owned_file_mode_alias_does_not_reacquire_component_pool_lock() {
    let (_, body) = function(&source("win32k_file_owners.rs"), "mode_projection_address");
    let mut names = Names::default();
    names.visit_block(&body);
    assert!(names.calls.iter().any(|name| name == "address"));
    assert!(names.calls.iter().any(|name| name == "length"));
    assert!(!names.calls.iter().any(|name| matches!(name.as_str(),
        "provider_pool_packet_lease_live" | "try_provider_pool_lock" | "provider_pool_lock")),
        "an exact live root allocation already retained by its publication owner must not turn pool-lock contention into INVALID_HANDLE");
}

#[test]
fn arbitrary_projection_preflight_busy_is_not_a_terminal_resource_failure() {
    let (_, body) = function(&source("hosted_file_mode.rs"), "driver_projection_alias");
    let mut names = Names::default();
    names.visit_block(&body);
    assert!(!names.paths.iter().any(|name| name == "STATUS_INSUFFICIENT_RESOURCES"),
        "physical pool contention is no-effect Busy, not an allocation failure");
    assert!(names.paths.iter().any(|name| name == "Busy"),
        "arbitrary provider allocations require a typed precommit Busy disposition");
    let (_, body) = function(&source("exec_file_mode.rs"), "try_set_file_mode_information");
    let mut names = Names::default();
    names.visit_block(&body);
    assert!(names.paths.iter().any(|name| name == "Busy"),
        "the mode adapter must retain precommit ownership instead of recording Busy as OwnedInline terminal status");
}

#[test]
fn mode_capture_consumes_full_supplied_length_after_file_busy_acquisition() {
    let file = source("exec_file_mode.rs");
    let (signature, body) = function(&file, "try_set_file_mode_information");
    assert!(signature.inputs.iter().any(|argument| matches!(argument,
        syn::FnArg::Typed(argument) if matches!(&*argument.pat,
            syn::Pat::Ident(name) if name.ident == "length"))),
        "FileMode scalar decoding must not discard the caller's full Length");
    let mut names = Names::default();
    names.visit_block(&body);
    let position = |name: &str| names.calls.iter().position(|call| call == name)
        .unwrap_or_else(|| panic!("missing {name}"));
    assert!(position("prepare_owned_file_io") < position("capture_file_mode_input"));
    let (_, capture) = function(&file, "capture_file_mode_input");
    let mut names = Names::default();
    names.visit_block(&capture);
    assert!(names.paths.iter().any(|name| name == "length"));
    assert!(!names.calls.iter().any(|name| name == "xas_read"),
        "boolean copy would collapse a trailing GUARD refusal into ACCESS_VIOLATION");
    assert!(names.calls.iter().any(|name| name == "capture_set_information_payload"),
        "all supplied bytes, not only the four-byte scalar, need owned capture");
}

#[test]
fn mode_prebusy_probe_is_extent_only_not_a_guard_consuming_copy() {
    let file = source("exec_file_mode.rs");
    let (_, body) = function(&file, "probe_file_mode_input_extent");
    let mut names = Names::default();
    names.visit_block(&body);
    assert!(!names.calls.iter().any(|name| matches!(name.as_str(),
        "xas_read" | "probe_user_input" | "hosted_thread_memory_access")),
        "NT ProbeForRead validates range/alignment before Busy; the full copy after Busy owns page refusal");
    let dispatcher = source("exec_handler.rs");
    let mut names = Names::default();
    names.visit_file(&dispatcher);
    assert!(names.calls.iter().any(|name| name == "probe_file_mode_input_extent"));
}
