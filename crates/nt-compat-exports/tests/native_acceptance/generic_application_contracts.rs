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
    assert!(!names.paths.iter().any(|name| name == "ACTIVE_CLIENT_PI"));
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
fn gui_message_capture_and_wait_use_registered_runtime_and_real_provider_wait() {
    #[derive(Default)]
    struct Audit { staging: Option<Names>, staged_release_guard: Option<Names> }
    impl<'ast> Visit<'ast> for Audit {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if matches!(&local.pat, syn::Pat::Ident(pat) if pat.ident == "msg_syscall") {
                let mut names = Names::default();
                names.visit_expr(&local.init.as_ref().unwrap().expr);
                self.staging = Some(names);
            }
            syn::visit::visit_local(self, local);
        }
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            let mut condition = Names::default();
            condition.visit_expr(&expression.cond);
            if condition.paths.iter().any(|name| name == "callback_suspended")
                && condition.paths.iter().any(|name| name == "component_suspension_park_request")
            {
                let mut body = Names::default();
                body.visit_block(&expression.then_branch);
                if body.calls.iter().any(|name| name == "release_win32k_message_stage") {
                    self.staged_release_guard = Some(condition);
                }
            }
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let file = source("service_sec_image.rs");
    let mut audit = Audit::default();
    audit.visit_file(&file);
    let names = audit.staging.expect("MSG staging");
    assert!(names.paths.iter().any(|name| name == "registered_gui_client"));
    assert!(!names.paths.iter().any(|name| matches!(name.as_str(),
        "shell_gui_client" | "interactive_gui_client" | "winlogon_gui_client")));
    let body = function(&file, "registered_gui_dispatch_client");
    let mut names = Names::default();
    names.visit_block(&body);
    for required in ["executable_by_badge", "capture_process_identity", "validate_thread_lifetime", "is_busy"] {
        assert!(names.calls.iter().any(|name| name == required), "missing exact runtime check {required}");
    }
    let mut names = Names::default();
    names.visit_file(&file);
    assert!(names.calls.iter().any(|name| name == "take_pending_provider_wait_dispatch"));
    assert!(names.calls.iter().any(|name| name == "provider_wait_admit_current"));
    assert!(!names.paths.iter().any(|name| matches!(name.as_str(),
        "gui_message_wait_park_request" | "GET_MESSAGE_EMPTY_QUEUE_GUARD")),
        "GetMessage must not turn speculative Peek completion into its own result");
    audit.staged_release_guard.expect("suspended callback/provider wait retains staged MSG");
    let body = function(&source("win32k_subsystem.rs"), "s_ke_wait_for_single_object");
    let mut names = Names::default();
    names.visit_block(&body);
    assert!(names.calls.iter().any(|name| name == "provider_wait_rendezvous"));
    let body = function(&source("win32k_glue.rs"), "resume_suspended_provider_wait_component");
    let mut names = Names::default();
    names.visit_block(&body);
    for required in ["published_win32k_output_length", "release_win32k_message_stage"] {
        assert!(names.calls.iter().any(|name| name == required),
            "actual wait completion must publish and retire its exact MSG stage: {required}");
    }
    struct OriginalSsn(bool);
    impl<'ast> Visit<'ast> for OriginalSsn {
        fn visit_expr_field(&mut self, expression: &'ast syn::ExprField) {
            if matches!(&expression.member, syn::Member::Named(name) if name == "ssn") {
                if let syn::Expr::Field(dispatch) = &*expression.base {
                    self.0 |= matches!(&dispatch.member, syn::Member::Named(name) if name == "dispatch")
                        && matches!(&*dispatch.base, syn::Expr::Path(path) if path.path.is_ident("pending"));
                }
            }
            syn::visit::visit_expr_field(self, expression);
        }
    }
    let mut original = OriginalSsn(false);
    original.visit_block(&body);
    assert!(original.0, "the retained original syscall, not Peek, determines resumed completion");
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
fn gdi_pointer_capture_eligibility_is_not_a_named_or_pe_subsystem_role() {
    struct Init(Option<syn::Expr>);
    impl<'ast> Visit<'ast> for Init {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if matches!(&local.pat, syn::Pat::Ident(pat) if pat.ident == "uses_client_gdi") {
                self.0 = Some((*local.init.as_ref().unwrap().expr).clone());
            }
            syn::visit::visit_local(self, local);
        }
    }
    let mut init = Init(None);
    init.visit_file(&source("service_sec_image.rs"));
    let mut names = Names::default();
    names.visit_expr(&init.0.expect("actual incoming GDI pointer-capture eligibility"));
    assert!(!names.calls.iter().any(|name| matches!(name.as_str(),
        "uses_win32_client_gdi" | "hosted_process_role" | "hosted_process_observation_role")));
    assert!(!names.paths.iter().any(|name| name == "process_role"),
        "the first registered GDI service must capture actual user pointers even before conversion completes");
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
