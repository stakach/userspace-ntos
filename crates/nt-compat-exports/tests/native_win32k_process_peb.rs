//! GUI context selection consumes published Ps objects, not a user-controlled TEB's PEB field.
//! ReactOS PsGetProcessPeb and USER process callouts read the canonical EPROCESS.Peb.
use syn::{visit::Visit, Expr};

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn body(file: &syn::File, name: &str) -> syn::Block {
    struct Find<'a> { name: &'a str, bodies: Vec<syn::Block> }
    impl<'ast> Visit<'ast> for Find<'_> {
        fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
            if function.sig.ident == self.name { self.bodies.push((*function.block).clone()); }
            syn::visit::visit_item_fn(self, function);
        }
        fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
            if function.sig.ident == self.name { self.bodies.push(function.block.clone()); }
            syn::visit::visit_impl_item_fn(self, function);
        }
    }
    let mut found = Find { name, bodies: Vec::new() };
    found.visit_file(file);
    assert_eq!(found.bodies.len(), 1, "one actual {name} implementation");
    found.bodies.pop().unwrap()
}

#[derive(Default)]
struct Effects { calls: Vec<String>, identifiers: Vec<String> }
impl<'ast> Visit<'ast> for Effects {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.calls.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.identifiers.push(ident.to_string());
    }
}

fn effects(block: &syn::Block) -> Effects {
    let mut effects = Effects::default();
    effects.visit_block(block);
    effects
}

fn position(effects: &Effects, call: &str) -> usize {
    effects.calls.iter().position(|name| name == call)
        .unwrap_or_else(|| panic!("actual boundary must call {call}"))
}

#[test]
fn selection_and_resume_have_no_teb_peb_capture_or_compatibility_initializer() {
    let file = source("win32k_subsystem.rs");
    let mut all = Effects::default();
    all.visit_file(&file);
    for obsolete in [
        "client_peb_from_teb", "record_process_client_peb", "initialize_eprocess_body",
        "process_ctx_client_peb", "set_process_ctx_client_peb", "client_peb",
        "synthetic_peb", "synthetic_params",
    ] {
        assert!(!all.identifiers.iter().any(|name| name == obsolete),
            "remove obsolete {obsolete}; canonical Ps publication owns EPROCESS.Peb");
    }
    let select = effects(&body(&file, "select_win32k_client_context"));
    assert!(select.calls.iter().any(|name| name == "ensure_thread_context"));
    assert!(select.identifiers.iter().any(|name| name == "client_teb"),
        "removing the PEB read must preserve the real calling thread TEB");
    let resume = effects(&body(&file, "restore_current_context_for_user_callback_resume_inner"));
    assert!(resume.calls.iter().any(|name| name == "seed_win32k_callout_teb"));
    assert!(resume.calls.iter().any(|name| name == "set_thread_ctx_teb"));
}

#[test]
fn gui_context_records_cannot_construct_private_ps_object_substitutes() {
    let file = source("win32k_subsystem.rs");
    let mut all = Effects::default();
    all.visit_file(&file);
    for obsolete in ["process_context_object_or_allocate", "thread_context_object_or_allocate"] {
        assert!(!all.identifiers.iter().any(|name| name == obsolete),
            "{obsolete} manufactures an object when the registered Ps body is absent");
    }
    for boundary in ["ensure_process_context", "ensure_thread_context"] {
        let actual = effects(&body(&file, boundary));
        assert!(!actual.calls.iter().any(|name| name == "allocate_kernel_object_body"),
            "{boundary} must retain the supplied canonical body, not allocate a substitute");
    }
}

#[test]
fn missing_supplied_ps_bodies_are_refused_before_gui_context_publication() {
    let select = body(&source("win32k_subsystem.rs"), "select_win32k_client_context");
    let mut refused = Vec::new();
    for statement in &select.stmts {
        let mut observed = Effects::default();
        observed.visit_stmt(statement);
        if observed.calls.iter().any(|name| name == "ensure_process_context") {
            break;
        }
        let syn::Stmt::Expr(Expr::If(branch), _) = statement else { continue };
        let terminal = branch.then_branch.stmts.last();
        if !matches!(terminal, Some(syn::Stmt::Expr(Expr::Return(ret), _))
            if matches!(ret.expr.as_deref(), Some(Expr::Path(path)) if path.path.is_ident("None"))) {
            continue;
        }
        struct ZeroChecks(Vec<String>);
        impl<'ast> Visit<'ast> for ZeroChecks {
            fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
                if matches!(binary.op, syn::BinOp::Eq(_)) {
                    if let (Expr::Path(path), Expr::Lit(literal)) = (&*binary.left, &*binary.right) {
                        if matches!(&literal.lit, syn::Lit::Int(value)
                            if matches!(value.base10_parse::<u64>(), Ok(0))) {
                            self.0.push(path.path.segments.last().unwrap().ident.to_string());
                        }
                    }
                }
                if matches!(binary.op, syn::BinOp::Or(_)) {
                    self.visit_expr(&binary.left);
                    self.visit_expr(&binary.right);
                }
            }
        }
        let mut checks = ZeroChecks(Vec::new());
        checks.visit_expr(&branch.cond);
        refused.extend(checks.0);
    }
    for supplied in ["supplied_eprocess", "supplied_ethread"] {
        assert!(refused.iter().any(|name| name == supplied),
            "{supplied} must be present before publishing ordinary GUI context records");
    }
}

#[test]
fn root_maps_exact_published_ps_objects_before_gui_request_publication() {
    let file = source("win32k_glue.rs");
    let grant = effects(&body(&file, "grant_win32k_client_ps_bodies"));
    for required in ["thread_lifetime", "process_kernel_object", "thread_kernel_object"] {
        assert!(position(&grant, required) < position(&grant, "grant_published_body"));
    }
    for identity in ["caller", "lifetime", "eprocess", "ethread", "Process", "Thread"] {
        assert!(grant.identifiers.iter().any(|name| name == identity));
    }
    let dispatch = effects(&body(&file, "win32k_dispatch_wide_observed_inner"));
    assert!(position(&dispatch, "win32k_client_context_is_admitted")
        < position(&dispatch, "grant_win32k_client_ps_bodies"));
    assert!(position(&dispatch, "grant_win32k_client_ps_bodies")
        < position(&dispatch, "clear_published_win32k_context"));
    assert!(position(&dispatch, "grant_win32k_client_ps_bodies")
        < position(&dispatch, "write_volatile"));
    let backing = effects(&body(&source("ps_object_backing.rs"), "grant_published_body"));
    for required in ["thread_lifetime", "process_kernel_object", "thread_kernel_object"] {
        assert!(position(&backing, required) < position(&backing, "map_published_row"));
    }
}

#[test]
fn canonical_process_peb_is_captured_before_main_ps_pair_publication() {
    let prepare = body(&source("ps_object_backing.rs"), "prepare_process");
    let captured = effects(&prepare);
    assert!(position(&captured, "query_process_basic") < position(&captured, "prepare"));
    assert!(captured.identifiers.iter().any(|name| name == "peb_base_address"));
    struct Initialization(bool);
    impl<'ast> Visit<'ast> for Initialization {
        fn visit_expr_struct(&mut self, structure: &'ast syn::ExprStruct) {
            if structure.path.segments.last().is_some_and(|part| part.ident == "ProcessInitialization") {
                self.0 = structure.fields.iter().any(|field| {
                    matches!(&field.member, syn::Member::Named(name) if name == "peb")
                        && matches!(&field.expr, Expr::Call(call)
                            if matches!(&*call.func, Expr::Path(path) if path.path.is_ident("GuestAddr"))
                            && call.args.len() == 1
                            && matches!(&call.args[0], Expr::Path(path) if path.path.is_ident("peb")))
                });
            }
            syn::visit::visit_expr_struct(self, structure);
        }
    }
    let mut initialization = Initialization(false);
    initialization.visit_block(&prepare);
    assert!(initialization.0, "ABI initialization must contain the captured PM PEB, not a substitute");
    let main = effects(&body(&source("exec_handler.rs"), "register_main_thread_spawn"));
    assert!(position(&main, "prepare_process") < position(&main, "publish_prepared_pair"));
    assert!(position(&main, "prepare_thread") < position(&main, "publish_prepared_pair"));
}

#[test]
fn initial_system_and_nonexecuting_lifecycle_keep_their_existing_exact_context_paths() {
    let file = source("win32k_subsystem.rs");
    let system = effects(&body(&file, "select_initial_system_context"));
    assert!(system.calls.iter().any(|name| name == "initial_system_projection"));
    for canonical in ["process_body", "thread_body"] {
        assert!(system.identifiers.iter().any(|name| name == canonical));
    }
    assert!(!system.calls.iter().any(|name| name == "ensure_process_context"));
    let lifecycle = effects(&body(&file, "select_existing_ps_provider_context"));
    for required in ["process_ctx_generation", "process_ctx_eprocess",
        "validate_ps_provider_execution_thread", "read_ps_provider_execution_teb"] {
        assert!(lifecycle.calls.iter().any(|name| name == required));
    }
    assert!(!lifecycle.calls.iter().any(|name| name == "ensure_process_context"
        || name == "allocate_kernel_object_body"));
}
