use syn::{visit::Visit, ImplItem, Item};

fn transport() -> syn::File {
    let path = concat!(env!("CARGO_MANIFEST_DIR"),
        "/../../components/ntos-executive/src/hosted_source_terminal_packet.rs");
    syn::parse_file(&std::fs::read_to_string(path).expect("retained native transport owner")).unwrap()
}

fn method(file: &syn::File, name: &str) -> syn::ImplItemFn {
    file.items.iter().find_map(|item| match item {
        Item::Impl(item) => item.items.iter().find_map(|item| match item {
            ImplItem::Fn(function) if function.sig.ident == name => Some(function.clone()),
            _ => None,
        }),
        _ => None,
    }).unwrap_or_else(|| panic!("missing transport method {name}"))
}

#[derive(Default)]
struct Effects { calls: Vec<String>, paths: Vec<String> }
impl<'ast> Visit<'ast> for Effects {
    fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
        if let Some(segment) = path.path.segments.last() {
            self.paths.push(segment.ident.to_string());
        }
        syn::visit::visit_type_path(self, path);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() {
                self.calls.push(segment.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if let Some(segment) = path.path.segments.last() {
            self.paths.push(segment.ident.to_string());
        }
        syn::visit::visit_expr_path(self, path);
    }
}

#[test]
fn native_terminal_transport_uses_only_exact_nonblocking_pool_effects() {
    let file = transport();
    let owner = file.items.iter().find_map(|item| match item {
        Item::Struct(item) if item.ident == "RetainedTerminalPacket" => Some(item),
        _ => None,
    }).expect("one durable transport owner");
    let allocation = owner.fields.iter().find(|field| field.ident.as_ref().is_some_and(|name| name == "allocation")).unwrap();
    let mut owned_type = Effects::default();
    owned_type.visit_type(&allocation.ty);
    assert!(owned_type.paths.iter().any(|path| path == "Option"));
    assert!(owned_type.paths.iter().any(|path| path == "RootProviderPoolAllocation"));
    let mut effects = Effects::default();
    effects.visit_file(&file);
    for required in ["try_allocate_root_provider_pool_allocation",
        "try_publish_root_provider_pool_packet", "try_capture_root_provider_pool_packet",
        "try_retire_root_provider_pool_allocation"] {
        assert!(effects.calls.iter().any(|call| call == required));
    }
    for forbidden in ["allocate_root_provider_pool_packet", "publish_provider_pool_packet",
        "capture_provider_pool_packet", "retire_root_provider_pool_packet", "provider_pool_lock"] {
        assert!(!effects.calls.iter().any(|call| call == forbidden));
    }
}

#[test]
fn all_source_work_owners_use_shared_transport_without_legacy_commit_state() {
    for kind in ["ioctl", "fsd", "pnp"] {
        let path = format!("{}/../../components/ntos-executive/src/hosted_kernel_win32k_source_{kind}.rs",
            env!("CARGO_MANIFEST_DIR"));
        let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
        assert!(!file.items.iter().any(|item| matches!(item, Item::Fn(function)
            if function.sig.ident == "commit_origin_packet")));
        let work = file.items.iter().find_map(|item| match item {
            Item::Struct(item) if item.ident == "Work" => Some(item),
            _ => None,
        }).unwrap();
        assert!(!work.fields.iter().any(|field|
            field.ident.as_ref().is_some_and(|name| name == "origin_commit_requested")));
        let packet = work.fields.iter().find(|field|
            field.ident.as_ref().is_some_and(|name| name == "terminal_packet")).unwrap();
        let mut owner = Effects::default();
        owner.visit_type(&packet.ty);
        assert!(owner.paths.iter().any(|path| path == "RetainedTerminalPacket"));
        let mut effects = Effects::default();
        for item in &file.items {
            if let Item::Impl(item) = item {
                if matches!(&*item.self_ty, syn::Type::Path(path) if path.path.is_ident("Work")) {
                    effects.visit_item_impl(item);
                }
            }
        }
        for forbidden in ["allocate_root_provider_pool_packet", "publish_provider_pool_packet",
            "capture_provider_pool_packet", "retire_root_provider_pool_packet", "commit_origin_packet"] {
            assert!(!effects.calls.iter().any(|call| call == forbidden), "{kind} Work uses {forbidden}");
        }
    }
}

#[test]
fn local_progress_rechecks_lane_admission_only_at_actual_dispatch() {
    let file = transport();
    let mut readiness = Effects::default();
    readiness.visit_impl_item_fn(&method(&file, "needs_lane"));
    assert!(readiness.paths.iter().any(|path| path == "DispatchOrigin"));
    assert!(!readiness.paths.iter().any(|path| path == "ReadAck" || path == "RetirePacket"));
    for name in ["prepare", "finish"] {
        let mut effects = Effects::default();
        effects.visit_impl_item_fn(&method(&file, name));
        let gate = effects.calls.iter().position(|call| call == "source_terminal_dispatch_ready").unwrap();
        let dispatch = effects.calls.iter().position(|call| call == "dispatch").unwrap();
        assert!(gate < dispatch, "local progress cannot enter a new callback phase without admission");
    }
}

#[test]
fn completed_terminal_retries_validate_the_exact_command_before_success() {
    let finish = method(&transport(), "finish");
    struct Observe { fields: Vec<String>, complete: Option<usize>, command: Option<usize> }
    impl<'ast> Visit<'ast> for Observe {
        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            if let syn::Member::Named(name) = &field.member {
                let index = self.fields.len();
                self.fields.push(name.to_string());
                if name == "command" && self.command.is_none() { self.command = Some(index); }
            }
            syn::visit::visit_expr_field(self, field);
        }
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            if path.path.segments.last().is_some_and(|part| part.ident == "Complete")
                && self.complete.is_none() {
                self.complete = Some(self.fields.len());
            }
            syn::visit::visit_expr_path(self, path);
        }
    }
    let mut observed = Observe { fields: Vec::new(), complete: None, command: None };
    observed.visit_impl_item_fn(&finish);
    assert!(observed.command.unwrap() < observed.complete.unwrap(),
        "an acknowledged commit cannot masquerade as an acknowledged discard after packet retirement");
}

#[test]
fn origin_success_records_readback_phase_instead_of_replaying_dispatch() {
    struct Arms { success: bool, readback: bool, retirement: bool }
    impl<'ast> Visit<'ast> for Arms {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            let mut effects = Effects::default();
            effects.visit_expr(&arm.body);
            if let syn::Pat::TupleStruct(pattern) = &arm.pat {
                let returned_zero = pattern.path.segments.last().is_some_and(|part| part.ident == "Returned")
                    && matches!(pattern.elems.first(), Some(syn::Pat::Lit(value))
                        if matches!(&value.lit, syn::Lit::Int(value) if matches!(value.base10_parse::<u32>(), Ok(0))));
                if returned_zero {
                    self.success = true;
                    assert!(effects.paths.iter().any(|path| path == "ReturnedSuccess"));
                    assert!(!effects.calls.iter().any(|call| call == "try_capture_root_provider_pool_packet"));
                }
            }
            if let syn::Pat::Path(path) = &arm.pat {
                let phase = path.path.segments.last().unwrap().ident.to_string();
                if phase == "ReadAck" || phase == "RetirePacket" {
                    assert!(!effects.calls.iter().any(|call| call == "dispatch"),
                        "a local post-success phase cannot require another callback");
                    self.readback |= phase == "ReadAck";
                    self.retirement |= phase == "RetirePacket";
                }
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut arms = Arms { success: false, readback: false, retirement: false };
    arms.visit_impl_item_fn(&method(&transport(), "finish"));
    assert!(arms.success && arms.readback && arms.retirement);
}

#[test]
fn prepare_success_is_durable_before_busy_ack_readback() {
    struct Success(bool);
    impl<'ast> Visit<'ast> for Success {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if let syn::Pat::TupleStruct(pattern) = &arm.pat {
                if pattern.path.segments.last().is_some_and(|part| part.ident == "Returned")
                    && matches!(pattern.elems.first(), Some(syn::Pat::Lit(value))
                        if matches!(&value.lit, syn::Lit::Int(value) if matches!(value.base10_parse::<u32>(), Ok(0)))) {
                    let mut effects = Effects::default();
                    effects.visit_expr(&arm.body);
                    assert!(effects.paths.iter().any(|path| path == "ReadAck"));
                    assert!(!effects.calls.iter().any(|call| call == "try_capture_root_provider_pool_packet"));
                    self.0 = true;
                }
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut success = Success(false);
    success.visit_impl_item_fn(&method(&transport(), "prepare"));
    assert!(success.0);
}
