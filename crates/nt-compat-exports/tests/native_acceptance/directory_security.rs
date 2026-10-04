use syn::visit::Visit;

fn source() -> syn::File {
    syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_directory_object.rs"
    ))
    .unwrap()
}

fn method<'a>(file: &'a syn::File, name: &str) -> &'a syn::ImplItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                _ => None,
            }),
            _ => None,
        })
        .unwrap()
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn native_directory_admission_checks_actual_subject_and_descriptor_before_effects() {
    let file = source();
    let mut calls = Calls::default();
    calls.visit_block(&method(&file, "stage_native_directory_object_open").block);
    let security = calls
        .0
        .iter()
        .position(|name| name == "prepare_directory_object_security")
        .expect(
            "native directory admission needs retained subject, exact parent and owned descriptor",
        );
    for effect in [
        "reserve_native_object_directory_handle",
        "commit_directory_object_security",
        "bind",
    ] {
        let effect = calls.0.iter().position(|name| name == effect).unwrap();
        assert!(
            security < effect,
            "security admission precedes namespace/handle effects"
        );
    }
}

#[test]
fn native_directory_handle_is_committed_before_checked_copyout_without_late_abort() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_named_directories.rs"
    ))
    .unwrap();
    let method = method(&file, "nt_named_directory_service");
    let mut calls = Calls::default();
    calls.visit_block(&method.block);
    let publish = calls.0.iter().position(|name| name == "publish").unwrap();
    let copy = calls
        .0
        .iter()
        .position(|name| name == "process_memory_write_checked")
        .expect("directory final handle copy preserves exact fault status");
    assert!(
        publish < copy,
        "ObInsert/Open commits the handle before final caller copy"
    );
    assert!(
        !calls.0[copy..]
            .iter()
            .any(|name| name == "abort_staged_directory_object_open"),
        "late copy faults cannot withdraw an already committed directory handle"
    );
}

#[test]
fn root_directory_handle_reference_does_not_require_traverse_handle_access() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_handler.rs"
    ))
    .unwrap();
    struct RequiredAccess(Option<u32>);
    impl<'ast> Visit<'ast> for RequiredAccess {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "lookup_native_object_directory_handle" {
                self.0 = match call.args.iter().nth(2) {
                    Some(syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Int(value),
                        ..
                    })) => value.base10_parse().ok(),
                    _ => None,
                };
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut access = RequiredAccess(None);
    access.visit_block(&method(&file, "native_directory_root_and_path").block);
    assert_eq!(access.0, Some(0),
        "NT references the RootDirectory object with access0; captured SD/traverse policy authorizes lookup");
}

#[test]
fn directory_force_access_check_selects_user_authorization_for_kernel_callers() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_directory_security.rs"
    ))
    .unwrap();
    #[derive(Default)]
    struct ForceMode(bool);
    impl<'ast> Visit<'ast> for ForceMode {
        fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
            #[derive(Default)]
            struct Condition {
                force_bit: bool,
                attributes: bool,
            }
            impl<'ast> Visit<'ast> for Condition {
                fn visit_lit_int(&mut self, value: &'ast syn::LitInt) {
                    self.force_bit |= matches!(value.base10_parse::<u32>(), Ok(0x400));
                }
                fn visit_member(&mut self, member: &'ast syn::Member) {
                    self.attributes |=
                        matches!(member, syn::Member::Named(name) if name == "attributes");
                }
            }
            #[derive(Default)]
            struct UserMode(bool);
            impl<'ast> Visit<'ast> for UserMode {
                fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
                    self.0 |= path
                        .path
                        .segments
                        .last()
                        .is_some_and(|segment| segment.ident == "UserMode");
                }
            }
            let mut condition = Condition::default();
            condition.visit_expr(&expression.cond);
            let mut mode = UserMode::default();
            mode.visit_block(&expression.then_branch);
            self.0 |= condition.force_bit && condition.attributes && mode.0;
            syn::visit::visit_expr_if(self, expression);
        }
    }
    let mut policy = ForceMode::default();
    policy.visit_block(&method(&file, "prepare_directory_object_security").block);
    assert!(
        policy.0,
        "OBJ_FORCE_ACCESS_CHECK must suppress the captured KernelMode bypass"
    );
}

#[test]
fn directory_entrypoints_own_durable_scope_across_retained_handle_effects() {
    let file = source();
    for (name, effects) in [
        (
            "stage_native_directory_object_open",
            &[
                "reserve_native_object_directory_handle",
                "commit_directory_object_security",
                "bind",
            ][..],
        ),
        (
            "reserve_provider_directory_object",
            &["reserve_native_object_directory_handle"][..],
        ),
        (
            "publish_provider_directory_object",
            &[
                "commit_directory_object_security",
                "publish",
                "record_process_handle_insert",
            ][..],
        ),
    ] {
        let body = &method(&file, name).block;
        let guard = body.stmts.iter().position(|statement| {
            let syn::Stmt::Local(local) = statement else { return false; };
            let syn::Pat::Ident(binding) = &local.pat else { return false; };
            if binding.by_ref.is_some() { return false; }
            let Some(initializer) = &local.init else { return false; };
            let syn::Expr::Call(call) = &*initializer.expr else { return false; };
            matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().unwrap().ident == "enter_durable")
        }).unwrap_or_else(|| panic!("{name} must own a top-level durable scope, not rely on a callee's expired guard"));
        for effect in effects {
            let position = body
                .stmts
                .iter()
                .position(|statement| {
                    let mut calls = Calls::default();
                    calls.visit_stmt(statement);
                    calls.0.iter().any(|call| call.as_str() == *effect)
                })
                .unwrap_or_else(|| panic!("{name} retains {effect}"));
            assert!(
                guard < position,
                "{name} must keep durable allocation active before {effect}"
            );
        }
    }
}

#[test]
fn retained_directory_security_allocations_are_durable_before_capture_and_publication() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_directory_security.rs"
    ))
    .unwrap();
    for (name, first_effect) in [
        (
            "capture_named_creator_security_descriptor",
            "capture_security_descriptor_bytes",
        ),
        ("prepare_directory_object_security", "capture"),
        ("commit_directory_object_security", "try_reserve"),
    ] {
        let mut calls = Calls::default();
        calls.visit_block(&method(&file, name).block);
        let durable = calls
            .0
            .iter()
            .position(|call| call == "enter_durable")
            .unwrap();
        let effect = calls
            .0
            .iter()
            .position(|call| call == first_effect)
            .unwrap();
        assert!(
            durable < effect,
            "{name} may retain allocations beyond the syscall scratch scope"
        );
    }
    let bootstrap = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "prepare_boot_directory_security" => {
                Some(function)
            }
            _ => None,
        })
        .unwrap();
    let mut calls = Calls::default();
    calls.visit_block(&bootstrap.block);
    assert!(
        calls
            .0
            .iter()
            .position(|call| call == "enter_durable")
            .unwrap()
            < calls.0.iter().position(|call| call == "capture").unwrap()
    );
}

#[test]
fn directory_attribute_admission_precedes_capture_and_normalizes_both_handle_boundaries() {
    let security = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_directory_security.rs"
    ))
    .unwrap();
    let mut calls = Calls::default();
    calls.visit_block(&method(&security, "prepare_directory_object_security").block);
    let admission = calls
        .0
        .iter()
        .position(|call| call == "admit_directory_object_attributes")
        .expect(
            "Directory flags require canonical validation and honest unsupported-feature refusal",
        );
    assert!(admission < calls.0.iter().position(|call| call == "capture").unwrap());
    let file = source();
    #[derive(Default)]
    struct NormalizedAttributes(bool);
    impl<'ast> Visit<'ast> for NormalizedAttributes {
        fn visit_member(&mut self, member: &'ast syn::Member) {
            self.0 |= matches!(member, syn::Member::Named(name) if name == "handle_attributes");
        }
    }
    for name in [
        "stage_native_directory_object_open",
        "reserve_provider_directory_object",
    ] {
        let mut normalized = NormalizedAttributes::default();
        normalized.visit_block(&method(&file, name).block);
        assert!(
            normalized.0,
            "{name} must reserve PM handles with admitted normalized attributes"
        );
    }
}

#[test]
fn directory_body_retirement_converges_at_service_cleanup_after_exact_owner_fences() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_directory_security.rs"
    ))
    .unwrap();
    let mut calls = Calls::default();
    calls.visit_block(&method(&file, "retire_directory_security_body").block);
    let withdrawal = calls.0.iter().position(|name| name == "retain").unwrap();
    for fence in ["handle_object_count", "find", "any"] {
        assert!(calls.0.iter().position(|name| name == fence).unwrap() < withdrawal);
    }
    let sweep = method(&file, "sweep_directory_security_bodies");
    let mut calls = Calls::default();
    calls.visit_block(&sweep.block);
    assert!(calls
        .0
        .iter()
        .any(|name| name == "retire_directory_security_body"));
    assert!(!calls.0.iter().any(|name| name == "note_boot_progress"));
    let service = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/service_sec_image.rs"
    ))
    .unwrap();
    let finalize = service
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "finalize_service_loop_work" => {
                Some(function)
            }
            _ => None,
        })
        .unwrap();
    let mut calls = Calls::default();
    calls.visit_block(&finalize.block);
    assert_eq!(
        calls.0.first().map(String::as_str),
        Some("sweep_directory_security_bodies")
    );
}

#[test]
fn provider_directory_reservation_retains_same_security_admission_through_publication() {
    let file = source();
    let mut calls = Calls::default();
    calls.visit_block(&method(&file, "reserve_provider_directory_object").block);
    let security = calls
        .0
        .iter()
        .position(|name| name == "prepare_directory_object_security")
        .expect("provider directory upload cannot bypass actual captured creator security");
    let reservation = calls
        .0
        .iter()
        .position(|name| name == "reserve_native_object_directory_handle")
        .unwrap();
    assert!(security < reservation);
    let reservation = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "ReservedProviderDirectoryObject" => {
                Some(item)
            }
            _ => None,
        })
        .unwrap();
    assert!(
        reservation
            .fields
            .iter()
            .any(|field| field.ident.as_ref().is_some_and(|name| name == "security")),
        "the admitted subject and descriptor remain owned while provider output is in flight"
    );
    let mut calls = Calls::default();
    calls.visit_block(&method(&file, "publish_provider_directory_object").block);
    let security = calls
        .0
        .iter()
        .position(|name| name == "commit_directory_object_security")
        .expect("publication revalidates the retained exact directory admission");
    let bind = calls.0.iter().position(|name| name == "bind").unwrap();
    assert!(security < bind);
}
