use syn::visit::Visit;

#[test]
fn boot_directory_policy_reads_the_composed_core_hive_transport() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_directory_security.rs"
    ))
    .unwrap();
    let capture = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "capture_boot_protection_mode" => Some(item),
            _ => None,
        })
        .expect("native bootstrap captures the composed SYSTEM policy");
    #[derive(Default)]
    struct Decoder {
        core: bool,
        regf: bool,
    }
    impl<'ast> Visit<'ast> for Decoder {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            self.core |= path
                .path
                .segments
                .last()
                .is_some_and(|part| part.ident == "boot_object_protection_mode_from_image");
            self.regf |= path
                .path
                .segments
                .iter()
                .any(|part| part.ident == "RegfHive");
            syn::visit::visit_expr_path(self, path);
        }
    }
    let mut decoder = Decoder::default();
    decoder.visit_block(&capture.block);
    assert!(
        decoder.core && !decoder.regf,
        "the owned composed SYSTEM is a core hive image, not the installed REGF source"
    );
}

#[test]
fn directory_creation_grant_uses_shared_policy_and_audits_before_error_propagation() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_directory_security.rs"
    ))
    .unwrap();
    fn argument_name(expression: &syn::Expr) -> Option<String> {
        match expression {
            syn::Expr::Reference(reference) => argument_name(&reference.expr),
            syn::Expr::Path(path) => path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string()),
            _ => None,
        }
    }
    #[derive(Default)]
    struct Audit {
        attributes: bool,
        granted: bool,
        used: bool,
        denied: bool,
        used_flag: bool,
        denied_on_false: bool,
        propagation: bool,
    }
    impl<'ast> Visit<'ast> for Audit {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            self.used_flag |= path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "SE_PRIVILEGE_USED_FOR_ACCESS");
            syn::visit::visit_expr_path(self, path);
        }
        fn visit_expr_unary(&mut self, expression: &'ast syn::ExprUnary) {
            self.denied_on_false |= matches!(expression.op, syn::UnOp::Not(_))
                && matches!(&*expression.expr, syn::Expr::Field(field)
                    if matches!(&field.member, syn::Member::Named(name) if name == "granted"));
            syn::visit::visit_expr_unary(self, expression);
        }
        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            self.attributes |=
                matches!(&field.member, syn::Member::Named(name) if name == "attributes");
            self.granted |= matches!(&field.member, syn::Member::Named(name) if name == "granted");
            syn::visit::visit_expr_field(self, field);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "fetch_add" {
                self.used |= argument_name(&call.receiver).as_deref() == Some("PRIVILEGES_USED");
                self.denied |=
                    argument_name(&call.receiver).as_deref() == Some("PRIVILEGE_DENIALS");
            }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
            self.propagation |= argument_name(&expression.expr).as_deref() == Some("granted");
            syn::visit::visit_expr_try(self, expression);
        }
    }
    struct Binding(bool);
    impl<'ast> Visit<'ast> for Binding {
        fn visit_block(&mut self, block: &'ast syn::Block) {
            for (position, statement) in block.stmts.iter().enumerate() {
                let syn::Stmt::Local(local) = statement else {
                    continue;
                };
                let Some(initializer) = &local.init else {
                    continue;
                };
                let syn::Expr::Call(call) = &*initializer.expr else {
                    continue;
                };
                if argument_name(&call.func).as_deref() != Some("prepare_object_creation_grant") {
                    continue;
                }
                let arguments: Vec<_> = call.args.iter().map(argument_name).collect();
                assert_eq!(
                    arguments,
                    [
                        "tokens",
                        "desired_access",
                        "DIRECTORY_GENERIC_MAPPING",
                        "mode",
                        "privilege_audit"
                    ]
                    .map(|name| Some(name.to_owned()))
                );
                let mut audit = Audit::default();
                let mut saw_audit = false;
                let mut saw_propagation = false;
                for following in &block.stmts[position + 1..] {
                    audit.visit_stmt(following);
                    if audit.propagation {
                        assert!(
                            saw_audit,
                            "privilege audit must be recorded even when grant returns an error"
                        );
                        saw_propagation = true;
                        break;
                    }
                    saw_audit |= audit.attributes
                        && audit.granted
                        && audit.used
                        && audit.denied
                        && audit.used_flag
                        && audit.denied_on_false;
                }
                assert!(
                    saw_propagation,
                    "the exact grant result must propagate after audit"
                );
                self.0 = true;
            }
            syn::visit::visit_block(self, block);
        }
    }
    let mut binding = Binding(false);
    binding.visit_block(&method(&file, "prepare_directory_object_security").block);
    assert!(
        binding.0,
        "Directory must consume the shared creation-grant policy"
    );
}

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
    calls.visit_block(&method(&file, "reserve_native_directory_object_open").block);
    let security = calls
        .0
        .iter()
        .position(|name| name == "prepare_directory_object_security")
        .expect(
            "native directory admission needs retained subject, exact parent and owned descriptor",
        );
    let reservation = calls
        .0
        .iter()
        .position(|name| name == "reserve_directory_object_open_from_security")
        .expect("only admitted security may enter the handle/canonical reservation helper");
    assert!(
        security < reservation,
        "security admission precedes namespace/handle effects"
    );
    let mut effects = Calls::default();
    effects.visit_block(&method(&file, "reserve_directory_object_open_from_security").block);
    assert!(effects
        .0
        .iter()
        .any(|name| name == "reserve_native_object_directory_handle"));
    assert!(effects.0.iter().any(|name| name == "reserve"));
}

#[test]
fn native_directory_handle_is_published_only_after_checked_copyout() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/native_directory_open_work.rs"
    ))
    .unwrap();
    let mut calls = Calls::default();
    calls.visit_block(
        &file
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == "step" => Some(&function.block),
                _ => None,
            })
            .expect("retained native open owns copyout and publication"),
    );
    let copy = calls
        .0
        .iter()
        .position(|name| name == "process_memory_write_checked")
        .expect("directory final handle copy preserves exact fault status");
    let publish = calls
        .0
        .iter()
        .position(|name| name == "publish_directory_local")
        .expect("visible PM publication follows successful checked output");
    assert!(copy < publish);
    assert!(
        calls
            .0
            .iter()
            .any(|name| name == "rollback_unpublished_directory_open"),
        "failed copyout must retain canonical rollback ownership"
    );
}

#[test]
fn root_directory_handle_reference_does_not_require_traverse_handle_access() {
    let file = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_namespace_security.rs"
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
            "reserve_native_directory_object_open",
            &[
                "prepare_directory_object_security",
                "reserve_directory_object_open_from_security",
            ][..],
        ),
        (
            "reserve_provider_directory_object",
            &[
                "prepare_directory_object_security",
                "reserve_directory_object_open_from_security",
            ][..],
        ),
        ("canonical_publish_directory_object", &["publish"][..]),
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
    let namespace = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_namespace_security.rs"
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
        let owner = if name == "capture_named_creator_security_descriptor" {
            &namespace
        } else {
            &file
        };
        calls.visit_block(&method(owner, name).block);
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
        "reserve_native_directory_object_open",
        "reserve_provider_directory_object",
    ] {
        // Both entrypoints must pass admitted security to the one reservation helper;
        // the helper, rather than either caller, consumes normalized PM attributes.
        let mut normalized = NormalizedAttributes::default();
        normalized.visit_block(&method(&file, "reserve_directory_object_open_from_security").block);
        assert!(
            normalized.0,
            "{name} must reach PM reservation through admitted normalized attributes"
        );
        let mut calls = Calls::default();
        calls.visit_block(&method(&file, name).block);
        assert!(calls
            .0
            .iter()
            .any(|call| call == "reserve_directory_object_open_from_security"));
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
    let sweep = calls
        .0
        .iter()
        .position(|name| name == "sweep_directory_security_bodies")
        .expect("service cleanup must converge retired directory bodies");
    for drain in ["redrive", "redrive_effects", "redrive_detached"] {
        assert!(
            calls
                .0
                .iter()
                .position(|name| name == drain)
                .is_some_and(|position| position < sweep),
            "directory completion must settle before security-body retirement"
        );
    }
    assert!(
        calls
            .0
            .iter()
            .position(|name| name == "fold_system_wal_if_dirty")
            .is_some_and(|position| sweep < position),
        "directory retirement must run before WAL early returns"
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
        .position(|name| name == "reserve_directory_object_open_from_security")
        .unwrap();
    assert!(security < reservation);
    let reservation = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "ReservedDirectoryObjectOpen" => Some(item),
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
    calls.visit_block(&method(&file, "commit_directory_local").block);
    let security = calls
        .0
        .iter()
        .position(|name| name == "commit_directory_object_security")
        .expect("publication revalidates the retained exact directory admission");
    let bind = calls.0.iter().position(|name| name == "bind").unwrap();
    assert!(security < bind);
    let mut publication = Calls::default();
    publication.visit_block(&method(&file, "publish_provider_directory_object").block);
    assert!(publication
        .0
        .iter()
        .any(|name| name == "finish_provider_directory_local"));
    let mut finish = Calls::default();
    finish.visit_block(&method(&file, "finish_provider_directory_local").block);
    assert!(finish.0.iter().any(|name| name == "commit_directory_local"));
}

#[test]
fn retained_directory_queues_allocate_in_durable_scope() {
    let directory = source();
    let handler = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_handler.rs"
    )).unwrap();
    let open = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/native_directory_open_work.rs"
    )).unwrap();
    let effect = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/native_directory_effect_work.rs"
    )).unwrap();
    for (owner, name) in [
        (&directory, "commit_directory_local"),
        (&handler, "retain_external_handle_reference"),
    ] {
        let mut calls = Calls::default();
        calls.visit_block(&method(owner, name).block);
        let durable = calls.0.iter().position(|call| call == "enter_durable");
        let reserve = calls.0.iter().position(|call| call == "reserve");
        assert!(matches!((durable, reserve), (Some(d), Some(r)) if d < r),
            "{name} must enter durable scope before reserving cleanup capacity");
    }
    for (owner, name) in [(&open, "park"), (&effect, "park")] {
        let function = owner.items.iter().find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        }).unwrap();
        let mut calls = Calls::default();
        calls.visit_block(&function.block);
        let durable = calls.0.iter().position(|call| call == "enter_durable");
        let reserve = calls.0.iter().position(|call| call == "try_reserve");
        assert!(matches!((durable, reserve), (Some(d), Some(r)) if d < r),
            "{name} must enter durable scope before growing its retained Reply queue");
    }
}
