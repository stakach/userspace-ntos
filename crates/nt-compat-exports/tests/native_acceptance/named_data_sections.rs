use syn::parse::Parser;
use syn::visit::Visit;

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(
        &std::fs::read_to_string(path)
            .unwrap_or_else(|_| panic!("missing focused named Section boundary {name}")),
    )
    .unwrap()
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_macro(&mut self, item: &'ast syn::Macro) {
        if let Ok(expressions) =
            syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                .parse2(item.tokens.clone())
        {
            for expression in &expressions {
                let mut nested = Calls::default();
                nested.visit_expr(expression);
                self.0.extend(nested.0);
            }
        }
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn method(file: &syn::File, name: &str) -> syn::Block {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(item) if item.sig.ident == name => Some(item.block.clone()),
                _ => None,
            }),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing actual {name} service"))
}

fn function(file: &syn::File, name: &str) -> syn::Block {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == name => Some((*item.block).clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing actual {name} function"))
}

#[test]
fn temporary_data_name_withdrawal_precedes_final_handle_group_release_without_unmapping_views() {
    // NT5/ReactOS ObpDeleteNameCheck uses global HandleCount, not pointer/view count.
    let block = method(&source("exec_handler.rs"), "release_handle_object");
    struct LastHandle(bool);
    impl<'ast> Visit<'ast> for LastHandle {
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            if let syn::Expr::Binary(condition) = &*branch.cond {
                if matches!(condition.op, syn::BinOp::Eq(_))
                    && matches!(&*condition.right, syn::Expr::Lit(value)
                        if matches!(&value.lit, syn::Lit::Int(value) if value.base10_parse::<u64>().ok() == Some(0)))
                {
                    if let syn::Expr::MethodCall(count) = &*condition.left {
                        if count.method == "handle_object_count"
                            && count.args.iter().any(|arg| matches!(arg, syn::Expr::Call(call)
                                if matches!(&*call.func, syn::Expr::Path(path)
                                    if path.path.segments.last().is_some_and(|part| part.ident == "Section"))))
                        {
                            let mut calls = Calls::default();
                            calls.visit_block(&branch.then_branch);
                            self.0 |= calls.0.iter().any(|name| name == "data_section_last_handle_closed");
                        }
                    }
                }
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let mut last = LastHandle(false);
    last.visit_block(&block);
    assert!(
        last.0,
        "DATA name cleanup belongs to globally-last canonical Section handle close"
    );

    let file = source("exec_named_data_sections.rs");
    let mut close = Calls::default();
    close.visit_block(&method(&file, "data_section_last_handle_closed"));
    let withdraw = close
        .0
        .iter()
        .position(|name| name == "withdraw_data_section_name")
        .expect("temporary names lose their namespace reference even with live views");
    let release = close
        .0
        .iter()
        .position(|name| name == "release_handle")
        .unwrap();
    assert!(
        withdraw < release,
        "withdraw the exact name reference before final handle-group release"
    );
    assert!(
        !close.0.iter().any(|name| name.starts_with("unmap")),
        "handle close must preserve live views"
    );
    let mut name = Calls::default();
    name.visit_block(&method(&file, "withdraw_data_section_name"));
    let unlink = name.0.iter().position(|name| name == "unlink").unwrap();
    let release = name
        .0
        .iter()
        .position(|name| name == "release_section_reference")
        .expect("the namespace owns a real exact SectionReference, not SD/index metadata");
    assert!(unlink < release);
}

#[test]
fn named_section_open_uses_typed_canonical_handles_without_identity_bypass() {
    let file = source("exec_named_sections.rs");
    let open = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "nt_open_section_service" => {
                    Some(method)
                }
                _ => None,
            }),
            _ => None,
        })
        .expect("NtOpenSection must have one focused canonical service");
    let mut calls = Calls::default();
    calls.visit_block(&open.block);
    for required in [
        "capture_named_object_attributes",
        "reserve_native_section_handle",
        "bind",
        "publish",
        "prepare_data_section_name",
        "submit_local_data",
    ] {
        assert!(
            calls.0.iter().any(|name| name == required),
            "canonical named open retains {required}"
        );
    }
    for forbidden in [
        "mint_handle",
        "smss_read_objattr_name",
        "smss_stack_write",
        "windows",
    ] {
        assert!(
            !calls.0.iter().any(|name| name == forbidden),
            "no named Section bypass via {forbidden}"
        );
    }
    struct ForbiddenIdentity(bool);
    impl<'ast> Visit<'ast> for ForbiddenIdentity {
        fn visit_expr_lit(&mut self, literal: &'ast syn::ExprLit) {
            let bytes = match &literal.lit {
                syn::Lit::ByteStr(value) => value.value(),
                syn::Lit::Str(value) => value.value().into_bytes(),
                _ => Vec::new(),
            };
            self.0 |= bytes
                .windows(17)
                .any(|word| word.eq_ignore_ascii_case(b"nlssectioncp20127"));
        }
    }
    let mut identity = ForbiddenIdentity(false);
    identity.visit_block(&open.block);
    assert!(
        !identity.0,
        "a code-page name is not canonical Section authority"
    );
    let work = source("section_metadata_work.rs");
    let mut local = Calls::default();
    local.visit_block(&function(&work, "submit_local_data"));
    assert!(local.0.iter().any(|name| name == "retain_work"));
    let mut publication = Calls::default();
    publication.visit_block(&function(&work, "publish_data_section_work"));
    assert!(publication
        .0
        .iter()
        .any(|name| name == "publish_existing_data_section"));
    let mut existing = Calls::default();
    existing.visit_block(&method(
        &source("exec_named_data_sections.rs"),
        "publish_existing_data_section",
    ));
    for required in ["bind", "bind_section_reference_handle", "publish"] {
        assert!(
            existing.0.iter().any(|name| name == required),
            "DATA open retains exact {required}"
        );
    }
    let mut copy = Calls::default();
    copy.visit_block(&function(&work, "copy_data_section_output"));
    assert!(copy
        .0
        .iter()
        .any(|name| name == "process_memory_write_checked"));
    assert!(!copy.0.iter().any(|name| matches!(
        name.as_str(),
        "publish" | "abort" | "close_process_handle_checked"
    )));
}

#[test]
fn late_data_section_openif_uses_retained_admission_and_existing_security() {
    let file = source("exec_named_data_sections.rs");
    let method = file.items.iter().find_map(|item| match item {
        syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "reconcile_data_section_name" => Some(method),
            _ => None,
        }),
        _ => None,
    }).expect("a parked named DATA create must reconcile late OPENIF insertion with its retained admission");
    let mut calls = Calls::default();
    calls.visit_block(&method.block);
    for required in [
        "obj_child",
        "resolve",
        "authorize_section_open",
        "retain_section_reference",
    ] {
        assert!(
            calls.0.iter().any(|call| call == required),
            "late OPENIF retains {required}"
        );
    }
    for forbidden in [
        "capture_named_object_attributes",
        "native_handle_caller",
        "capture",
        "obj_resolve",
        "assign_section_security",
    ] {
        assert!(
            !calls.0.iter().any(|call| call == forbidden),
            "late insertion cannot replace admitted authority using {forbidden}"
        );
    }
}

#[test]
fn late_openif_authorization_uses_retained_request_not_new_creation_grant() {
    let block = method(
        &source("exec_named_data_sections.rs"),
        "reconcile_data_section_name",
    );
    fn admission_field(expression: &syn::Expr, name: &str) -> bool {
        matches!(expression, syn::Expr::Field(field)
            if matches!(&*field.base, syn::Expr::Path(path) if path.path.is_ident("admission"))
                && matches!(&field.member, syn::Member::Named(member) if member == name))
    }
    struct Authority {
        open_if: bool,
        original_request: bool,
    }
    impl<'ast> Visit<'ast> for Authority {
        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            self.open_if |= admission_field(&syn::Expr::Field(field.clone()), "open_if");
            syn::visit::visit_expr_field(self, field);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|part| part.ident == "authorize_section_open"))
            {
                self.original_request |= call.args.len() == 4
                    && admission_field(&call.args[2], "requested_access")
                    && admission_field(&call.args[3], "access_mode");
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut authority = Authority {
        open_if: false,
        original_request: false,
    };
    authority.visit_block(&block);
    assert!(
        authority.open_if,
        "late collision must honor retained OPENIF intent"
    );
    assert!(authority.original_request,
        "existing SD must check original MAX/SACL request in retained Force access mode, not new-object grant");
}

#[test]
fn data_section_name_is_admitted_before_metadata_or_backing_effects() {
    let file = source("exec_handler.rs");
    struct CreateArm(Vec<String>);
    impl<'ast> Visit<'ast> for CreateArm {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if matches!(&arm.pat, syn::Pat::Path(path)
                if path.path.segments.last().unwrap().ident == "NtCreateSection")
            {
                let syn::Expr::Unsafe(body) = &*arm.body else {
                    panic!("section service body");
                };
                for statement in &body.block.stmts {
                    // SEC_IMAGE has its own existing named-image admission. Inspect only DATA.
                    if let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement {
                        struct ImageBranch(bool);
                        impl<'ast> Visit<'ast> for ImageBranch {
                            fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
                                self.0 |= path.path.segments.last().unwrap().ident == "SEC_IMAGE";
                            }
                        }
                        let mut image = ImageBranch(false);
                        image.visit_expr(&branch.cond);
                        if image.0 {
                            continue;
                        }
                    }
                    let mut calls = Calls::default();
                    calls.visit_stmt(statement);
                    self.0.extend(calls.0);
                }
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut arm = CreateArm(Vec::new());
    arm.visit_file(&file);
    let admission = arm
        .0
        .iter()
        .position(|name| name == "prepare_data_section_name")
        .expect("named DATA Section namespace/collision admission precedes backing effects");
    let delegated = arm
        .0
        .iter()
        .position(|name| name == "create_admitted_data_section")
        .unwrap();
    assert!(admission < delegated);
    let mut helper = Calls::default();
    helper.visit_block(&method(
        &source("exec_named_data_sections.rs"),
        "create_admitted_data_section",
    ));
    for effect in [
        "submit_hosted_data",
        "reserve_generic_data_section",
        "submit_local_data",
    ] {
        assert!(
            helper.0.iter().any(|name| name == effect),
            "admitted DATA creation delegates actual {effect}"
        );
    }
}

#[test]
fn code_page_files_use_normal_file_and_section_paths_not_boot_staging() {
    struct StagedIdentity(bool);
    impl<'ast> Visit<'ast> for StagedIdentity {
        fn visit_ident(&mut self, ident: &'ast syn::Ident) {
            self.0 |= matches!(
                ident.to_string().as_str(),
                "NLS_20127_START"
                    | "NLS_20127_VADDR"
                    | "NLS_20127_FRAMES"
                    | "nls20127_start"
                    | "nls20127_dest"
                    | "nls_section_handle"
            );
        }
    }
    for name in [
        "main.rs",
        "device_io.rs",
        "spawn_hosts.rs",
        "storage_host.rs",
        "service_sec_image.rs",
    ] {
        let mut identity = StagedIdentity(false);
        identity.visit_file(&source(name));
        assert!(
            !identity.0,
            "{name} must not stage one code page outside canonical File/Section ownership"
        );
    }
}
