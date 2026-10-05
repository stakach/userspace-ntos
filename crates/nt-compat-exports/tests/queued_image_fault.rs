use syn::visit::Visit;

#[derive(Default)]
struct Calls(Vec<String>);
impl<'a> Visit<'a> for Calls {
    fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn source() -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/native_image_residency.rs");
    syn::parse_file(&std::fs::read_to_string(path).expect(
        "canonical image pages require a retained source cache, not private anonymous pages",
    ))
    .unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing canonical image lifecycle function {name}"))
}

fn calls(file: &syn::File, name: &str) -> Vec<String> {
    let function = function(file, name);
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    calls.0
}

fn names_in_expression(expression: &syn::Expr) -> Vec<String> {
    struct Names(Vec<String>);
    impl<'a> Visit<'a> for Names {
        fn visit_path_segment(&mut self, segment: &'a syn::PathSegment) {
            self.0.push(segment.ident.to_string());
            syn::visit::visit_path_segment(self, segment);
        }
    }
    let mut names = Names(Vec::new());
    names.visit_expr(expression);
    names.0
}

#[test]
fn native_image_hardware_fault_admission_preserves_present_bit() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src");
    let service =
        syn::parse_file(&std::fs::read_to_string(root.join("service_sec_image.rs")).unwrap())
            .unwrap();
    struct Admissions(usize);
    impl<'a> Visit<'a> for Admissions {
        fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
            if call.method == "service_native_image_page_residency" {
                self.0 += 1;
                let observation = call.args.last().expect("fault observation argument");
                let syn::Expr::Call(decode) = observation else {
                    panic!("native image admission must preserve the hardware Present bit, not pass true");
                };
                let names = names_in_expression(&decode.func);
                assert!(
                    names.ends_with(&["ImageFaultObservation".into(), "from_x86_error".into(),]),
                    "hardware fault admission must decode the original x86 observation"
                );
                assert!(
                    matches!(decode.args.first(), Some(syn::Expr::Path(path))
                    if path.path.is_ident("m3")),
                    "decode the actual fault error word"
                );
                assert_eq!(decode.args.len(), 1);
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut admissions = Admissions(0);
    admissions.visit_file(&service);
    assert!(admissions.0 > 0, "inspect the real image fault admission");

    struct Signatures(usize);
    impl<'a> Visit<'a> for Signatures {
        fn visit_signature(&mut self, signature: &'a syn::Signature) {
            if matches!(
                signature.ident.to_string().as_str(),
                "service_native_image_page_residency" | "service_page_residency"
            ) {
                self.0 += 1;
                assert!(
                    signature.inputs.iter().any(|argument| matches!(argument,
                    syn::FnArg::Typed(argument) if matches!(&*argument.ty,
                        syn::Type::Path(path) if path.path.segments.last().unwrap().ident
                            == "ImageFaultObservation"))),
                    "the complete admission chain must retain typed fault observation"
                );
                assert!(
                    !signature.inputs.iter().any(|argument| matches!(argument,
                    syn::FnArg::Typed(argument) if matches!(&*argument.ty,
                        syn::Type::Path(path) if path.path.is_ident("bool")))),
                    "a bool collapses not-present and protection faults"
                );
            }
            syn::visit::visit_signature(self, signature);
        }
    }
    let adapter =
        syn::parse_file(&std::fs::read_to_string(root.join("exec_native_image_view.rs")).unwrap())
            .unwrap();
    let mut signatures = Signatures(0);
    signatures.visit_file(&adapter);
    signatures.visit_file(&source());
    assert_eq!(signatures.0, 3);
}

#[test]
fn delayed_not_present_image_fault_revalidates_resident_before_any_fill() {
    // NT5 mmfault.c and ReactOS ARM3/pagfault.c recheck the current mapping after
    // another thread may have resolved a queued fault. A resident row alone is
    // neither an access violation nor authority to acknowledge the fault.
    let file = source();
    let inner = function(&file, "service_page_residency");
    let (resident_index, resident) = inner
        .block
        .stmts
        .iter()
        .enumerate()
        .find_map(|(index, statement)| {
            let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else {
                return None;
            };
            let mut calls = Calls::default();
            calls.visit_block(&branch.then_branch);
            calls
                .0
                .iter()
                .any(|call| call == "is_resident")
                .then_some((index, branch))
        })
        .expect("find the actual resident lifetime validation branch");
    let mut sequence = Calls::default();
    sequence.visit_block(&resident.then_branch);
    assert!(sequence.0.iter().any(|call| call == "revalidate_resident_image_page"),
        "a queued nonpresent fault on a current shared/private image mapping needs checked revalidation");
    assert!(
        !sequence.0.iter().any(|call| matches!(
            call.as_str(),
            "ensure_source_page" | "install_view_page" | "map_private_page_from_frame"
        )),
        "resident retry must preserve the existing image bytes and ownership"
    );

    struct RetryReturn(bool);
    impl<'a> Visit<'a> for RetryReturn {
        fn visit_expr_if(&mut self, branch: &'a syn::ExprIf) {
            if names_in_expression(&branch.cond)
                .iter()
                .any(|name| name == "NotPresent")
            {
                self.0 |= branch.then_branch.stmts.iter().any(|statement| {
                    matches!(statement,
                    syn::Stmt::Expr(syn::Expr::Return(returned), _)
                    if returned.expr.as_ref().is_some_and(|expression| matches!(&**expression,
                        syn::Expr::Call(call) if matches!(&*call.func,
                            syn::Expr::Path(path) if path.path.segments.last().unwrap().ident
                                == "revalidate_resident_image_page"))))
                });
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let mut retry = RetryReturn(false);
    retry.visit_block(&resident.then_branch);
    assert!(
        retry.0,
        "propagate checked NotPresent revalidation; do not synthesize Ok from residency"
    );

    let fill_index = inner
        .block
        .stmts
        .iter()
        .position(|statement| {
            let mut calls = Calls::default();
            calls.visit_stmt(statement);
            calls.0.iter().any(|call| call == "ensure_source_page")
        })
        .expect("nonresident image faults retain source fill");
    assert!(resident_index < fill_index);
    let before_resident = &inner.block.stmts[..resident_index];
    let mut validation = Calls::default();
    for statement in before_resident {
        validation.visit_stmt(statement);
    }
    for required in [
        "current",
        "hosted_thread_memory_access",
        "process_committed_mapping_basic_information",
        "image_view_fault_access_status",
    ] {
        assert!(
            validation.0.iter().any(|call| call == required),
            "resident retry must retain {required} before mapping effects"
        );
    }
    assert!(!validation.0.iter().any(|call| call == "ensure_source_page"));
}

#[test]
fn resident_revalidation_cannot_refill_or_hide_real_protection_faults() {
    let file = source();
    let sequence = calls(&file, "revalidate_resident_image_page");
    assert!(
        !sequence.is_empty(),
        "resident revalidation must consult checked mapping ownership"
    );
    assert!(
        !sequence.iter().any(|call| matches!(
            call.as_str(),
            "ensure_source_page"
                | "install_view_page"
                | "map_private_page_from_frame"
                | "vm_map_private_page"
        )),
        "a duplicate fault must not recreate image contents"
    );
    let inner = function(&file, "service_page_residency");
    struct Protection(bool);
    impl<'a> Visit<'a> for Protection {
        fn visit_expr_if(&mut self, branch: &'a syn::ExprIf) {
            if names_in_expression(&branch.cond)
                .iter()
                .any(|name| name == "Protection")
            {
                let mut calls = Calls::default();
                calls.visit_block(&branch.then_branch);
                self.0 |= calls.0.iter().any(|call| call == "Err");
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let mut protection = Protection(false);
    protection.visit_block(&inner.block);
    assert!(
        protection.0,
        "resident shared non-COW protection faults must remain fail-closed, not retry-success"
    );
    assert!(
        calls(&file, "service_page_residency")
            .iter()
            .any(|call| call == "vm_reprotect_private_page"),
        "retain the existing checked private COW reprotection path"
    );
}

fn executive_source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn resident_backend_method<'a>(file: &'a syn::File, name: &str) -> &'a syn::ImplItemFn {
    file.items
        .iter()
        .find_map(|item| {
            let syn::Item::Impl(implementation) = item else {
                return None;
            };
            if !matches!(&*implementation.self_ty, syn::Type::Path(path)
            if path.path.segments.last().unwrap().ident == "ResidentIo")
            {
                return None;
            }
            implementation.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                _ => None,
            })
        })
        .unwrap_or_else(|| panic!("missing checked resident backend {name}"))
}

#[test]
fn resident_retry_uses_exact_ready_source_and_revalidates_current_owner() {
    let file = source();
    let ready = function(&file, "ready_source_frame");
    let sequence = calls(&file, "ready_source_frame");
    for required in [
        "find",
        "descriptor",
        "area",
        "filter",
        "ready_frame",
        "ok_or",
    ] {
        assert!(
            sequence.iter().any(|call| call == required),
            "resident retry must use a ready exact source: missing {required}"
        );
    }
    assert!(
        !sequence.iter().any(|call| matches!(
            call.as_str(),
            "advance" | "acquire" | "ensure_source_page" | "initialize"
        )),
        "checking retained source identity must not allocate or refill"
    );
    #[derive(Default)]
    struct SourceIdentity {
        area: bool,
        rva: bool,
        retiring: bool,
        revoked: bool,
    }
    impl<'a> Visit<'a> for SourceIdentity {
        fn visit_expr_struct(&mut self, expression: &'a syn::ExprStruct) {
            if expression.path.is_ident("SourceKey") {
                for field in &expression.fields {
                    if let syn::Member::Named(name) = &field.member {
                        self.area |= name == "area";
                        self.rva |= name == "rva";
                    }
                }
            }
            syn::visit::visit_expr_struct(self, expression);
        }
        fn visit_expr_unary(&mut self, expression: &'a syn::ExprUnary) {
            if matches!(expression.op, syn::UnOp::Not(_)) {
                if let syn::Expr::Field(field) = &*expression.expr {
                    if let syn::Member::Named(name) = &field.member {
                        self.retiring |= name == "retiring";
                        self.revoked |= name == "revoke_acked";
                    }
                }
            }
            syn::visit::visit_expr_unary(self, expression);
        }
    }
    let mut identity = SourceIdentity::default();
    identity.visit_block(&ready.block);
    assert!(
        identity.area && identity.rva && identity.retiring && identity.revoked,
        "source reuse must match area/RVA and exclude retiring or revoked cache entries"
    );

    let validation = resident_backend_method(&file, "validate_current");
    let mut sequence = Calls::default();
    sequence.visit_block(&validation.block);
    for required in [
        "current",
        "is_resident",
        "get",
        "process_committed_mapping_basic_information",
        "validate_owned_backing",
        "ready_source_frame",
    ] {
        assert!(
            sequence.0.iter().any(|call| call == required),
            "each mapping attempt must retain {required} authority validation"
        );
    }
    let retry = calls(&file, "revalidate_resident_image_page");
    assert!(
        retry.iter().any(|call| call == "advance"),
        "return the checked retained mapping operation's outcome, not a resident-row success"
    );
}

#[test]
fn resident_frame_identity_query_checks_reply_label_and_length() {
    let file = source();
    let mut sequence = Calls::default();
    sequence.visit_block(&resident_backend_method(&file, "frame_address").block);
    assert!(sequence
        .0
        .iter()
        .any(|call| call == "get_frame_paddr_checked"));
    assert!(
        !sequence.0.iter().any(|call| call == "get_frame_paddr"),
        "the diagnostic-only address query is not mapping identity authority"
    );
    let main = executive_source("main.rs");
    let query = function(&main, "get_frame_paddr_checked");
    fn number(expression: &syn::Expr, expected: u64) -> bool {
        matches!(expression, syn::Expr::Lit(literal)
            if matches!(&literal.lit, syn::Lit::Int(value)
                if value.base10_parse::<u64>().ok() == Some(expected)))
    }
    fn reply_test(expression: &syn::Expr, shift: bool, mask: u64, expected: u64) -> bool {
        let syn::Expr::Binary(comparison) = expression else {
            return false;
        };
        let syn::Expr::Binary(extraction) = &*comparison.left else {
            return false;
        };
        matches!(comparison.op, syn::BinOp::Ne(_))
            && (if shift {
                matches!(extraction.op, syn::BinOp::Shr(_))
            } else {
                matches!(extraction.op, syn::BinOp::BitAnd(_))
            })
            && matches!(&*extraction.left, syn::Expr::Path(path) if path.path.is_ident("reply"))
            && number(&extraction.right, mask)
            && number(&comparison.right, expected)
    }
    let checked = query.block.stmts.iter().any(|statement| {
        let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else {
            return false;
        };
        let syn::Expr::Binary(condition) = &*branch.cond else {
            return false;
        };
        let mut errors = Calls::default();
        errors.visit_block(&branch.then_branch);
        matches!(condition.op, syn::BinOp::Or(_))
            && reply_test(&condition.left, true, 12, 0)
            && reply_test(&condition.right, false, 0x7f, 1)
            && errors.0.iter().any(|call| call == "Err")
    });
    assert!(
        checked,
        "reject nonzero labels or non-one-word GetAddress replies before using MR0"
    );
}

#[test]
fn uncertain_resident_remap_fences_access_view_drain_and_source_purge() {
    let file = source();
    let available = calls(&file, "memory_available");
    for required in ["blocks_retirement", "descriptor", "checked_add"] {
        assert!(
            available.iter().any(|call| call == required),
            "uncertain remap range denial requires {required}"
        );
    }
    let runtime = executive_source("hosted_thread_runtime.rs");
    let retirement = function(&runtime, "hosted_thread_memory_retirement_access");
    fn mentions(statement: &syn::Stmt, name: &str) -> bool {
        struct Names<'a> {
            name: &'a str,
            found: bool,
        }
        impl<'ast> Visit<'ast> for Names<'_> {
            fn visit_path_segment(&mut self, segment: &'ast syn::PathSegment) {
                self.found |= segment.ident == self.name;
                syn::visit::visit_path_segment(self, segment);
            }
            fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
                if invocation.path.segments.last().is_some_and(|segment| {
                    segment.ident == "addr_of" || segment.ident == "addr_of_mut"
                }) {
                    let addressed: syn::Expr = syn::parse2(invocation.tokens.clone())
                        .expect("backing address macro must contain an actual expression");
                    self.found |= names_in_expression(&addressed)
                        .iter()
                        .any(|name| name == self.name);
                }
                syn::visit::visit_macro(self, invocation);
            }
        }
        let mut names = Names { name, found: false };
        names.visit_stmt(statement);
        names.found
    }
    let backing = retirement
        .block
        .stmts
        .iter()
        .position(|statement| mentions(statement, "HOSTED_THREAD_RUNTIME_WORK"))
        .expect("inspect the actual pending-thread backing table access");
    for owner in ["private_residency", "native_image_residency"] {
        let fence = retirement
            .block
            .stmts
            .iter()
            .enumerate()
            .find_map(|(index, statement)| {
                let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else {
                    return None;
                };
                let syn::Expr::Unary(denial) = &*branch.cond else {
                    return None;
                };
                let mut condition = Calls::default();
                condition.visit_expr(&denial.expr);
                if !matches!(denial.op, syn::UnOp::Not(_))
                    || !names_in_expression(&denial.expr)
                        .iter()
                        .any(|name| name == owner)
                    || !condition.0.iter().any(|call| call == "memory_available")
                {
                    return None;
                }
                let refuses = branch.then_branch.stmts.iter().any(|statement| {
                    let syn::Stmt::Expr(syn::Expr::Return(ret), _) = statement else {
                        return false;
                    };
                    let Some(expression) = &ret.expr else {
                        return false;
                    };
                    let mut refusal = Calls::default();
                    refusal.visit_expr(expression);
                    refusal.0.iter().any(|call| call == "Err")
                });
                assert!(
                    refuses,
                    "{owner} denial must return an error, not merely observe it"
                );
                Some(index)
            })
            .unwrap_or_else(|| panic!("cleanup access must deny pending {owner} remaps"));
        assert!(
            fence < backing,
            "{owner} must fence before pending-thread backing access"
        );
    }
    let ordinary = function(&runtime, "hosted_thread_memory_access");
    let delegated = ordinary
        .block
        .stmts
        .iter()
        .position(|statement| {
            let syn::Stmt::Expr(syn::Expr::Try(propagated), _) = statement else {
                return false;
            };
            names_in_expression(&propagated.expr)
                .iter()
                .any(|name| name == "hosted_thread_memory_retirement_access")
        })
        .expect("ordinary access must propagate both residency fences through cleanup admission");
    for storage in ["CLIENT_FRAME_REGISTRY", "PROCESS_PAGEFILE"] {
        let access = ordinary
            .block
            .stmts
            .iter()
            .position(|statement| mentions(statement, storage))
            .unwrap_or_else(|| panic!("inspect actual {storage} backing access"));
        assert!(
            delegated < access,
            "both residency fences must precede {storage} access"
        );
    }
    for (name, cleanup) in [
        ("drain_view", "advance"),
        ("purge_area", "begin_retirement"),
    ] {
        let sequence = calls(&file, name);
        let fence = sequence
            .iter()
            .position(|call| call == "blocks_retirement")
            .expect("retained remap must deny teardown");
        let cleanup = sequence.iter().position(|call| call == cleanup).unwrap();
        assert!(
            fence < cleanup,
            "{name} must fence before native owner cleanup"
        );
        let operation = function(&file, name);
        let first_guard = operation
            .block
            .stmts
            .iter()
            .find_map(|statement| match statement {
                syn::Stmt::Expr(syn::Expr::If(branch), _) => Some(branch),
                _ => None,
            })
            .unwrap();
        let mut guard = Calls::default();
        guard.visit_expr(&first_guard.cond);
        assert!(guard.0.iter().any(|call| call == "blocks_retirement"));
        let mut refusal = Calls::default();
        refusal.visit_block(&first_guard.then_branch);
        assert!(refusal.0.iter().any(|call| call == "Err"));
    }
}
