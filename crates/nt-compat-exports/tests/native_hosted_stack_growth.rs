use syn::visit::Visit;

fn named(path: &syn::Path, name: &str) -> bool {
    path.segments.last().is_some_and(|part| part.ident == name)
}

#[derive(Default)]
struct Effects(Vec<String>);
impl<'a> Visit<'a> for Effects {
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
    fn visit_macro(&mut self, value: &'a syn::Macro) {
        self.0
            .push(value.path.segments.last().unwrap().ident.to_string());
        syn::visit::visit_macro(self, value);
    }
}

fn source() -> syn::File {
    syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/service_sec_image.rs"
    ))
    .unwrap()
}

fn helper_source() -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/hosted_stack_growth.rs");
    let text = std::fs::read_to_string(path)
        .expect("dynamic stack growth needs its focused canonical publication helper");
    syn::parse_file(&text).unwrap()
}

fn growth_helper(file: &syn::File) -> &syn::ItemFn {
    file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "service_hosted_stack_growth" => Some(function),
        _ => None,
    }).expect("dynamic stack growth must own canonical VAD and commit publication in one focused helper")
}

fn position(effects: &Effects, name: &str) -> usize {
    effects
        .0
        .iter()
        .position(|effect| effect == name)
        .unwrap_or_else(|| panic!("actual stack growth is missing {name}"))
}

#[test]
fn dynamic_growth_prepares_canonical_commit_before_mapping_and_publishes_after_ack() {
    let file = helper_source();
    let helper = growth_helper(&file);
    let mut effects = Effects::default();
    effects.visit_block(&helper.block);
    let lifetime = position(&effects, "capture_process_identity");
    let commit = position(&effects, "prepare_guard_growth_into");
    let charge = position(&effects, "prepare_process_commit_charge");
    let mapping = position(&effects, "vm_map_private_page");
    let publication = position(&effects, "apply_exact");
    let charged = position(&effects, "commit_process_commit_charge");
    assert!(
        lifetime < mapping && commit < mapping,
        "exact identity and contiguous reserved-page commit must be prepared before effects"
    );
    assert!(position(&effects, "ensure_process_working_set_admission") < charge
        && position(&effects, "ensure_process_user_page_table") < charge
        && charge < mapping,
        "preflight PT/working-set accounting before reserving commitment, and reserve before map effects");
    assert!(
        mapping < publication && mapping < charged,
        "publish canonical metadata and charge only after acknowledged backing mapping"
    );
    let teb = position(&effects, "hosted_thread_teb_for_badge");
    assert!(
        teb < mapping,
        "authenticate the current thread's actual TEB before mapping effects"
    );
    assert!(
        position(&effects, "process_memory_read_status") < commit,
        "stack policy must capture TEB/PEB through canonical protection and residency admission"
    );
    assert!(
        publication < position(&effects, "process_memory_write_checked"),
        "publish acknowledged stack metadata before updating the exact TEB limit"
    );
}

#[test]
fn generic_fault_growth_requires_acknowledged_canonical_publication_before_reply() {
    let file = source();
    struct CallSite {
        found: bool,
    }
    impl<'a> Visit<'a> for CallSite {
        fn visit_expr_match(&mut self, expression: &'a syn::ExprMatch) {
            let mut effects = Effects::default();
            effects.visit_expr(&expression.expr);
            if effects
                .0
                .iter()
                .any(|effect| effect == "service_hosted_stack_growth")
            {
                for arm in &expression.arms {
                    let syn::Pat::TupleStruct(ok) = &arm.pat else {
                        continue;
                    };
                    if !named(&ok.path, "Ok") {
                        continue;
                    }
                    let grown = ok.elems.iter().any(|pattern| {
                        matches!(pattern,
                        syn::Pat::TupleStruct(value) if named(&value.path, "Some")
                            && value.elems.iter().any(|pattern| matches!(pattern,
                                syn::Pat::Path(path) if named(&path.path, "Grown"))))
                    });
                    let mut success = Effects::default();
                    success.visit_expr(&arm.body);
                    if grown {
                        assert!(
                            success
                                .0
                                .iter()
                                .any(|effect| effect == "component_reply_recv"),
                            "acknowledged growth must resume through its retained fault Reply"
                        );
                        self.found = true;
                    } else if ok.elems.iter().any(|pattern| {
                        matches!(pattern,
                        syn::Pat::TupleStruct(value) if named(&value.path, "Some"))
                    }) {
                        assert!(
                            !success
                                .0
                                .iter()
                                .any(|effect| effect == "component_reply_recv"),
                            "terminal stack overflow must not resume the faulting instruction"
                        );
                        assert!(
                            success.0.iter().any(|effect| effect == "park_and_log"),
                            "non-grown stack outcomes must preserve the parked fault owner"
                        );
                    }
                }
            }
            syn::visit::visit_expr_match(self, expression);
        }
    }
    let mut site = CallSite { found: false };
    site.visit_file(&file);
    assert!(
        site.found,
        "the real hosted fault loop must invoke canonical growth before resuming the client"
    );
}
