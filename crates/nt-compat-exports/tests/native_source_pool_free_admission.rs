use syn::visit::Visit;

const LEDGER: &str =
    include_str!("../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const ROUTING: &str =
    include_str!("../../../components/ntos-executive/src/hosted_source_retirement.rs");

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::Block {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == name => Some(&*item.block),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing function {name}"))
}

#[derive(Default)]
struct Facts {
    calls: Vec<String>,
    methods: Vec<String>,
    paths: Vec<String>,
}

impl<'ast> Visit<'ast> for Facts {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(last) = path.path.segments.last() {
                self.calls.push(last.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.methods.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.paths
            .extend(path.path.segments.iter().map(|part| part.ident.to_string()));
        syn::visit::visit_expr_path(self, path);
    }
}

fn facts(body: &syn::Block) -> Facts {
    let mut result = Facts::default();
    result.visit_block(body);
    result
}

fn contains(items: &[String], name: &str) -> bool {
    items.iter().any(|item| item == name)
}

fn assert_admission(body: &syn::Block) {
    struct Admission {
        classified: bool,
        unregistered: bool,
        protected: bool,
        driver_owned: bool,
        in_unregistered: bool,
        driver_prepared: bool,
    }
    impl<'ast> Visit<'ast> for Admission {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "pool_free_admission" {
                assert_eq!(call.args.len(), 3);
                for (argument, expected) in
                    call.args
                        .iter()
                        .zip(["instance_index", "domain", "component_address"])
                {
                    assert!(
                        matches!(argument, syn::Expr::Path(path)
                        if path.path.is_ident(expected)),
                        "classify exact physical request"
                    );
                }
                self.classified = true;
            }
            if call.method == "prepare_driver_free" {
                self.driver_prepared = true;
            }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|part|
                    part.ident == "hosted_instance_pool_free_unlocked"))
            {
                assert!(
                    self.classified,
                    "classify every owner before any physical free effect"
                );
                assert!(
                    self.in_unregistered || self.driver_prepared,
                    "registered driver storage must pass its exact retirement protocol"
                );
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            struct PatternNames(Vec<String>);
            impl<'ast> Visit<'ast> for PatternNames {
                fn visit_path(&mut self, path: &'ast syn::Path) {
                    self.0
                        .extend(path.segments.iter().map(|part| part.ident.to_string()));
                    syn::visit::visit_path(self, path);
                }
            }
            let mut names = PatternNames(Vec::new());
            names.visit_pat(&arm.pat);
            if contains(&names.0, "SourcePoolFreeAdmission") {
                let mut branch = Facts::default();
                branch.visit_expr(&arm.body);
                if contains(&names.0, "Unregistered") {
                    assert!(
                        contains(&branch.calls, "hosted_instance_pool_free_unlocked"),
                        "ordinary pool frees require explicit Unregistered admission"
                    );
                    assert!(contains(
                        &branch.calls,
                        "hosted_instance_pool_allocation_is_free_unlocked"
                    ));
                    struct PoolOperation(bool);
                    impl<'ast> Visit<'ast> for PoolOperation {
                        fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
                            if matches!(binary.op, syn::BinOp::Eq(_))
                                && matches!(&*binary.left, syn::Expr::Path(path) if path.path.is_ident("op"))
                                && matches!(&*binary.right, syn::Expr::Lit(literal)
                                    if matches!(&literal.lit, syn::Lit::Int(integer)
                                        if matches!(integer.base10_parse::<u64>(), Ok(3))))
                            {
                                self.0 = true;
                            }
                            syn::visit::visit_expr_binary(self, binary);
                        }
                    }
                    let mut operation = PoolOperation(false);
                    operation.visit_expr(&arm.body);
                    assert!(operation.0, "ordinary pool free remains op3-only");
                    self.unregistered = true;
                }
                if contains(&names.0, "Protected") {
                    assert!(!contains(
                        &branch.calls,
                        "hosted_instance_pool_free_unlocked"
                    ));
                    assert!(!contains(&branch.methods, "prepare_driver_free"));
                    assert!(
                        !contains(&branch.paths, "STATUS_SUCCESS"),
                        "protected storage cannot be reported as a successful free"
                    );
                    self.protected = true;
                }
                if contains(&names.0, "DriverOwned") {
                    self.driver_owned = true;
                }
            }
            let before = self.in_unregistered;
            self.in_unregistered =
                contains(&names.0, "SourcePoolFreeAdmission") && contains(&names.0, "Unregistered");
            syn::visit::visit_arm(self, arm);
            self.in_unregistered = before;
        }
    }
    let all = facts(body);
    assert!(
        !contains(&all.methods, "allocation_for"),
        "absence of an owner-filtered HostedDriver row is not ordinary free authority"
    );
    assert!(contains(&all.methods, "prepare_driver_free"));
    assert!(
        contains(&all.methods, "retire"),
        "exact driver retirement still acknowledges teardown"
    );
    let mut admission = Admission {
        classified: false,
        unregistered: false,
        protected: false,
        driver_owned: false,
        in_unregistered: false,
        driver_prepared: false,
    };
    admission.visit_block(body);
    assert!(
        admission.classified,
        "native bridge must classify all physical owners"
    );
    assert!(admission.unregistered, "no implicit absent-driver fallback");
    assert!(
        admission.protected,
        "non-driver owners require explicit refusal"
    );
    assert!(
        admission.driver_owned,
        "only exact DriverOwned admission enters driver retirement"
    );
}

#[test]
fn native_pool_free_classifies_all_owners_before_generic_or_driver_free() {
    let source = syn::parse_file(LEDGER).unwrap();
    assert_admission(function(&source, "retire_allocation"));
}

#[test]
fn ordinary_and_irq_retirement_share_the_same_admission_bridge() {
    let ledger = syn::parse_file(LEDGER).unwrap();
    assert!(contains(
        &facts(function(&ledger, "service")).calls,
        "retire_allocation"
    ));
    let driver = syn::parse_file(DRIVER).unwrap();
    assert!(contains(
        &facts(function(&driver, "service_hosted_irq_lane_pool_retirement")).calls,
        "retire_allocation"
    ));
    let routing = syn::parse_file(ROUTING).unwrap();
    let route = facts(function(&routing, "retire"));
    assert!(contains(&route.calls, "hosted_irq_lane_service"));
    assert!(contains(&route.calls, "call_on4"));
    assert!(!contains(&route.calls, "pool_free"));
    assert!(!contains(
        &route.calls,
        "hosted_instance_pool_free_unlocked"
    ));
    for name in ["s_ex_free_pool", "s_io_free_irp"] {
        assert!(contains(&facts(function(&driver, name)).calls, "retire"));
    }
}

#[test]
fn caller_op7_and_op8_keep_separate_close_and_physical_acknowledgement() {
    let source = syn::parse_file(LEDGER).unwrap();
    struct CallerRetirement {
        found: bool,
    }
    impl<'ast> Visit<'ast> for CallerRetirement {
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            if matches!(&*branch.cond, syn::Expr::Binary(binary)
                if matches!(binary.op, syn::BinOp::Eq(_))
                && matches!(&*binary.left, syn::Expr::Path(path) if path.path.is_ident("op"))
                && matches!(&*binary.right, syn::Expr::Lit(literal)
                    if matches!(&literal.lit, syn::Lit::Int(integer)
                        if matches!(integer.base10_parse::<u64>(), Ok(7)))))
            {
                let begin = facts(&branch.then_branch);
                assert!(contains(&begin.methods, "begin_hosted_caller_retirement"));
                assert!(!contains(&begin.methods, "finish_hosted_caller_retirement"));
                let mut finish = Facts::default();
                finish.visit_expr(&branch.else_branch.as_ref().expect("op8 ack branch").1);
                assert!(contains(
                    &finish.calls,
                    "hosted_instance_pool_allocation_is_free_unlocked"
                ));
                assert!(contains(&finish.methods, "finish_hosted_caller_retirement"));
                assert!(contains(&finish.methods, "swap_remove"));
                assert!(!contains(
                    &begin.calls,
                    "hosted_instance_pool_free_unlocked"
                ));
                assert!(!contains(
                    &finish.calls,
                    "hosted_instance_pool_free_unlocked"
                ));
                self.found = true;
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let mut caller = CallerRetirement { found: false };
    caller.visit_block(function(&source, "service"));
    assert!(
        caller.found,
        "retain canonical caller retirement/acknowledgement protocol"
    );
}

#[test]
fn admission_scanner_rejects_absent_driver_fallback_and_protected_free() {
    let valid: syn::Block = syn::parse_quote!({
        let owner = match ledger().pool_free_admission(instance_index, domain, component_address) {
            Ok(SourcePoolFreeAdmission::Unregistered) => {
                return if op == 3
                    && hosted_instance_pool_allocation_is_free_unlocked(inst, component_address)
                        == Some(false)
                    && hosted_instance_pool_free_unlocked(inst, component_address)
                {
                    STATUS_SUCCESS
                } else {
                    STATUS_INVALID_HANDLE
                };
            }
            Ok(SourcePoolFreeAdmission::Protected(_)) => return STATUS_PENDING,
            Ok(SourcePoolFreeAdmission::DriverOwned(owner)) => owner,
            Err(_) => return STATUS_INVALID_HANDLE,
        };
        let ticket = ledger().prepare_driver_free(instance_index, domain, component_address);
        if hosted_instance_pool_free_unlocked(inst, component_address) {
            ledger().retire(ticket, owner);
        }
    });
    assert_admission(&valid);
    let absent_driver: syn::Block = syn::parse_quote!({
        let owner =
            ledger().allocation_for(HostedDriver(instance_index), domain, component_address);
        if owner.is_none() {
            hosted_instance_pool_free_unlocked(inst, component_address);
        }
        ledger().prepare_driver_free(instance_index, domain, component_address);
        ledger().retire(ticket, owner);
    });
    assert!(std::panic::catch_unwind(|| assert_admission(&absent_driver)).is_err());
    let mut protected_free = valid.clone();
    let syn::Stmt::Local(binding) = &mut protected_free.stmts[0] else {
        panic!("fixture binding")
    };
    let syn::Expr::Match(admission) = &mut *binding.init.as_mut().unwrap().expr else {
        panic!("fixture admission match")
    };
    let mut changed = false;
    for arm in &mut admission.arms {
        if matches!(&arm.pat, syn::Pat::TupleStruct(ok)
                if ok.path.is_ident("Ok") && matches!(ok.elems.first(),
                    Some(syn::Pat::TupleStruct(protected)) if protected.path.segments.last()
                        .is_some_and(|part| part.ident == "Protected")))
        {
            arm.body = Box::new(syn::parse_quote!({
                hosted_instance_pool_free_unlocked(inst, component_address);
                return STATUS_PENDING;
            }));
            changed = true;
        }
    }
    assert!(changed);
    assert!(std::panic::catch_unwind(|| assert_admission(&protected_free)).is_err());
}
