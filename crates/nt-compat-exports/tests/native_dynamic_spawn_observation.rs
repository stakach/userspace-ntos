use syn::visit::Visit;

const SERVICE: &str = include_str!(
    "../../../components/ntos-executive/src/service_sec_image.rs"
);
const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");
const RUNTIME: &str = include_str!(
    "../../../components/ntos-executive/src/hosted_process_runtime.rs"
);

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == name => Some(function),
        _ => None,
    }).unwrap_or_else(|| panic!("missing actual native function {name}"))
}

#[derive(Default)]
struct Audit {
    calls: Vec<String>,
    methods: Vec<String>,
    paths: Vec<String>,
    generation_comparisons: usize,
    running: bool,
    spawn_ack: bool,
}

impl<'ast> Visit<'ast> for Audit {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(name) = path.path.segments.last() {
                self.calls.push(name.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.methods.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        if let Some(name) = path.segments.last() {
            self.running |= name.ident == "Running";
            self.paths.push(name.ident.to_string());
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        if matches!(binary.op, syn::BinOp::Eq(_) | syn::BinOp::Ne(_)) {
            let generation = |expression: &syn::Expr| matches!(expression,
                syn::Expr::Field(field) if matches!(&field.member,
                    syn::Member::Named(name) if name == "generation"));
            if generation(&binary.left) && generation(&binary.right) {
                self.generation_comparisons += 1;
            }
            let acknowledged = |left: &syn::Expr, right: &syn::Expr| {
                matches!(left, syn::Expr::MethodCall(call) if call.method == "load")
                    && matches!(right, syn::Expr::Lit(literal)
                        if matches!(&literal.lit, syn::Lit::Int(value)
                            if value.base10_parse::<u64>().ok() == Some(1)))
            };
            self.spawn_ack |= acknowledged(&binary.left, &binary.right)
                || acknowledged(&binary.right, &binary.left);
        }
        syn::visit::visit_expr_binary(self, binary);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        use syn::parse::Parser;
        let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
        if let Ok(expressions) = parser.parse2(mac.tokens.clone()) {
            let mut nested = Audit::default();
            for expression in &expressions {
                nested.visit_expr(expression);
            }
            self.calls.extend(nested.calls);
            self.methods.extend(nested.methods);
            self.paths.extend(nested.paths);
            self.generation_comparisons += nested.generation_comparisons;
            self.running |= nested.running;
            self.spawn_ack |= nested.spawn_ack;
        }
    }
}

fn audit(function: &syn::ItemFn) -> Audit {
    let mut audit = Audit::default();
    audit.visit_block(&function.block);
    audit
}

#[test]
fn observational_lookup_requires_exact_live_catalog_runtime_and_process() {
    let file = syn::parse_file(SERVICE).unwrap();
    let observed = audit(function(&file, "live_hosted_pi_for_observation_role"));
    assert!(observed.methods.iter().any(|name| name == "hosted_process_image"));
    assert!(observed.methods.iter().any(|name| name == "observation_role"));
    assert!(observed.calls.iter().any(|name| name == "hosted_process_runtime_for_pi"));
    assert!(observed.generation_comparisons != 0,
        "a reused PI must not substitute another catalog/runtime incarnation");
    assert!(observed.methods.iter().any(|name| name == "capture_process_identity"),
        "resolve the current canonical process mechanism, not merely a numeric PID");
    assert!(observed.methods.iter().any(|name| name == "process") && observed.running,
        "a retired/static process registration is not a live observational instance");
    assert!(observed.spawn_ack,
        "catalog registration alone is not acknowledged process construction");
    assert!(!observed.methods.iter().any(|name| name == "hosted_process_role"));
}

#[test]
fn observational_lookup_rejects_each_identity_mismatch_and_ambiguous_live_matches() {
    fn field(expression: &syn::Expr) -> Option<(String, String)> {
        let syn::Expr::Field(value) = expression else { return None; };
        let syn::Expr::Path(owner) = &*value.base else { return None; };
        let syn::Member::Named(member) = &value.member else { return None; };
        Some((owner.path.get_ident()?.to_string(), member.to_string()))
    }
    #[derive(Default)]
    struct Guards {
        mismatches: Vec<((String, String), (String, String))>,
        hosted_generation: bool,
        ambiguous: bool,
    }
    impl<'ast> Visit<'ast> for Guards {
        fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
            if matches!(binary.op, syn::BinOp::Ne(_)) {
                if let (Some(left), Some(right)) = (field(&binary.left), field(&binary.right)) {
                    self.mismatches.push((left, right));
                }
                self.hosted_generation |= field(&binary.left)
                    == Some(("identity".into(), "generation".into()))
                    && matches!(&*binary.right, syn::Expr::Call(call)
                        if matches!(&*call.func, syn::Expr::Path(path)
                            if path.path.segments.last().unwrap().ident == "Hosted")
                        && call.args.first().and_then(field)
                            == Some(("image".into(), "generation".into())));
            }
            syn::visit::visit_expr_binary(self, binary);
        }
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            if matches!(&*branch.cond, syn::Expr::MethodCall(call)
                if call.method == "is_some"
                    && matches!(&*call.receiver, syn::Expr::Path(path)
                        if path.path.is_ident("selected"))) {
                struct NoneReturn(bool);
                impl<'ast> Visit<'ast> for NoneReturn {
                    fn visit_expr_return(&mut self, returned: &'ast syn::ExprReturn) {
                        self.0 |= returned.expr.as_deref().is_some_and(|expression|
                            matches!(expression, syn::Expr::Path(path) if path.path.is_ident("None")));
                    }
                }
                let mut returned = NoneReturn(false);
                returned.visit_block(&branch.then_branch);
                self.ambiguous |= returned.0;
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let file = syn::parse_file(SERVICE).unwrap();
    let mut guards = Guards::default();
    guards.visit_block(&function(&file, "live_hosted_pi_for_observation_role").block);
    for (left, right) in [
        (("runtime", "generation"), ("image", "generation")),
        (("mechanism", "generation"), ("image", "generation")),
        (("mechanism", "top_badge"), ("image", "top_badge")),
        (("identity", "pid"), ("mechanism", "pid")),
    ] {
        let pair = ((left.0.into(), left.1.into()), (right.0.into(), right.1.into()));
        assert!(guards.mismatches.contains(&pair), "missing exact mismatch rejection {pair:?}");
    }
    assert!(guards.hosted_generation && guards.ambiguous,
        "a stale canonical generation or multiple live matches cannot identify an observed owner");
}

#[test]
fn final_spawn_gates_observe_dynamic_instances_not_fixed_pi_atomics() {
    let file = syn::parse_file(MAIN).unwrap();
    struct Gates(Vec<(Vec<u8>, Audit)>);
    impl<'ast> Visit<'ast> for Gates {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("check")) {
                if let Some(syn::Expr::Lit(syn::ExprLit {
                    lit: syn::Lit::ByteStr(label), ..
                })) = call.args.first() {
                    let label = label.value();
                    if [b"exec_winlogon_spawned".as_slice(), b"exec_services_spawned",
                        b"exec_lsass_spawned"].contains(&label.as_slice()) {
                        let mut audit = Audit::default();
                        let condition = call.args.iter().nth(1).expect("gate condition");
                        if !matches!(condition, syn::Expr::Lit(syn::ExprLit {
                            lit: syn::Lit::Bool(value), ..
                        }) if !value.value) {
                            audit.visit_expr(condition);
                            self.0.push((label, audit));
                        }
                    }
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut gates = Gates(Vec::new());
    gates.visit_file(&file);
    assert!(gates.0.len() >= 3);
    for (label, audit) in gates.0 {
        assert!(audit.calls.iter().any(|name| name == "live_hosted_pi_for_observation_role"),
            "{} must resolve an exact dynamic observed process", String::from_utf8_lossy(&label));
        assert!(!audit.paths.iter().any(|name|
            ["WINLOGON_SPAWNED", "SERVICES_SPAWNED", "LSASS_SPAWNED"].contains(&name.as_str())));
    }
}

#[test]
fn diagnostic_frontiers_use_observational_lookup_without_changing_operational_roles() {
    let file = syn::parse_file(SERVICE).unwrap();
    for name in ["dump_interactive_logon_quiesce", "dump_services_start_quiesce",
        "pre_user_shell_frontier_pending", "progress_stall_deferral_snapshot"] {
        let observed = audit(function(&file, name));
        assert!(observed.calls.iter().any(|name| name == "live_hosted_pi_for_observation_role"),
            "{name} must not select a static unspawned role registration");
        assert!(!observed.paths.iter().any(|name|
            ["WINLOGON_SPAWNED", "SERVICES_SPAWNED", "LSASS_SPAWNED"].contains(&name.as_str())),
            "{name} must not depend on legacy fixed-PI spawn observations");
    }
    let operational = audit(function(&file, "hosted_pi_for_role"));
    assert!(operational.methods.iter().any(|name| name == "hosted_process_role"));
    assert!(!operational.methods.iter().any(|name| name == "observation_role"));
    let runtime = syn::parse_file(RUNTIME).unwrap();
    let binding = audit(function(&runtime, "runtime_for_image"));
    assert!(binding.calls.iter().any(|name| name == "spawned_signal_for_pi"),
        "operational unspawned admission must retain its exact per-instance signal");
}
