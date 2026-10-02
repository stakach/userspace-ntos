use syn::visit::Visit;

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::Block {
    for item in &file.items {
        match item {
            syn::Item::Fn(item) if item.sig.ident == name => return &item.block,
            syn::Item::Impl(item) => {
                for item in &item.items {
                    if let syn::ImplItem::Fn(item) = item {
                        if item.sig.ident == name {
                            return &item.block;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    panic!("missing native function {name}");
}

#[derive(Default)]
struct Boundary {
    calls: Vec<String>,
    methods: Vec<String>,
    fields: Vec<String>,
    paths: Vec<String>,
    returns: usize,
}

impl<'ast> Visit<'ast> for Boundary {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.methods.push(call.method.to_string());
        if call.method == "pool_retirement_arguments" {
            assert_eq!(call.args.len(), 4);
            assert!(matches!(call.args.first(), Some(syn::Expr::Field(field))
                if matches!(&field.member, syn::Member::Named(name) if name == "identity")));
            assert!(
                matches!(call.args.last(), Some(syn::Expr::Path(path))
                if path.path.is_ident("current_irql")),
                "retirement policy must receive actual arena IRQL, not a substituted constant"
            );
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member {
            self.fields.push(name.to_string());
        }
        syn::visit::visit_expr_field(self, field);
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
        self.paths.extend(
            path.path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string()),
        );
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_return(&mut self, value: &'ast syn::ExprReturn) {
        self.returns += 1;
        syn::visit::visit_expr_return(self, value);
    }
}

#[test]
fn pool_and_irp_free_exports_use_common_retirement_with_exact_operations() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/driver_launch.rs"
    ))
    .unwrap();
    struct RetirementCall {
        operation: u64,
        found: bool,
    }
    impl<'ast> Visit<'ast> for RetirementCall {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                let names: Vec<_> = path
                    .path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect();
                if names.ends_with(&["hosted_source_retirement".into(), "retire".into()]) {
                    assert_eq!(call.args.len(), 2);
                    assert!(
                        matches!(call.args.first(), Some(syn::Expr::Lit(literal))
                        if matches!(&literal.lit, syn::Lit::Int(value)
                            if value.base10_parse::<u64>().ok() == Some(self.operation))),
                        "retirement export must preserve its exact free operation"
                    );
                    self.found = true;
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    for (name, operation) in [("s_ex_free_pool", 3), ("s_io_free_irp", 2)] {
        let body = function(&source, name);
        let mut call = RetirementCall {
            operation,
            found: false,
        };
        call.visit_block(body);
        assert!(
            call.found,
            "{name} must route through common exact IRQ-aware retirement"
        );
        let mut boundary = Boundary::default();
        boundary.visit_block(body);
        assert!(
            !boundary
                .calls
                .iter()
                .any(|call| matches!(call.as_str(), "call_on4" | "call_on4_raw")),
            "{name} must not bypass common IRQ retirement with legacy IPC"
        );
    }
}

#[test]
fn irq_pool_retirement_routes_exact_lane_before_legacy_ipc() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/hosted_source_retirement.rs");
    let source = std::fs::read_to_string(path)
        .expect("IRQ-aware common source retirement module is required");
    let source = syn::parse_file(&source).unwrap();
    let body = function(&source, "retire");
    #[derive(Default)]
    struct IrqBranch {
        found: bool,
    }
    impl<'ast> Visit<'ast> for IrqBranch {
        fn visit_expr_if(&mut self, value: &'ast syn::ExprIf) {
            let mut condition = Boundary::default();
            condition.visit_expr(&value.cond);
            if condition
                .calls
                .iter()
                .any(|call| call == "hosted_irq_lane_context")
            {
                let mut branch = Boundary::default();
                branch.visit_block(&value.then_branch);
                assert!(
                    branch
                        .calls
                        .iter()
                        .any(|call| call == "hosted_irq_lane_service"),
                    "IRQ ExFreePool must submit an exact retained lane service"
                );
                assert!(
                    branch.paths.iter().any(|path| path == "PoolRetirement"),
                    "pool retirement needs its own IRQ service kind"
                );
                assert!(
                    !branch
                        .calls
                        .iter()
                        .any(|call| matches!(call.as_str(), "call_on4" | "call_on4_raw")),
                    "IRQ pool retirement cannot enter the legacy FSD lifetime exchange"
                );
                assert!(
                    branch.returns > 0,
                    "IRQ retirement must return before legacy IPC"
                );
                self.found = true;
            }
            syn::visit::visit_expr_if(self, value);
        }
    }
    let mut branch = IrqBranch::default();
    for statement in &body.stmts {
        let mut boundary = Boundary::default();
        boundary.visit_stmt(statement);
        if boundary
            .calls
            .iter()
            .any(|call| matches!(call.as_str(), "call_on4" | "call_on4_raw"))
        {
            assert!(
                branch.found,
                "IRQ authority must be checked before any legacy pool-free IPC"
            );
        }
        branch.visit_stmt(statement);
    }
    assert!(
        branch.found,
        "ExFreePool must route its exact IRQ lane before legacy IPC"
    );
}

#[test]
fn irq_broker_dispatches_distinct_pool_retirement() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/hosted_irq_broker.rs"
    ))
    .unwrap();
    let body = function(&source, "execute_service");
    #[derive(Default)]
    struct RetirementArm {
        found: bool,
    }
    impl<'ast> Visit<'ast> for RetirementArm {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if let syn::Pat::Path(path) = &arm.pat {
                if path
                    .path
                    .segments
                    .last()
                    .is_some_and(|segment| segment.ident == "PoolRetirement")
                {
                    self.found = true;
                    assert!(
                        !matches!(&*arm.body, syn::Expr::Tuple(tuple) if tuple.elems.is_empty()),
                        "pool retirement must execute a real broker operation"
                    );
                }
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut arms = RetirementArm::default();
    arms.visit_block(body);
    assert!(
        arms.found,
        "IRQ broker must handle PoolRetirement independently of other services"
    );
}

#[test]
fn narrow_irq_exchange_does_not_admit_legacy_source_irp_services() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/spawn_hosts.rs"
    ))
    .unwrap();
    let mut boundary = Boundary::default();
    boundary.visit_block(function(&source, "component_hosted_irq_exchange"));
    assert!(!boundary
        .paths
        .iter()
        .any(|path| path == "FSD_SERVICE_SOURCE_IRP_LABEL"));
    assert!(
        !boundary
            .calls
            .iter()
            .any(|call| call == "service_hosted_source_irp_lifetime"),
        "IRQ exchange must retain its token protocol, not widen to the ordinary FSD pump"
    );
}

#[test]
fn irq_pool_broker_validates_lane_grant_and_actual_irql_before_effects() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/hosted_irq_broker.rs"
    ))
    .unwrap();
    let body = function(&source, "pool_retirement_service");
    let mut before = Boundary::default();
    let mut effect = false;
    for statement in &body.stmts {
        let mut current = Boundary::default();
        current.visit_stmt(statement);
        if current
            .calls
            .iter()
            .any(|call| call == "service_hosted_irq_lane_pool_retirement")
        {
            assert!(
                before.methods.iter().any(|method| method == "lane"),
                "retirement must resolve its exact retained lane"
            );
            assert!(
                before
                    .calls
                    .iter()
                    .any(|call| call == "lane_has_service_grant")
                    && before.fields.iter().any(|field| field == "dpc_grant"),
                "retirement must authenticate the exact connection or retained DPC grant"
            );
            assert!(
                before.methods.iter().any(|method| method == "current_irql")
                    && before.fields.iter().any(|field| field == "control")
                    && before.fields.iter().any(|field| field == "identity"),
                "IRQL must come from the retained lane's actual arena control"
            );
            assert!(before.methods.iter().any(|method| method == "pool_retirement_arguments"),
                "shared policy must validate exact identity, service, arguments and IRQL before effects");
            assert!(
                current
                    .fields
                    .iter()
                    .any(|field| field == "projection_instance")
                    && current.fields.iter().any(|field| field == "domain_id")
                    && current.fields.iter().any(|field| field == "domain_cookie"),
                "retirement engine must receive the authenticated lane's exact domain"
            );
            effect = true;
        }
        before.visit_stmt(statement);
    }
    assert!(
        effect,
        "IRQ pool retirement must call the shared exact retirement engine"
    );
}
