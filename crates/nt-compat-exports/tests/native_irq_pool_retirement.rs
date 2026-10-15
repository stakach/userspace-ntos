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

fn assert_string_free_retirement(body: &syn::Block, triplet: &str, offsets: [&str; 3]) {
    struct DescriptorGuard<'a> {
        triplet: &'a str,
        offsets: [&'a str; 3],
        found: bool,
    }
    impl<'ast> Visit<'ast> for DescriptorGuard<'_> {
        fn visit_expr_if(&mut self, value: &'ast syn::ExprIf) {
            let mut condition = Boundary::default();
            condition.visit_expr(&value.cond);
            if condition.calls.iter().any(|call| call == self.triplet) {
                assert!(matches!(&*value.cond, syn::Expr::Let(binding)
                    if matches!(&*binding.pat, syn::Pat::TupleStruct(tuple)
                        if tuple.path.is_ident("Some"))),
                    "invalid string descriptors must not reach retirement or clearing");
                assert!(value.else_branch.is_none());
                let mut retired = false;
                let mut cleared = Vec::new();
                let mut clearing_writes = 0;
                for statement in &value.then_branch.stmts {
                    if let syn::Stmt::Expr(syn::Expr::If(buffer), _) = statement {
                        assert!(matches!(&*buffer.cond, syn::Expr::Binary(binary)
                            if matches!(binary.op, syn::BinOp::Ne(_))
                            && matches!(&*binary.left, syn::Expr::Path(path) if path.path.is_ident("buf"))
                            && matches!(&*binary.right, syn::Expr::Lit(literal)
                                if matches!(&literal.lit, syn::Lit::Int(integer)
                                    if integer.base10_parse::<u64>().ok() == Some(0)))),
                            "null buffers must not be submitted for retirement");
                        assert!(buffer.else_branch.is_none());
                        let mut branch = Boundary::default();
                        branch.visit_block(&buffer.then_branch);
                        assert_eq!(branch.calls.len(), 1);
                        assert_eq!(branch.calls[0], "s_ex_free_pool");
                        assert!(branch.paths.iter().any(|path| path == "buf"));
                        retired = true;
                    } else {
                        let mut boundary = Boundary::default();
                        boundary.visit_stmt(statement);
                        if boundary.calls.iter().any(|call| call == "write_unaligned") {
                            clearing_writes += 1;
                            assert!(retired, "retire the buffer before clearing its descriptor");
                            assert!(matches!(statement, syn::Stmt::Expr(syn::Expr::Call(call), _)
                                if call.args.len() == 2
                                && matches!(call.args.iter().nth(1), Some(syn::Expr::Lit(literal))
                                    if matches!(&literal.lit, syn::Lit::Int(integer)
                                        if integer.base10_parse::<u64>().ok() == Some(0)))),
                                "clear descriptor fields to zero after retirement");
                            cleared.extend(boundary.paths.into_iter().filter(|path|
                                self.offsets.contains(&path.as_str())));
                        }
                    }
                }
                assert!(retired);
                assert_eq!(clearing_writes, 3, "clear exactly the three descriptor fields");
                for offset in self.offsets {
                    assert!(cleared.iter().any(|path| path == offset),
                        "preserve descriptor clearing for {offset}");
                }
                self.found = true;
            }
            syn::visit::visit_expr_if(self, value);
        }
    }
    let mut boundary = Boundary::default();
    boundary.visit_block(body);
    assert!(!boundary.calls.iter().any(|call| call == "pool_free"),
        "string free must not bypass retained allocation retirement");
    assert_eq!(boundary.calls.iter().filter(|call| *call == "s_ex_free_pool").count(), 1);
    let mut guard = DescriptorGuard { triplet, offsets, found: false };
    guard.visit_block(body);
    assert!(guard.found, "preserve the valid-triplet guard");
}

#[test]
fn string_free_exports_use_pool_retirement_before_clearing_valid_descriptors() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/driver_launch.rs"
    ))
    .unwrap();
    for (name, triplet, offsets) in [
        ("s_rtl_free_unicode_string", "unicode_string_triplet", [
            "UNICODE_STRING_LENGTH_OFFSET", "UNICODE_STRING_MAXIMUM_LENGTH_OFFSET",
            "UNICODE_STRING_BUFFER_OFFSET",
        ]),
        ("s_rtl_free_ansi_string", "ansi_string_triplet", [
            "ANSI_STRING_LENGTH_OFFSET", "ANSI_STRING_MAXIMUM_LENGTH_OFFSET",
            "ANSI_STRING_BUFFER_OFFSET",
        ]),
    ] {
        let body = function(&source, name);
        assert_string_free_retirement(body, triplet, offsets);
    }
}

#[test]
fn string_free_scanner_rejects_nonzero_reset_and_clearing_before_retirement() {
    let valid: syn::Block = syn::parse_quote!({
        unsafe {
            if let Some((_len, _max, buf)) = unicode_string_triplet(us) {
                if buf != 0 { s_ex_free_pool(buf); }
                write_unaligned((us + LENGTH) as *mut u16, 0);
                write_unaligned((us + MAXIMUM_LENGTH) as *mut u16, 0);
                write_unaligned((us + BUFFER) as *mut u64, 0);
            }
        }
    });
    let check = |body: &syn::Block| {
        assert_string_free_retirement(body, "unicode_string_triplet",
            ["LENGTH", "MAXIMUM_LENGTH", "BUFFER"]);
    };
    check(&valid);
    for reset_before_retirement in [false, true] {
        let mut invalid = valid.clone();
        let syn::Stmt::Expr(syn::Expr::Unsafe(outer), _) = &mut invalid.stmts[0]
            else { panic!("fixture unsafe block") };
        let syn::Stmt::Expr(syn::Expr::If(descriptor), _) = &mut outer.block.stmts[0]
            else { panic!("fixture triplet guard") };
        if reset_before_retirement {
            descriptor.then_branch.stmts.swap(0, 1);
        } else {
            let syn::Stmt::Expr(syn::Expr::Call(write), _) = &mut descriptor.then_branch.stmts[1]
                else { panic!("fixture reset") };
            *write.args.iter_mut().nth(1).unwrap() = syn::parse_quote!(1);
        }
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&invalid))).is_err(),
            "scanner must reject nonzero reset or retirement-order bypass");
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
