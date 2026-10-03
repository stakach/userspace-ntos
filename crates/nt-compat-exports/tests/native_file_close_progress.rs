use syn::visit::Visit;

fn calls(source: &str, module: &str, function: &str) -> bool {
    struct Find<'a> {
        module: &'a str,
        function: &'a str,
        found: bool,
    }
    impl<'ast> Visit<'ast> for Find<'_> {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                let segments: Vec<_> = path.path.segments.iter().collect();
                self.found |= segments.windows(2).any(|pair| {
                    pair[0].ident == self.module && pair[1].ident == self.function
                });
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut find = Find { module, function, found: false };
    find.visit_file(&syn::parse_file(source).expect("native source must parse"));
    find.found
}

#[test]
fn accepted_file_close_is_ready_inside_its_parked_parent_pump() {
    let pump = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");
    assert!(calls(pump, "hosted_routed_file_close_work", "nested_work_ready"),
        "a retained ZwClose cannot depend on the outer service loop while its parent dispatch is parked");
}

#[test]
fn retained_section_metadata_is_ready_inside_its_parked_parent_pump() {
    let pump = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");
    assert!(calls(pump, "provider_section_broker", "nested_work_ready"),
        "MmCreateSection metadata must progress while its native caller is parked");
}

#[test]
fn section_metadata_redrive_does_not_borrow_handler_across_provider_dispatch() {
    let parsed = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/provider_section_broker.rs"
    )).unwrap();
    let redrive = parsed.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == "redrive" => Some(item),
        _ => None,
    }).expect("Section metadata redrive boundary");
    let syn::FnArg::Typed(handler) = redrive.sig.inputs.first().unwrap() else {
        panic!("Section redrive requires explicit handler ownership");
    };
    assert!(matches!(&*handler.ty, syn::Type::Ptr(_)),
        "external metadata dispatch can reenter the executive; no exclusive handler borrow may span it");
}

#[test]
fn nested_file_work_runner_steps_retained_close_without_outer_loop() {
    let source = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let parsed = syn::parse_file(source).unwrap();
    let runner = parsed.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == "redrive_nested_hosted_file_work" => Some(item),
        _ => None,
    }).expect("nested retained File runner");
    // Restrict the check to the nested runner: the existing outer-loop call is insufficient.
    struct Find(bool);
    impl<'ast> Visit<'ast> for Find {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                let segments: Vec<_> = path.path.segments.iter().collect();
                self.0 |= segments.windows(2).any(|pair| {
                    pair[0].ident == "hosted_routed_file_close_work"
                        && pair[1].ident == "redrive_nested_ready"
                });
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut find = Find(false);
    find.visit_item_fn(runner);
    assert!(find.0, "accepted close work must progress before the parent invocation returns");
}

#[test]
fn borrowed_cleanup_bookkeeping_does_not_enter_hosted_drivers() {
    let parsed = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/service_sec_image.rs"
    )).unwrap();
    let cleanup = parsed.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == "start_file_cleanup" => Some(item),
        _ => None,
    }).expect("File cleanup bookkeeping boundary");
    struct Find(bool);
    impl<'ast> Visit<'ast> for Find {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                self.0 |= path.path.segments.iter().any(|segment| {
                    segment.ident == "pump_hosted_file_lifecycle"
                });
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut find = Find(false);
    find.visit_item_fn(cleanup);
    assert!(!find.0,
        "cleanup must queue ownership and finish handler bookkeeping before reentrant native driver dispatch");
}

#[test]
fn independent_file_lifecycle_remains_reachable_after_close_request_retirement() {
    let pump = include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");
    assert!(calls(pump, "driver_launch", "nested_hosted_file_lifecycle_work_ready"),
        "canonical cleanup/close ownership must remain schedulable without its original close request");

    let parsed = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/service_sec_image.rs"
    )).unwrap();
    let runner = parsed.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == "redrive_nested_hosted_file_work" => Some(item),
        _ => None,
    }).expect("nested retained File runner");
    struct Find(bool);
    impl<'ast> Visit<'ast> for Find {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                let segments: Vec<_> = path.path.segments.iter().collect();
                self.0 |= segments.windows(2).any(|pair| {
                    pair[0].ident == "driver_launch"
                        && pair[1].ident == "redrive_nested_hosted_file_lifecycle_work"
                });
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut find = Find(false);
    find.visit_item_fn(runner);
    assert!(find.0, "independent lifecycle work needs a held nested step, not only outer maintenance");

    let driver = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
    assert!(calls(driver, "hosted_file_lifecycle_owners", "nested_work_ready"));
    assert!(calls(driver, "hosted_file_lifecycle_owners", "nested_work_step"));
}
