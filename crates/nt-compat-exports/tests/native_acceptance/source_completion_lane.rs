use syn::{visit::Visit, Expr, Item};

fn lane_source() -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/hosted_source_completion_lane.rs");
    let source = std::fs::read_to_string(path)
        .expect("pending source completion needs its own retained ordinary execution lane");
    syn::parse_file(&source).unwrap()
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn fields(source: &syn::File, name: &str) -> Vec<(String, String)> {
    let record = source
        .items
        .iter()
        .find_map(|item| match item {
            Item::Struct(record) if record.ident == name => Some(record),
            _ => None,
        })
        .expect("typed completion execution receipt");
    record
        .fields
        .iter()
        .filter_map(|field| {
            let syn::Type::Path(ty) = &field.ty else {
                return None;
            };
            Some((
                field.ident.as_ref().unwrap().to_string(),
                ty.path.segments.last().unwrap().ident.to_string(),
            ))
        })
        .collect()
}

#[test]
fn source_completion_uses_independent_initialized_domain_lane() {
    let source = lane_source();
    let mut calls = Calls::default();
    calls.visit_file(&source);
    assert!(
        calls
            .0
            .iter()
            .any(|call| call == "component_dispatch_loop_with_ready"),
        "secondary lane must enter the initialized persistent loop without rerunning DriverEntry"
    );
    assert!(
        calls.0.iter().any(|call| call == "enroll_completion"),
        "completion execution must have its own canonical worker/physical ingress receipt"
    );
    if calls
        .0
        .iter()
        .any(|call| call == "spawn_hosted_driver_worker_thread")
    {
        let driver = syn::parse_file(include_str!(
            "../../../../components/ntos-executive/src/driver_launch.rs"
        ))
        .unwrap();
        let worker = driver
            .items
            .iter()
            .find_map(|item| match item {
                Item::Fn(function) if function.sig.ident == "spawn_hosted_driver_worker_thread" => {
                    Some(function)
                }
                _ => None,
            })
            .unwrap();
        let mut worker_calls = Calls::default();
        worker_calls.visit_item_fn(worker);
        assert!(worker_calls.0.iter().any(|call| call == "initialize_actor"));
    } else {
        assert!(
            calls.0.iter().any(|call| call == "initialize_actor"),
            "completion callbacks require a retained canonical kernel execution thread"
        );
    }
    assert!(!calls.0.iter().any(|call| call == "primary_route" || call == "enroll_interrupt"
        || call == "component_main"),
        "a source primary can itself wait for completion; neither it nor the IRQ lane is an ordinary completion worker");
    let lane = fields(&source, "SourceCompletionLane");
    for (name, ty) in [("domain", "HostedDomainIdentity"), ("pml4", "u64")] {
        assert!(
            lane.iter().any(|field| field.0 == name && field.1 == ty),
            "completion lane retains exact {name}, not a driver ordinal alone"
        );
    }
}

#[test]
fn completion_command_retains_source_identity_without_second_terminal_owner() {
    let source = lane_source();
    let command = fields(&source, "SourceCompletionCommand");
    for (name, ty) in [
        ("ticket", "SourceIrpTicket"),
        ("allocation", "SourceIrpAllocation"),
        ("token", "u64"),
    ] {
        assert!(
            command.iter().any(|field| field.0 == name && field.1 == ty),
            "completion command must bind exact {name} before native execution"
        );
    }
    let execute = source
        .items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "execute" => Some(function),
            _ => None,
        })
        .expect("fixed source-local completion entry");
    let mut calls = Calls::default();
    calls.visit_item_fn(execute);
    assert_eq!(
        calls
            .0
            .iter()
            .filter(|call| *call == "complete_hosted_irp")
            .count(),
        1,
        "the existing native unwinder remains the sole completion routine engine"
    );
    for forbidden in [
        "call_hosted_pe",
        "run_irp",
        "dispatch_irp_for_instance_exact",
    ] {
        assert!(
            !calls.0.iter().any(|call| call == forbidden),
            "a completion command cannot become arbitrary driver dispatch: {forbidden}"
        );
    }
    let lane = fields(&source, "SourceCompletionLane");
    for forbidden in [
        "SourceLease",
        "ReadSourceLease",
        "RetainedReadForward",
        "RetainedFlushForward",
        "RetainedQueryInformationForward",
    ] {
        assert!(
            !lane.iter().any(|field| field.1 == forbidden),
            "Work retains the source/terminal owner; the lane owns execution only"
        );
    }
}
