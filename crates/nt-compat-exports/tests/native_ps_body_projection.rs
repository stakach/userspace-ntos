use std::path::PathBuf;
use syn::{visit::Visit, Expr, Item, ItemFn, Pat};

fn source(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).expect("native Ps projection boundary")).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing native function {name}"))
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0.push(
                path.path
                    .segments
                    .iter()
                    .map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>()
                    .join("::"),
            );
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[derive(Default)]
struct DispatchProjection {
    dispatches: usize,
    projected: usize,
}
impl<'ast> Visit<'ast> for DispatchProjection {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if matches!(&*call.func, Expr::Path(path)
            if path.path.segments.iter().map(|segment| segment.ident.to_string()).collect::<Vec<_>>()
                .ends_with(&["provider_ps".into(), "dispatch".into()]))
        {
            self.dispatches += 1;
            if let Some(Expr::Closure(projection)) = call.args.last() {
                let mut calls = Calls::default();
                calls.visit_expr(&projection.body);
                if calls
                    .0
                    .iter()
                    .any(|name| name.ends_with("provider_ps_projection::grant"))
                {
                    self.projected += 1;
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn logical_ps_requests_project_referenced_bodies_before_pointer_publication() {
    let file = source("service_sec_image.rs");
    let mut evidence = DispatchProjection::default();
    evidence.visit_block(&function(&file, "service_win32k_ps_request").block);
    assert!(evidence.dispatches != 0);
    assert_eq!(
        evidence.projected, evidence.dispatches,
        "each canonical Ps result must pass exact physical-provider projection acknowledgement"
    );
}

#[test]
fn kernel_ps_requests_share_the_same_canonical_projection_contract() {
    let file = source("kernel_provider_activation.rs");
    let mut evidence = DispatchProjection::default();
    evidence.visit_block(&function(&file, "service_ps").block);
    assert!(evidence.dispatches != 0);
    assert_eq!(
        evidence.projected, evidence.dispatches,
        "kernel activation must not publish a referenced but unmapped Ps body"
    );
}

#[test]
fn referenced_body_policy_projects_lookup_and_retain_and_rolls_back_rejected_reference() {
    let file = source("provider_ps.rs");
    let dispatch = function(&file, "dispatch");
    let project_reference = function(&file, "project_reference");
    let callback = project_reference
        .sig
        .inputs
        .iter()
        .last()
        .and_then(|argument| match argument {
            syn::FnArg::Typed(argument) => match &*argument.pat {
                Pat::Ident(name) => Some(name.ident.to_string()),
                _ => None,
            },
            _ => None,
        })
        .expect("dispatch projection callback");
    let mut helper_calls = Calls::default();
    helper_calls.visit_block(&project_reference.block);
    assert!(
        helper_calls.0.iter().any(|call| call == &callback),
        "shared reference policy acknowledges projection"
    );
    assert!(
        helper_calls
            .0
            .iter()
            .any(|call| call == "release_kernel_object_pointer"),
        "shared reference policy rolls back rejected reference"
    );
    struct Arms {
        validated: Vec<String>,
    }
    impl<'ast> Visit<'ast> for Arms {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            let name = match &arm.pat {
                Pat::Path(path) => Some(path.path.segments.last().unwrap().ident.to_string()),
                Pat::Ident(pattern) => Some(pattern.ident.to_string()),
                _ => None,
            };
            if let Some(name) = name {
                if [
                    "W32_PS_OP_LOOKUP_PROCESS",
                    "W32_PS_OP_LOOKUP_THREAD",
                    "W32_PS_OP_RETAIN_POINTER",
                ]
                .contains(&name.as_str())
                {
                    let mut calls = Calls::default();
                    calls.visit_expr(&arm.body);
                    assert!(calls.0.iter().any(|call| call == "project_reference"),
                        "{name} must use acknowledged projection and rollback before publishing authority");
                    self.validated.push(name);
                }
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut evidence = Arms {
        validated: Vec::new(),
    };
    evidence.visit_block(&dispatch.block);
    assert_eq!(
        evidence.validated.len(),
        3,
        "all referenced-body operations share projection admission"
    );
}

// Compile and execute the actual executive policy; only transport constants/yield are shimmed.
mod win32k_subsystem {
    pub const W32_PS_OP_QUERY_PROCESS: u64 = 1;
    pub const W32_PS_OP_QUERY_THREAD: u64 = 2;
    pub const W32_PS_OP_SET_THREAD_PRIORITY: u64 = 3;
    pub const W32_PS_OP_LOOKUP_PROCESS: u64 = 4;
    pub const W32_PS_OP_LOOKUP_THREAD: u64 = 5;
    pub const W32_PS_OP_RETAIN_POINTER: u64 = 6;
    pub const W32_PS_OP_RELEASE_POINTER: u64 = 7;
    pub const W32_PS_OP_YIELD_EXECUTION: u64 = 8;
}
mod sel4_rt {
    pub fn yield_now() {}
}
#[path = "../../../components/ntos-executive/src/provider_ps.rs"]
mod provider_ps;

fn fixture() -> (nt_process::ProcessManager, u32, u32, u32) {
    let mut pm = nt_process::ProcessManager::new();
    let caller_pid = pm.create_process("caller", None, None);
    let caller_tid = pm.create_thread(caller_pid, 0, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(caller_pid, 0x1000));
    assert!(pm.publish_thread_kernel_object(caller_tid, 0x2000));
    let other_pid = pm.create_process("other", None, None);
    let other_tid = pm.create_thread(other_pid, 0, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(other_pid, 0x3000));
    assert!(pm.publish_thread_kernel_object(other_tid, 0x4000));
    (pm, caller_tid, other_pid, other_tid)
}

fn process_references(pm: &nt_process::ProcessManager, pid: u32) -> u32 {
    pm.process_object_delete_blockers(pid)
        .unwrap()
        .process_kernel_pointer_references
}

fn thread_references(pm: &nt_process::ProcessManager, tid: u32) -> u32 {
    // Each fixture process owns exactly one thread, making the public aggregate exact.
    let pid = pm.thread(tid).unwrap().process_id;
    pm.process_object_delete_blockers(pid)
        .unwrap()
        .thread_kernel_pointer_references
}

#[test]
fn actual_cross_thread_lookup_acknowledges_exact_body_with_acquired_reference() {
    let (mut pm, caller_tid, _, other_tid) = fixture();
    assert_ne!(caller_tid, other_tid);
    let before = thread_references(&pm, other_tid);
    let mut observed = None;
    let result = provider_ps::dispatch(
        &mut pm,
        win32k_subsystem::W32_PS_OP_LOOKUP_THREAD,
        u64::from(other_tid),
        0,
        |pm, body| {
            observed = Some(body);
            assert_eq!(thread_references(pm, other_tid), before + 1);
            Ok(())
        },
    );
    assert_eq!(observed, Some(0x4000));
    assert_eq!(result, (0, 0x4000, u64::from(before + 1), 0));
}

#[test]
fn actual_process_lookup_acknowledges_projection_before_publication() {
    let (mut pm, _, pid, _) = fixture();
    let before = process_references(&pm, pid);
    let mut observed = None;
    let result = provider_ps::dispatch(
        &mut pm,
        win32k_subsystem::W32_PS_OP_LOOKUP_PROCESS,
        u64::from(pid),
        0,
        |pm, body| {
            observed = Some(body);
            assert_eq!(process_references(pm, pid), before + 1);
            Ok(())
        },
    );
    assert_eq!(observed, Some(0x3000));
    assert_eq!(result, (0, 0x3000, u64::from(before + 1), 0));
}

#[test]
fn actual_lookup_projection_rejection_restores_counts_and_publishes_no_pointer() {
    for process in [false, true] {
        let (mut pm, _, pid, tid) = fixture();
        let before = if process {
            process_references(&pm, pid)
        } else {
            thread_references(&pm, tid)
        };
        let (op, object, expected) = if process {
            (
                win32k_subsystem::W32_PS_OP_LOOKUP_PROCESS,
                u64::from(pid),
                0x3000,
            )
        } else {
            (
                win32k_subsystem::W32_PS_OP_LOOKUP_THREAD,
                u64::from(tid),
                0x4000,
            )
        };
        let result = provider_ps::dispatch(&mut pm, op, object, 0, |_, body| {
            assert_eq!(body, expected);
            Err(0xc000009au32)
        });
        assert_eq!(result, (0xc000009au32 as i32, 0, 0, 0));
        let after = if process {
            process_references(&pm, pid)
        } else {
            thread_references(&pm, tid)
        };
        assert_eq!(after, before);
    }
}

#[test]
fn actual_pointer_retain_projects_and_failed_projection_releases_only_new_reference() {
    let (mut pm, _, _, tid) = fixture();
    let before = thread_references(&pm, tid);
    let result = provider_ps::dispatch(
        &mut pm,
        win32k_subsystem::W32_PS_OP_RETAIN_POINTER,
        0x4000,
        0,
        |_, body| {
            assert_eq!(body, 0x4000);
            Ok(())
        },
    );
    assert_eq!(result, (0, u64::from(before + 1), 0, 0));
    let result = provider_ps::dispatch(
        &mut pm,
        win32k_subsystem::W32_PS_OP_RETAIN_POINTER,
        0x4000,
        0,
        |_, body| {
            assert_eq!(body, 0x4000);
            Err(0xc000000du32)
        },
    );
    assert_eq!(result, (0xc000000du32 as i32, 0, 0, 0));
    assert_eq!(thread_references(&pm, tid), before + 1);
}

#[test]
fn invalid_lookup_does_not_invoke_projection() {
    let (mut pm, _, _, _) = fixture();
    let result = provider_ps::dispatch(
        &mut pm,
        win32k_subsystem::W32_PS_OP_LOOKUP_THREAD,
        u64::MAX,
        0,
        |_, _| panic!("invalid lookup cannot authorize projection"),
    );
    assert_ne!(result.0, 0);
    assert_eq!((result.1, result.2, result.3), (0, 0, 0));
}

#[test]
fn canonical_projection_authenticates_physical_route_and_acknowledges_mapping_result() {
    let file = source("provider_ps_projection.rs");
    let grant = function(&file, "grant");
    let mut calls = Calls::default();
    calls.visit_block(&grant.block);
    for required in [
        "channel_route",
        "physical_source",
        "dispatch",
        "current_reply",
        "win32k_physical_lane_for_channel",
        "current_win32k_provider_domain",
    ] {
        assert!(
            calls
                .0
                .iter()
                .any(|name| name.split("::").last() == Some(required)),
            "projection must independently authenticate {required}"
        );
    }
    struct Comparisons(Vec<(String, String)>);
    impl<'ast> Visit<'ast> for Comparisons {
        fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
            if matches!(binary.op, syn::BinOp::Ne(_)) {
                if let (Expr::Field(left), Expr::Field(right)) = (&*binary.left, &*binary.right) {
                    if matches!(&*left.base, Expr::Path(path) if path.path.is_ident("source"))
                        && matches!(&*right.base, Expr::Path(path) if path.path.is_ident("channel"))
                    {
                        if let (syn::Member::Named(left), syn::Member::Named(right)) =
                            (&left.member, &right.member)
                        {
                            self.0.push((left.to_string(), right.to_string()));
                        }
                    }
                }
            }
            syn::visit::visit_expr_binary(self, binary);
        }
    }
    let mut comparisons = Comparisons(Vec::new());
    comparisons.visit_block(&grant.block);
    for member in ["tcb", "pml4"] {
        assert!(
            comparisons.0.contains(&(member.into(), member.into())),
            "actual physical {member} must match the authenticated channel"
        );
    }
    let Some(syn::Stmt::Expr(Expr::Call(result), None)) = grant.block.stmts.last() else {
        panic!("projection must directly propagate canonical mapping acknowledgement");
    };
    assert!(
        matches!(&*result.func, Expr::Path(path)
        if path.path.segments.last().is_some_and(|segment| segment.ident == "grant_referenced_body")),
        "no mapping failure may become successful pointer publication"
    );
    for forbidden in ["unwrap_or", "unwrap_or_default"] {
        assert!(
            !calls.0.iter().any(|name| name == forbidden),
            "no fabricated projection ACK"
        );
    }
}

#[test]
fn bootstrap_ps_projection_uses_retained_vspace_not_later_public_readiness() {
    let file = source("provider_ps_projection.rs");
    let grant = function(&file, "grant");
    struct PublicReadiness(bool);
    impl<'ast> Visit<'ast> for PublicReadiness {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            self.0 |= path
                .path
                .segments
                .iter()
                .any(|segment| segment.ident == "WIN32K_HOST_PML4");
            syn::visit::visit_expr_path(self, path);
        }
    }
    let mut readiness = PublicReadiness(false);
    readiness.visit_block(&grant.block);
    assert!(!readiness.0,
        "DriverEntry owns an authenticated registered VSpace before public completion readiness; projection cannot require the later atomic");
    let mut calls = Calls::default();
    calls.visit_block(&grant.block);
    for required in [
        "physical_source",
        "ProviderRoot::new",
        "grant_referenced_body",
    ] {
        assert!(
            calls.0.iter().any(|name| name.ends_with(required)),
            "bootstrap projection still requires exact retained authority: {required}"
        );
    }
}

#[test]
fn returned_ethread_projects_its_validated_published_process_before_thread_body() {
    let file = source("ps_object_backing.rs");
    let grant = function(&file, "grant_referenced_body");
    #[derive(Default)]
    struct Dependency(Vec<&'static str>);
    impl<'ast> Visit<'ast> for Dependency {
        fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
            if matches!(binary.op, syn::BinOp::Ne(_)) {
                if let (Expr::MethodCall(query), Expr::Call(expected)) =
                    (&*binary.left, &*binary.right)
                {
                    if query.method == "process_kernel_object"
                        && matches!(&*query.receiver, Expr::Path(path) if path.path.is_ident("pm"))
                        && matches!(query.args.first(), Some(Expr::MethodCall(owner))
                            if owner.method == "process_id"
                            && matches!(&*owner.receiver, Expr::Path(path) if path.path.is_ident("lifetime")))
                        && matches!(&*expected.func, Expr::Path(path) if path.path.is_ident("Some"))
                        && matches!(expected.args.first(), Some(Expr::Path(path)) if path.path.is_ident("process_body"))
                    {
                        self.0.push("canonical-process");
                    }
                }
                if let (Expr::Field(phase), Expr::Path(expected)) = (&*binary.left, &*binary.right)
                {
                    if matches!(&phase.member, syn::Member::Named(name) if name == "phase")
                        && matches!(&*phase.base, Expr::Index(row)
                            if matches!(&*row.index, Expr::Path(path) if path.path.is_ident("process_index")))
                        && expected
                            .path
                            .segments
                            .last()
                            .is_some_and(|name| name.ident == "Published")
                    {
                        self.0.push("published-process");
                    }
                }
            }
            syn::visit::visit_expr_binary(self, binary);
        }
        fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
            if matches!(&*assign.left, Expr::Path(path) if path.path.is_ident("dependent_process"))
                && matches!(&*assign.right, Expr::Call(value)
                    if matches!(&*value.func, Expr::Path(path) if path.path.is_ident("Some"))
                    && matches!(value.args.first(), Some(Expr::Path(path)) if path.path.is_ident("process_index")))
            {
                self.0.push("select-process");
            }
            syn::visit::visit_expr_assign(self, assign);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "map_published_row" {
                if matches!(call.args.first(), Some(Expr::Path(path)) if path.path.is_ident("process_index"))
                {
                    self.0.push("map-process");
                } else if matches!(call.args.first(), Some(Expr::Path(path)) if path.path.is_ident("index"))
                {
                    self.0.push("map-thread");
                }
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut dependency = Dependency::default();
    dependency.visit_block(&grant.block);
    let position = |name| {
        dependency
            .0
            .iter()
            .position(|event| *event == name)
            .unwrap_or_else(|| panic!("missing exact ETHREAD dependency boundary {name}"))
    };
    assert!(position("canonical-process") < position("select-process"));
    assert!(position("published-process") < position("select-process"));
    assert!(position("select-process") < position("map-process"));
    assert!(
        position("map-process") < position("map-thread"),
        "acknowledge owning EPROCESS before publishing ETHREAD with embedded process pointer"
    );
}
