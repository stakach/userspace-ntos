//! Acceptance is an observation of actual process generations, not image metadata or PI masks.
//! ReactOS winlogon/setup.c -> syssetup/install.c InstallLiveCD launches userinit directly;
//! the installed WlxActivateUserShell prerequisites are not prerequisites for that media path.

use syn::visit::Visit;

const MAIN: &str = include_str!("../../../../components/ntos-executive/src/main.rs");
const SERVICE: &str =
    include_str!("../../../../components/ntos-executive/src/service_sec_image.rs");
const TERMINAL: &str =
    include_str!("../../../../components/ntos-executive/src/component_terminal.rs");
const OBSERVER: &str =
    include_str!("../../../../components/ntos-executive/src/desktop_observation.rs");

#[test]
fn shell_report_selects_historical_parent_from_unique_live_explorer() {
    let file = syn::parse_file(OBSERVER).unwrap();
    let capture = file
        .items
        .iter()
        .find_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            item.items.iter().find_map(|method| match method {
                syn::ImplItem::Fn(method)
                    if method.sig.ident == "capture_desktop_acceptance_report" =>
                {
                    Some(method)
                }
                _ => None,
            })
        })
        .unwrap();
    let mut evidence = Evidence::default();
    evidence.visit_block(&capture.block);
    assert!(evidence.calls.iter().any(|name| name == "live_for_role"));
    assert!(evidence
        .calls
        .iter()
        .any(|name| name == "historical_snapshot"));
    assert!(evidence.names.iter().any(|name| name == "parent"));
    assert!(
        !evidence.names.iter().any(|name| name == "userinit_count"),
        "unrelated retired Userinit generations must not poison exact Explorer parent selection"
    );
}

#[test]
fn resumed_gui_completion_uses_retained_caller_and_common_receipt_boundary() {
    let service = syn::parse_file(SERVICE).unwrap();
    let completed = function(&service, "process_completed_user_callback_outer_dispatch");
    let mut evidence = Evidence::default();
    evidence.visit_block(&completed.block);
    assert!(
        evidence
            .calls
            .iter()
            .any(|call| call == "observe_completed_desktop_dispatch"),
        "resumed provider completion must record GUI receipts after successful output settlement"
    );
    let terminal = syn::parse_file(TERMINAL).unwrap();
    let mut evidence = Evidence::default();
    evidence.visit_block(&function(&terminal, "process_output").block);
    assert!(
        evidence.names.iter().any(|name| name == "logical_caller"),
        "terminal output must pass original continuation caller, never recapture ambient thread"
    );
}

#[test]
fn inline_gui_completion_uses_same_exact_receipt_boundary() {
    let service = syn::parse_file(SERVICE).unwrap();
    let mut evidence = Evidence::default();
    evidence.visit_block(&function(&service, "service_sec_image").block);
    assert!(
        evidence
            .calls
            .iter()
            .any(|call| call == "observe_completed_desktop_dispatch"),
        "inline and resumed GUI completions must share the authenticated receipt policy"
    );
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == name => Some(item),
            _ => None,
        })
        .unwrap_or_else(|| panic!("actual production function {name} must exist"))
}

#[derive(Default)]
struct Evidence {
    names: Vec<String>,
    calls: Vec<String>,
    bytes: Vec<Vec<u8>>,
}

impl<'ast> Visit<'ast> for Evidence {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.names.push(ident.to_string());
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(name) = path.path.segments.last() {
                self.calls.push(name.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_lit_byte_str(&mut self, literal: &'ast syn::LitByteStr) {
        self.bytes.push(literal.value());
    }
}

fn report_parameter(function: &syn::ItemFn) -> String {
    function
        .sig
        .inputs
        .iter()
        .find_map(|input| {
            let syn::FnArg::Typed(input) = input else {
                return None;
            };
            let ty = match &*input.ty {
                syn::Type::Reference(reference) => &*reference.elem,
                ty => ty,
            };
            let syn::Type::Path(path) = ty else {
                return None;
            };
            if !path
                .path
                .segments
                .last()
                .is_some_and(|name| name.ident == "DesktopAcceptanceReport")
            {
                return None;
            }
            if let syn::Type::Reference(reference) = &*input.ty {
                assert!(
                    reference.mutability.is_none(),
                    "acceptance must consume an immutable report"
                );
            }
            let syn::Pat::Ident(name) = &*input.pat else {
                return None;
            };
            Some(name.ident.to_string())
        })
        .unwrap_or_else(|| {
            panic!(
        "{} must consume a copied exact-generation DesktopAcceptanceReport, not live PI globals",
        function.sig.ident
    )
        })
}

fn assert_exact_gate(name: &str) {
    let file = syn::parse_file(MAIN).expect("actual executive source must parse");
    let gate = function(&file, name);
    let mut evidence = Evidence::default();
    evidence.visit_block(&gate.block);
    for forbidden in [
        "hosted_gate_pi",
        "hosted_gate_bit",
        "hosted_thread_runtime_gate_published",
        "PM_EXEC_LINK_OK",
        "PM_IDENTITY_OK",
        "PM_PROCESS_SPAWNED_OK",
        "PM_VSPACE_PUBLISHED_OK",
        "USERINIT_SPAWNED",
        "EXPLORER_SPAWNED",
    ] {
        assert!(
            !evidence.names.iter().any(|value| value == forbidden),
            "{name} must not combine historical PI/leaf evidence through {forbidden}"
        );
    }
    let report = report_parameter(gate);
    assert!(
        evidence.names.contains(&report),
        "{name} must actually consume its report"
    );
}

#[test]
fn userinit_compound_gate_consumes_exact_historical_launch_receipts() {
    assert_exact_gate("userinit_image_pipeline_spec");
}

#[test]
fn explorer_compound_gate_consumes_exact_live_launch_and_gui_receipts() {
    assert_exact_gate("explorer_image_pipeline_spec");
}

#[test]
fn desktop_batch_evidence_requires_completed_flush_and_retains_original_caller() {
    let file = syn::parse_file(MAIN).expect("actual executive source must parse");
    let flush = function(&file, "ke_gdi_flush_user_batch");
    let statements = &flush.block.stmts;
    let capture = statements
        .iter()
        .position(|statement| {
            let syn::Stmt::Local(local) = statement else {
                return false;
            };
            let Some(initializer) = &local.init else {
                return false;
            };
            matches!(&*initializer.expr, syn::Expr::Field(field)
            if matches!(&field.member, syn::Member::Named(name) if name == "logical_caller"))
        })
        .expect("retain the exact caller before invoking the reentrant batch provider");
    let dispatch = statements
        .iter()
        .position(|statement| {
            let mut evidence = Evidence::default();
            evidence.visit_stmt(statement);
            evidence
                .calls
                .iter()
                .any(|call| call == "win32k_flush_user_gdi_batch")
        })
        .expect("invoke the real batch provider");
    assert!(capture < dispatch);
    let completion = statements
        .iter()
        .enumerate()
        .find_map(|(index, statement)| {
            let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else {
                return None;
            };
            let mut condition = Evidence::default();
            condition.visit_expr(&branch.cond);
            let mut body = Evidence::default();
            body.visit_block(&branch.then_branch);
            body.calls
                .iter()
                .any(|call| call == "service_observe_desktop_gui_for")
                .then_some((index, branch, condition))
        })
        .expect("only acknowledged batch completion can publish desktop evidence");
    assert!(completion.0 > dispatch);
    assert!(completion.2.names.iter().any(|name| name == "ok"));
    assert!(completion.2.names.iter().any(|name| name == "status"));
    let syn::Expr::Binary(and) = &*completion.1.cond else {
        panic!("completion must require both a real return and successful status");
    };
    assert!(matches!(and.op, syn::BinOp::And(_)));
    assert!(matches!(&*and.left, syn::Expr::Path(path) if path.path.is_ident("ok")));
    let syn::Expr::Binary(status) = &*and.right else {
        panic!("require successful status")
    };
    assert!(matches!(status.op, syn::BinOp::Eq(_)));
    assert!(matches!(&*status.right, syn::Expr::Lit(literal)
        if matches!(&literal.lit, syn::Lit::Int(integer) if integer.base10_parse::<u32>().ok() == Some(0))));
    let mut facts = Evidence::default();
    facts.visit_block(&completion.1.then_branch);
    for required in ["batch_caller", "BatchFlush", "BatchRecords"] {
        assert!(facts.names.iter().any(|name| name == required));
    }
}

fn withdraws_loop_context(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Expr(syn::Expr::Assign(assignment), _) = statement else {
        return false;
    };
    let syn::Expr::Field(field) = &*assignment.left else {
        return false;
    };
    let syn::Member::Named(member) = &field.member else {
        return false;
    };
    let syn::Expr::Path(value) = &*assignment.right else {
        return false;
    };
    member == "loop_ctx" && value.path.is_ident("None")
}

fn local_name(pattern: &syn::Pat) -> Option<String> {
    match pattern {
        syn::Pat::Ident(name) => Some(name.ident.to_string()),
        syn::Pat::Type(typed) => local_name(&typed.pat),
        _ => None,
    }
}

#[test]
fn service_returns_copied_desktop_report_before_withdrawing_live_context() {
    let file = syn::parse_file(SERVICE).expect("actual service source must parse");
    let service = function(&file, "service_sec_image");
    let statements = &service.block.stmts;
    let withdrawal = statements
        .iter()
        .position(withdraws_loop_context)
        .expect("service must withdraw its live loop context");
    let (capture, report) = statements
        .iter()
        .enumerate()
        .find_map(|(index, statement)| {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let name = local_name(&local.pat)?;
            let initializer = local.init.as_ref()?;
            let mut evidence = Evidence::default();
            evidence.visit_expr(&initializer.expr);
            evidence
                .calls
                .iter()
                .any(|call| call == "capture_desktop_acceptance_report")
                .then_some((index, name))
        })
        .expect("capture an owned exact-generation acceptance report while the handler is live");
    assert!(
        capture < withdrawal,
        "capture must precede loop_ctx withdrawal"
    );
    let syn::ReturnType::Type(_, returned) = &service.sig.output else {
        panic!("service must return its acceptance report");
    };
    let mut return_type = Evidence::default();
    return_type.visit_type(returned);
    assert!(return_type
        .names
        .iter()
        .any(|name| name == "DesktopAcceptanceReport"));
    let mut returned = Evidence::default();
    returned.visit_stmt(statements.last().expect("service has a return expression"));
    assert!(
        returned.names.contains(&report),
        "the returned result must contain the captured report, not a live handler pointer"
    );
}

#[derive(Default)]
struct LaunchContractArms {
    report: String,
    installed: bool,
    media: bool,
    installed_gate_outside_contract: bool,
    in_installed: bool,
    in_captured_contract: bool,
}

impl<'ast> Visit<'ast> for LaunchContractArms {
    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        let from_report = matches!(&*expression.expr, syn::Expr::MethodCall(call)
            if call.method == "launch_contract"
                && matches!(&*call.receiver, syn::Expr::Path(path)
                    if path.path.is_ident(self.report.as_str())));
        let old = self.in_captured_contract;
        self.in_captured_contract = from_report;
        syn::visit::visit_expr_match(self, expression);
        self.in_captured_contract = old;
    }

    fn visit_arm(&mut self, arm: &'ast syn::Arm) {
        let mut pattern = Evidence::default();
        pattern.visit_pat(&arm.pat);
        let installed = pattern.names.iter().any(|name| name == "InstalledLogon");
        let media = pattern.names.iter().any(|name| name == "MediaSetup");
        assert!(
            !(installed && media),
            "media setup and installed logon need separate contracts"
        );
        assert!(
            !(installed || media) || self.in_captured_contract,
            "startup mode must be the captured report's registry contract, not an image/PI guess"
        );
        let mut body = Evidence::default();
        body.visit_expr(&arm.body);
        let has_installed_gate = body
            .bytes
            .iter()
            .any(|value| value == b"exec_winlogon_user_shell_activated");
        self.installed |= installed && has_installed_gate;
        self.media |= media;
        assert!(
            !media || !has_installed_gate,
            "LiveCD must not require WlxActivateUserShell"
        );
        let old = self.in_installed;
        self.in_installed |= installed;
        syn::visit::visit_arm(self, arm);
        self.in_installed = old;
    }

    fn visit_lit_byte_str(&mut self, literal: &'ast syn::LitByteStr) {
        if literal.value() == b"exec_winlogon_user_shell_activated" && !self.in_installed {
            self.installed_gate_outside_contract = true;
        }
    }
}

#[test]
fn shell_activation_uses_captured_media_or_installed_prerequisites() {
    let file = syn::parse_file(MAIN).expect("actual executive source must parse");
    let gate = function(&file, "user_shell_activation_spec");
    let report = report_parameter(gate);
    let mut evidence = Evidence::default();
    evidence.visit_block(&gate.block);
    assert!(
        evidence.names.contains(&report),
        "startup contract must come from the captured report"
    );
    assert!(evidence.calls.iter().any(|call| call == "launch_contract"));
    let mut arms = LaunchContractArms {
        report,
        ..LaunchContractArms::default()
    };
    arms.visit_block(&gate.block);
    assert!(
        arms.installed && arms.media,
        "both real startup contracts must be explicit"
    );
    assert!(
        !arms.installed_gate_outside_contract,
        "installed-only gates cannot be unconditional"
    );
    assert!(
        evidence
            .calls
            .iter()
            .any(|call| call == "userinit_image_pipeline_spec"),
        "media setup still requires genuine userinit and subsequent desktop receipts"
    );
}
