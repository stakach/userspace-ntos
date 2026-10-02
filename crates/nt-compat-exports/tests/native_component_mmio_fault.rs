use std::path::PathBuf;
use syn::{visit::Visit, Expr, Item, ItemFn, Pat};

fn source(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).expect("native MMIO fault source")).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .expect("component fault entry point")
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
}

#[derive(Default)]
struct MmioGate {
    terminal: bool,
}

impl<'ast> Visit<'ast> for MmioGate {
    fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
        if let Expr::Let(condition) = &*branch.cond {
            if let (Pat::TupleStruct(pattern), Expr::Call(call)) =
                (&*condition.pat, &*condition.expr)
            {
                if pattern.path.is_ident("Some") && pattern.elems.len() == 1 {
                    if let (Some(Pat::Ident(binding)), Expr::Path(path)) =
                        (pattern.elems.first(), &*call.func)
                    {
                        let segments: Vec<_> = path
                            .path
                            .segments
                            .iter()
                            .map(|segment| segment.ident.to_string())
                            .collect();
                        if segments.ends_with(&[
                            "hosted_component_mmio_fault".into(),
                            "service_fault".into(),
                        ]) {
                            assert_eq!(call.args.len(), 3);
                            for (argument, expected) in call.args.iter().zip(["ch", "addr", "fsr"])
                            {
                                assert!(matches!(argument, Expr::Path(path) if path.path.is_ident(expected)),
                                    "MMIO admission uses the exact fault channel, address and access");
                            }
                            self.terminal = branch.then_branch.stmts.iter().any(|statement| {
                                matches!(statement, syn::Stmt::Expr(Expr::Return(result), _)
                                    if matches!(result.expr.as_deref(), Some(Expr::Path(path))
                                        if path.path.is_ident(&binding.ident)))
                            });
                        }
                    }
                }
            }
        }
        syn::visit::visit_expr_if(self, branch);
    }
}

#[test]
fn canonical_mmio_fault_resolution_precedes_every_anonymous_component_fill() {
    let file = source("spawn_hosts.rs");
    let fault = function(&file, "pump_service_vm_fault");
    let mut calls = Calls::default();
    calls.visit_block(&fault.block);
    let mmio = calls
        .0
        .iter()
        .position(|name| name.ends_with("hosted_component_mmio_fault::service_fault"))
        .expect("resolve canonical retained MMIO before private demand-zero dispatch");
    for fallback in ["pump_service_win32k_fault", "pump_service_generic_fault"] {
        let position = calls.0.iter().position(|name| name == fallback).unwrap();
        assert!(
            mmio < position,
            "MMIO must never reach anonymous RAM fallback"
        );
    }
    let mut gate = MmioGate::default();
    gate.visit_block(&fault.block);
    assert!(
        gate.terminal,
        "both MMIO success and refusal are terminal; ambiguous or failed MMIO cannot fall through"
    );
}

#[test]
fn retained_mmio_fault_resolver_never_allocates_anonymous_backing() {
    let file = source("hosted_component_mmio_fault.rs");
    let _ = function(&file, "service_fault");
    let mut calls = Calls::default();
    calls.visit_file(&file);
    assert!(
        calls.0.iter().any(|name| name.ends_with("page_map_r")),
        "acknowledging a lost MMIO leaf requires an actual retained-cap PageMap effect"
    );
    for forbidden in [
        "alloc_frame",
        "alloc_frame_r",
        "pump_service_generic_fault",
        "pump_service_win32k_fault",
        "untyped_retype_r",
    ] {
        assert!(
            !calls
                .0
                .iter()
                .any(|name| name.split("::").last() == Some(forbidden)),
            "MMIO resolution must not synthesize memory backing: {forbidden}"
        );
    }
}

fn field_is(expression: &Expr, base: &str, member: &str) -> bool {
    matches!(expression, Expr::Field(field)
        if matches!(&*field.base, Expr::Path(path) if path.path.is_ident(base))
        && matches!(&field.member, syn::Member::Named(name) if name == member))
}

fn returns_none(block: &syn::Block) -> bool {
    block.stmts.iter().any(|statement| {
        matches!(statement, syn::Stmt::Expr(Expr::Return(result), _)
            if matches!(result.expr.as_deref(), Some(Expr::Path(path)) if path.path.is_ident("None")))
    })
}

#[derive(Default)]
struct FaultPreflight {
    protection_mask: bool,
    binding_fields: Vec<String>,
    current_cap_checked: bool,
    retained_cap_checked: bool,
}

impl<'ast> Visit<'ast> for FaultPreflight {
    fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
        struct Condition<'a>(&'a mut FaultPreflight);
        impl<'ast> Visit<'ast> for Condition<'_> {
            fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
                if matches!(binary.op, syn::BinOp::BitAnd(_))
                    && matches!(&*binary.left, Expr::Path(path) if path.path.is_ident("fsr"))
                    && matches!(&*binary.right, Expr::Lit(literal)
                        if matches!(&literal.lit, syn::Lit::Int(value) if value.base10_parse::<u64>().ok() == Some(0x11)))
                {
                    self.0.protection_mask = true;
                }
                if matches!(binary.op, syn::BinOp::Ne(_)) {
                    for member in ["driver_id", "instance", "projection_domain", "pdo_object"] {
                        if field_is(&binary.left, "state", member)
                            && field_is(&binary.right, "binding", member)
                        {
                            self.0.binding_fields.push(member.to_owned());
                        }
                    }
                }
                syn::visit::visit_expr_binary(self, binary);
            }

            fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
                if matches!(&*call.func, Expr::Path(path)
                    if path.path.segments.last().is_some_and(|segment| segment.ident == "checked_frame_address"))
                {
                    if let Some(argument) = call.args.first() {
                        self.0.current_cap_checked |= matches!(argument, Expr::Path(path) if path.path.is_ident("source_cap"));
                        self.0.retained_cap_checked |= matches!(argument, Expr::Try(value)
                            if matches!(&*value.expr, Expr::MethodCall(method)
                                if method.method == "cap" && matches!(&*method.receiver, Expr::Path(path) if path.path.is_ident("row"))));
                    }
                }
                syn::visit::visit_expr_call(self, call);
            }
        }
        // Only fail-closed conditions count as binding/cap admission checks.
        if returns_none(&branch.then_branch) {
            Condition(self).visit_expr(&branch.cond);
        } else if branch.then_branch.stmts.iter().any(|statement| {
            matches!(statement, syn::Stmt::Expr(Expr::Return(result), _)
                if matches!(result.expr.as_deref(), Some(Expr::Call(call))
                    if matches!(&*call.func, Expr::Path(path) if path.path.is_ident("Some"))
                    && matches!(call.args.first(), Some(Expr::Lit(literal))
                        if matches!(&literal.lit, syn::Lit::Bool(value) if !value.value))))
        }) {
            Condition(self).visit_expr(&branch.cond);
        }
        syn::visit::visit_expr_if(self, branch);
    }
}

#[test]
fn mmio_repair_rejects_protection_and_execute_faults_and_exact_binding_mismatch() {
    let file = source("hosted_component_mmio_fault.rs");
    let fault = function(&file, "service_fault");
    let mut preflight = FaultPreflight::default();
    preflight.visit_block(&fault.block);
    assert!(
        preflight.protection_mask,
        "present/protection and execute faults must be refused, not remapped"
    );
    for member in ["driver_id", "instance", "projection_domain", "pdo_object"] {
        assert!(
            preflight.binding_fields.iter().any(|field| field == member),
            "canonical resource state must match the exact binding {member}"
        );
    }
}

#[test]
fn mmio_repair_attests_current_context_and_retained_cap_before_map_effect() {
    let file = source("hosted_component_mmio_fault.rs");
    let fault = function(&file, "service_fault");
    let mut preflight = FaultPreflight::default();
    preflight.visit_block(&fault.block);
    assert!(preflight.current_cap_checked && preflight.retained_cap_checked,
        "both the selected owner's current context cap and retained map cap require physical attestation");
    let mut calls = Calls::default();
    calls.visit_block(&fault.block);
    let resolve = calls
        .0
        .iter()
        .position(|name| name.ends_with("hosted_pnp_mapping_page"))
        .unwrap();
    let remap = calls
        .0
        .iter()
        .position(|name| name.ends_with("begin_remap"))
        .unwrap();
    let checks: Vec<_> = calls
        .0
        .iter()
        .enumerate()
        .filter_map(|(index, name)| name.ends_with("checked_frame_address").then_some(index))
        .collect();
    assert_eq!(
        checks.len(),
        2,
        "attest current backing and original retained map cap, never historical source cap"
    );
    assert!(
        checks
            .iter()
            .all(|index| resolve < *index && *index < remap),
        "exact context selection and both native physical checks precede the remap effect epoch"
    );
}
