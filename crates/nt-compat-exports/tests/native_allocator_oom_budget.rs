#[path = "../../../components/ntos-executive/src/allocator_oom_budget.rs"]
mod budget;

use syn::{visit::Visit, Expr, Item};

#[derive(Default)]
struct Calls {
    names: Vec<String>,
    scopes: Vec<Vec<u8>>,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.names.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, call: &'ast syn::Macro) {
        if let Some(segment) = call.path.segments.last() {
            self.names.push(segment.ident.to_string());
        }
        syn::visit::visit_macro(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            if let Some(segment) = path.path.segments.last() {
                self.names.push(segment.ident.to_string());
                if segment.ident == "enter_scope" {
                    if let Some(Expr::Lit(literal)) = call.args.first() {
                        if let syn::Lit::ByteStr(scope) = &literal.lit {
                            self.scopes.push(scope.value());
                        }
                    }
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn function_calls(source: &str, name: &str) -> Calls {
    let file = syn::parse_file(source).unwrap();
    let block = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(&*function.block),
            Item::Impl(implementation) => implementation.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => Some(&method.block),
                _ => None,
            }),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing {name}"));
    let mut calls = Calls::default();
    calls.visit_block(block);
    calls
}

#[test]
fn native_oom_reporting_and_value_reservations_use_focused_diagnostics() {
    let report = function_calls(
        include_str!("../../../components/ntos-executive/src/allocator.rs"),
        "report_oom",
    );
    let budget = report
        .names
        .iter()
        .position(|name| name == "next_oom_emission")
        .unwrap();
    let write = report
        .names
        .iter()
        .position(|name| name == "write_word")
        .unwrap();
    let print = report
        .names
        .iter()
        .position(|name| name == "debug_bytes")
        .unwrap();
    assert!(
        budget < write && write < print,
        "reserve emission before logging"
    );
    for forbidden in [
        "alloc",
        "reserve",
        "reserve_exact",
        "try_reserve",
        "try_reserve_exact",
        "collect",
        "format",
        "vec",
        "with_capacity",
        "to_vec",
        "to_owned",
    ] {
        assert!(!report.names.iter().any(|name| name == forbidden));
    }
    let capture = function_calls(
        include_str!("../../../components/ntos-executive/src/exec_registry_value_mutation.rs"),
        "nt_set_value_key_admitted",
    );
    assert_eq!(
        capture.scopes,
        [
            b"registry.set-value-capture".to_vec(),
            b"registry.set-value-retain-cm".to_vec(),
            b"registry.set-value-mutation".to_vec()
        ]
    );
    let hive = function_calls(
        include_str!("../../../components/ntos-executive/src/exec_registry_set_value.rs"),
        "journal_set_mutable_value",
    );
    assert_eq!(
        hive.scopes,
        [
            b"registry.mutable-hive-path".to_vec(),
            b"hive.prepare-value".to_vec()
        ]
    );
    let append = function_calls(
        include_str!("../../../components/ntos-executive/src/writable_fs.rs"),
        "append_log_record",
    );
    assert_eq!(append.scopes, [b"memfs.hive-journal-append".to_vec()]);
}

#[test]
fn allocation_guard_observes_methods_and_macros() {
    let calls = function_calls(
        "fn probe() { bytes.try_reserve(1); let _ = format!(\"x\"); let _ = vec![1]; }",
        "probe",
    );
    assert_eq!(calls.names, ["try_reserve", "format", "vec"]);
}

#[test]
fn earlier_refusal_does_not_suppress_later_frontiers_within_explicit_bound() {
    let mut emitted = 0;
    let mut receipts = Vec::new();
    for frontier in [
        ("capture", 8),
        ("hive.prepare-value", 60_528),
        ("memfs.hive-journal-append", 60_528),
    ] {
        if let Some(next) = budget::next_oom_emission(emitted) {
            emitted = next;
            receipts.push(frontier);
        }
    }
    assert_eq!(receipts.len(), 3);
    assert_eq!(receipts[1], ("hive.prepare-value", 60_528));
    assert_eq!(receipts[2], ("memfs.hive-journal-append", 60_528));
    while let Some(next) = budget::next_oom_emission(emitted) {
        emitted = next;
    }
    assert_eq!(emitted, budget::OOM_EMISSION_LIMIT);
    assert_eq!(budget::next_oom_emission(emitted), None);
    assert_eq!(budget::next_oom_emission(usize::MAX), None);
}
