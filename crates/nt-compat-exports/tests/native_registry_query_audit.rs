//! Missing-value receipts observe a completed query, never admit or retry one.
use syn::{visit::Visit, Expr, Pat};

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src").join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn pattern_name(pattern: &Pat) -> Option<String> {
    match pattern {
        Pat::Path(path) => path.path.segments.last().map(|part| part.ident.to_string()),
        Pat::Ident(ident) => Some(ident.ident.to_string()),
        _ => None,
    }
}

#[derive(Default)]
struct Effects { calls: Vec<String>, paths: Vec<String>, macros: Vec<String> }
impl<'ast> Visit<'ast> for Effects {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.calls.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.paths.push(path.path.segments.last().unwrap().ident.to_string());
        syn::visit::visit_expr_path(self, path);
    }
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.macros.push(mac.path.segments.last().unwrap().ident.to_string());
        syn::visit::visit_macro(self, mac);
    }
}

fn query_body() -> Box<Expr> {
    struct Query(Option<Box<Expr>>);
    impl<'ast> Visit<'ast> for Query {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if pattern_name(&arm.pat).as_deref() == Some("NtQueryValueKey") {
                assert!(self.0.is_none(), "one actual syscall boundary");
                self.0 = Some(arm.body.clone());
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut query = Query(None);
    query.visit_file(&source("exec_handler.rs"));
    query.0.expect("actual NtQueryValueKey arm")
}

#[test]
fn missing_query_hook_uses_counted_capture_only_after_actual_missing_result() {
    struct Missing(Vec<Box<Expr>>);
    impl<'ast> Visit<'ast> for Missing {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if let Pat::TupleStruct(pattern) = &arm.pat {
                if pattern.path.segments.last().is_some_and(|part| part.ident == "Ok")
                    && pattern.elems.len() == 1
                    && pattern_name(&pattern.elems[0]).as_deref() == Some("None")
                { self.0.push(arm.body.clone()); }
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let body = query_body();
    let mut missing = Missing(Vec::new());
    missing.visit_expr(&body);
    assert_eq!(missing.0.len(), 1);
    let mut effects = Effects::default();
    effects.visit_expr(&missing.0[0]);
    assert_eq!(effects.calls.iter().filter(|name| *name == "missing_value").count(), 1,
        "actual missing-value branch needs the generic receipt");
    struct Hook(Vec<syn::ExprCall>);
    impl<'ast> Visit<'ast> for Hook {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if matches!(&*call.func, Expr::Path(path)
                if path.path.segments.last().is_some_and(|part| part.ident == "missing_value"))
            { self.0.push(call.clone()); }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut hooks = Hook(Vec::new());
    hooks.visit_expr(&body);
    assert_eq!(hooks.0.len(), 1, "no receipts before probes or on successful query");
    let mut args = Effects::default();
    for argument in &hooks.0[0].args { args.visit_expr(argument); }
    for captured in ["name16", "key_path", "key", "query_pid", "query_tid", "query_pi"] {
        assert!(args.paths.iter().any(|name| name == captured));
    }
    assert!(!args.paths.iter().any(|name| name == "name_lc"));
    for forbidden in ["capture_registry_value_name", "registry_target_path", "resolve_registry_key", "probe_user_output"] {
        assert!(!args.calls.iter().any(|name| name == forbidden));
    }
    let Expr::Block(block) = &*missing.0[0] else { panic!("missing block") };
    let Some(syn::Stmt::Expr(Expr::Lit(status), None)) = block.block.stmts.last() else {
        panic!("unchanged missing status must remain the branch result")
    };
    assert!(matches!(&status.lit, syn::Lit::Int(value)
        if matches!(value.base10_parse::<u32>(), Ok(0xc0000034))));
}

#[test]
fn observed_caller_is_captured_before_key_lookup_without_new_admission() {
    struct Order(Vec<String>);
    impl<'ast> Visit<'ast> for Order {
        fn visit_local(&mut self, local: &'ast syn::Local) {
            if let Pat::Ident(binding) = &local.pat {
                if ["query_pid", "query_tid", "query_pi"].contains(&binding.ident.to_string().as_str()) {
                    self.0.push(binding.ident.to_string());
                    assert!(binding.mutability.is_none());
                    struct Propagate(bool);
                    impl<'ast> Visit<'ast> for Propagate {
                        fn visit_expr_try(&mut self, _: &'ast syn::ExprTry) { self.0 = true; }
                    }
                    let mut propagation = Propagate(false);
                    propagation.visit_expr(&local.init.as_ref().unwrap().expr);
                    assert!(!propagation.0, "unavailable telemetry cannot change syscall status");
                }
            }
            syn::visit::visit_local(self, local);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "resolve_registry_key" { self.0.push("resolve_registry_key".into()); }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut order = Order(Vec::new());
    order.visit_expr(&query_body());
    assert_eq!(order.0, ["query_pid", "query_tid", "query_pi", "resolve_registry_key"]);
}

#[test]
fn receipt_has_no_allocation_user_reads_authority_resolution_or_policy_filters() {
    let file = source("registry_query_audit.rs");
    let mut effects = Effects::default();
    effects.visit_file(&file);
    for forbidden in ["format", "collect", "to_string", "to_owned", "to_vec", "reserve",
        "try_reserve", "from_utf16", "from_utf16_lossy", "read_volatile", "read_unaligned",
        "resolve_registry_key", "registry_target_path", "capture_registry_value_name",
        "probe_user_output", "current_process_is_winlogon", "current_process_is_interactive_shell"] {
        assert!(!effects.calls.iter().chain(&effects.macros).any(|name| name == forbidden),
            "receipt must not change authority, allocation, capture, or policy: {forbidden}");
    }
    for bound in ["RECEIPT_LIMIT", "PATH_BYTE_LIMIT", "VALUE_UNIT_LIMIT"] {
        assert!(effects.paths.iter().any(|name| name == bound));
    }
    assert!(effects.calls.iter().any(|name| name == "fetch_update"));
}

static OUTPUT: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());
static AUDIT_CLOCK_AVAILABLE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static AUDIT_CLOCK_100NS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

fn registry_query_audit_time_100ns() -> Option<u64> {
    use std::sync::atomic::Ordering;
    AUDIT_CLOCK_AVAILABLE.load(Ordering::Acquire)
        .then(|| AUDIT_CLOCK_100NS.load(Ordering::Relaxed))
}

fn print_str(bytes: &[u8]) { OUTPUT.lock().unwrap().push_str(std::str::from_utf8(bytes).unwrap()); }
fn print_u64(value: u64) { print_str(value.to_string().as_bytes()); }

#[path = "../../../components/ntos-executive/src/registry_query_audit.rs"]
mod native_audit;

#[test]
fn actual_receipt_bounds_total_output_and_escapes_original_utf16() {
    native_audit::missing_value(None, 0, 0, 0, None, &[]);
    let mut name = vec![0x0041, 0x0000, 0x000a, 0x0022, 0x005c, 0xd800];
    name.resize(80, 0x0042);
    let mut path = String::from("key\n\"\\");
    path.push_str(&"p".repeat(300));
    for _ in 0..130 {
        native_audit::missing_value(Some(604), 608, 17, 9, Some(&path), &name);
    }
    let output = OUTPUT.lock().unwrap();
    assert_eq!(output.lines().count(), 128, "newlines in names/paths cannot inject log records");
    assert!(output.contains("receipt=128/128"));
    assert!(output.contains("lifetime-receipt=128/8192 window=unavailable"));
    assert!(!output.contains("receipt=129/128"));
    assert!(output.contains("pid=604 tid=608 pi=17 key-target=9"));
    assert!(output.contains("pid=unavailable tid=0 pi=0 key-target=0"));
    assert!(output.contains("path-present=0 path-bytes=0 path-truncated=0 path=\"\" value-units=0 value-truncated=0 value=\"\""));
    assert!(output.contains("path-truncated=1"));
    assert!(output.contains("value-units=80 value-truncated=1"));
    assert!(output.contains("A\\u0000\\u000a\\u0022\\u005c\\ud800"));
    assert!(output.contains("key\\x0a\\x22\\x5c"));
    assert!(output.contains("status=0xc0000034"));
    assert!(output.len() < 128 * 2048, "all three output dimensions are bounded");
    drop(output);

    // This is the only test invoking the global observer; its initial clock is unavailable.
    AUDIT_CLOCK_100NS.store(60 * 10_000_000, std::sync::atomic::Ordering::Relaxed);
    AUDIT_CLOCK_AVAILABLE.store(true, std::sync::atomic::Ordering::Release);
    native_audit::missing_value(Some(604), 608, 17, 9, Some(&path), &name);
    let output = OUTPUT.lock().unwrap();
    assert_eq!(output.lines().count(), 129,
        "an earlier exhausted window must not suppress a later missing-value receipt");
    let renewed = output.lines().last().unwrap();
    assert!(renewed.contains("receipt=1/128"));
    assert!(renewed.contains("lifetime-receipt=129/8192 window=1"));
    assert!(renewed.contains("pid=604 tid=608 pi=17 key-target=9"));
    assert!(renewed.contains("A\\u0000\\u000a\\u0022\\u005c\\ud800"));
    assert!(renewed.contains("status=0xc0000034"));
}

const TEST_WINDOW_100NS: u64 = 60 * 10_000_000;

#[test]
fn unavailable_budget_renews_at_first_known_zero_epoch() {
    let budget = native_audit::ReceiptBudget::new();
    for ordinal in 1..=128 {
        let receipt = budget.claim(None).unwrap();
        assert_eq!(receipt.receipt, ordinal);
        assert_eq!(receipt.lifetime_receipt, ordinal);
        assert_eq!(receipt.window, None);
    }
    assert_eq!(budget.claim(None), None);
    let first_known = budget.claim(Some(0)).unwrap();
    assert_eq!(first_known.receipt, 1);
    assert_eq!(first_known.lifetime_receipt, 129);
    assert_eq!(first_known.window, Some(0));
    let equal = budget.claim(Some(0)).unwrap();
    assert_eq!(equal.receipt, 2);
    assert_eq!(equal.lifetime_receipt, 130);
    assert_eq!(equal.window, Some(0));
}

#[test]
fn only_a_forward_epoch_renews_the_current_window() {
    let budget = native_audit::ReceiptBudget::new();
    for ordinal in 1..=128 {
        assert_eq!(budget.claim(Some(0)).unwrap().receipt, ordinal);
    }
    assert_eq!(budget.claim(Some(TEST_WINDOW_100NS - 1)), None);
    let renewed = budget.claim(Some(TEST_WINDOW_100NS)).unwrap();
    assert_eq!(renewed.receipt, 1);
    assert_eq!(renewed.lifetime_receipt, 129);
    assert_eq!(renewed.window, Some(1));
    for ordinal in 2..=128 {
        let now = match ordinal % 3 {
            0 => None,
            1 => Some(0),
            _ => Some(TEST_WINDOW_100NS),
        };
        let receipt = budget.claim(now).unwrap();
        assert_eq!(receipt.receipt, ordinal);
        assert_eq!(receipt.lifetime_receipt, 128 + ordinal);
        assert_eq!(receipt.window, Some(1));
    }
    for now in [None, Some(0), Some(TEST_WINDOW_100NS), Some(2 * TEST_WINDOW_100NS - 1)] {
        assert_eq!(budget.claim(now), None);
    }
    let next = budget.claim(Some(2 * TEST_WINDOW_100NS)).unwrap();
    assert_eq!(next.receipt, 1);
    assert_eq!(next.lifetime_receipt, 257);
    assert_eq!(next.window, Some(2));
}

#[test]
fn maximum_clock_value_is_representable_without_reopening_old_windows() {
    let budget = native_audit::ReceiptBudget::new();
    let epoch = u64::MAX / TEST_WINDOW_100NS;
    for ordinal in 1..=128 {
        let now = if ordinal == 1 || ordinal % 3 == 0 {
            Some(u64::MAX)
        } else if ordinal % 3 == 1 {
            Some(0)
        } else {
            None
        };
        let receipt = budget.claim(now).unwrap();
        assert_eq!(receipt.receipt, ordinal);
        assert_eq!(receipt.lifetime_receipt, ordinal);
        assert_eq!(receipt.window, Some(epoch));
    }
    for now in [None, Some(0), Some(u64::MAX)] {
        assert_eq!(budget.claim(now), None);
    }
}

#[test]
fn lifetime_limit_is_exact_across_windows_and_refusals() {
    let budget = native_audit::ReceiptBudget::new();
    for window in 0..64 {
        for ordinal in 1..=128 {
            let receipt = budget.claim(Some(window * TEST_WINDOW_100NS)).unwrap();
            assert_eq!(receipt.receipt, ordinal);
            assert_eq!(receipt.lifetime_receipt, window * 128 + ordinal);
            assert_eq!(receipt.window, Some(window));
        }
        assert_eq!(budget.claim(Some(window * TEST_WINDOW_100NS)), None);
    }
    for now in [None, Some(0), Some(64 * TEST_WINDOW_100NS), Some(u64::MAX)] {
        assert_eq!(budget.claim(now), None, "the 8192 lifetime cap cannot renew");
    }
}

#[test]
fn concurrent_claims_cannot_leak_lifetime_budget_on_cas_retries() {
    let budget = std::sync::Arc::new(native_audit::ReceiptBudget::new());
    let start = std::sync::Arc::new(std::sync::Barrier::new(8));
    let threads: Vec<_> = (0..8).map(|_| {
        let budget = std::sync::Arc::clone(&budget);
        let start = std::sync::Arc::clone(&start);
        std::thread::spawn(move || {
            start.wait();
            (0..64).filter_map(|_| budget.claim(None)).collect::<Vec<_>>()
        })
    }).collect();
    let mut receipts: Vec<_> = threads.into_iter()
        .flat_map(|thread| thread.join().unwrap()).collect();
    receipts.sort_by_key(|receipt| receipt.lifetime_receipt);
    assert_eq!(receipts.len(), 128);
    for (index, receipt) in receipts.iter().enumerate() {
        assert_eq!(receipt.receipt, index as u64 + 1);
        assert_eq!(receipt.lifetime_receipt, index as u64 + 1);
        assert_eq!(receipt.window, None);
    }
    assert_eq!(budget.claim(None), None);
    let renewed = budget.claim(Some(0)).unwrap();
    assert_eq!(renewed.receipt, 1);
    assert_eq!(renewed.lifetime_receipt, 129,
        "failed CAS attempts and refused claims cannot consume a lifetime ordinal");
    assert_eq!(renewed.window, Some(0));
}

#[test]
fn registry_query_clock_is_optional_local_hpet_observation() {
    let file = source("main.rs");
    let helper = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "registry_query_audit_time_100ns" =>
            Some(function),
        _ => None,
    }).expect("optional HPET-only registry diagnostic clock helper");
    assert!(matches!(&helper.sig.output, syn::ReturnType::Type(_, ty)
        if matches!(&**ty, syn::Type::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "Option"))));
    let mut effects = Effects::default();
    effects.visit_item_fn(helper);
    for forbidden in ["fallback_monotonic_time_100ns", "_rdtsc", "nt_time_snapshot",
        "call_on4", "syscall", "unwrap", "expect", "format", "collect", "try_reserve"] {
        assert!(!effects.calls.iter().chain(&effects.macros).any(|call| call == forbidden),
            "diagnostic clock must not use {forbidden}");
    }
    struct HpetGuard(bool);
    impl<'ast> Visit<'ast> for HpetGuard {
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            let mut condition = Effects::default();
            condition.visit_expr(&branch.cond);
            let mut observed = Effects::default();
            observed.visit_block(&branch.then_branch);
            if observed.calls.iter().any(|call| call == "monotonic_time_100ns") {
                for flag in ["HPET_PERIOD_FS", "HPET_MONOTONIC_READY"] {
                    assert!(condition.paths.iter().any(|path| path == flag),
                        "clock observation must be guarded by {flag}");
                }
                assert!(matches!(&*branch.cond, Expr::Binary(binary)
                    if matches!(binary.op, syn::BinOp::And(_))
                    && matches!(&*binary.left, Expr::Binary(period)
                        if matches!(period.op, syn::BinOp::Ne(_))
                        && matches!(&*period.right, Expr::Lit(literal)
                            if matches!(&literal.lit, syn::Lit::Int(value)
                                if matches!(value.base10_parse::<u64>(), Ok(0)))))
                    && matches!(&*binary.right, Expr::MethodCall(ready)
                        if ready.method == "load"
                        && matches!(&*ready.receiver, Expr::Path(path)
                            if path.path.is_ident("HPET_MONOTONIC_READY")))),
                    "both HPET availability conditions must hold");
                assert!(observed.calls.iter().any(|call| call == "Some"));
                let mut unavailable = Effects::default();
                unavailable.visit_expr(&branch.else_branch.as_ref().expect("unavailable clock").1);
                assert!(unavailable.paths.iter().any(|path| path == "None"));
                assert!(!unavailable.calls.iter().any(|call| call == "monotonic_time_100ns"));
                self.0 = true;
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let mut guard = HpetGuard(false);
    guard.visit_item_fn(helper);
    assert!(guard.0, "sample the local clock only under the initialized HPET guard");
}
