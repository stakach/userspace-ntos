use syn::{visit::Visit, Expr, Item, Stmt};

#[test]
fn callback_crash_observer_does_not_infer_fixed_role_clientinfo_backing() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/win32k_glue.rs"
    )).unwrap();
    let observer = source.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "dump_client_callback_crash_state" => Some(function),
        _ => None,
    }).expect("actual callback fault identity and register diagnostic remains");
    #[derive(Default)]
    struct Contract { fixed_mirrors: usize, raw_reads: usize, saved_rip: usize, callback_requests: usize }
    impl<'ast> Visit<'ast> for Contract {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            if let Some(segment) = path.path.segments.last() {
                self.fixed_mirrors += usize::from(segment.ident == "WINLOGON_MAIN_TEB_MIRROR_VA");
                self.saved_rip += usize::from(segment.ident == "USER_CONTEXT_RIP");
            }
            syn::visit::visit_expr_path(self, path);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            self.raw_reads += usize::from(called_name(call).as_deref() == Some("read_volatile"));
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.callback_requests += usize::from(call.method == "request");
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut contract = Contract::default();
    contract.visit_item_fn(observer);
    assert_eq!(contract.fixed_mirrors, 0, "numeric client role is not authority for a TEB mapping");
    assert_eq!(contract.raw_reads, 0, "historical CLIENTINFO snapshots must not fault crash reporting");
    assert!(contract.saved_rip >= 1, "retain actual saved fault registers");
    assert!(contract.callback_requests >= 1, "retain exact active callback metadata");
}

#[test]
fn quiescent_boot_observers_do_not_inspect_obsolete_fixed_winlogon_teb_mirrors() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/main.rs"
    )).unwrap();
    let obsolete = ["activation_context_stack_spec", "teb_tail_snapshot_diagnostic"];
    #[derive(Default)]
    struct Observations { obsolete_calls: usize, fixed_mirrors: usize, raw_reads: usize, counters: Vec<String> }
    impl<'ast> Visit<'ast> for Observations {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            match called_name(call).as_deref() {
                Some("activation_context_stack_spec" | "teb_tail_snapshot_diagnostic") => self.obsolete_calls += 1,
                Some("read_volatile") => self.raw_reads += 1,
                _ => {}
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            if let Some(name) = path.path.segments.last() {
                let name = name.ident.to_string();
                self.fixed_mirrors += usize::from(name == "WINLOGON_MAIN_TEB_MIRROR_VA");
                self.counters.push(name);
            }
            syn::visit::visit_expr_path(self, path);
        }
    }
    let mut calls = Observations::default();
    calls.visit_file(&source);
    assert_eq!(calls.obsolete_calls, 0, "obsolete static-role observations cannot fault boot verdict evaluation");
    for item in &source.items {
        if let Item::Fn(function) = item {
            assert!(!obsolete.iter().any(|name| function.sig.ident == *name),
                "do not retain dormant fixed-role initial-state diagnostics");
        }
    }
    let gdi = source.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "gdi_user_batch_flush_spec" => Some(function),
        _ => None,
    }).expect("real runtime GDI batch measurement remains");
    let mut observed = Observations::default();
    observed.visit_block(&gdi.block);
    assert_eq!(observed.fixed_mirrors, 0, "runtime batch measurement cannot infer a named process TEB alias");
    assert_eq!(observed.raw_reads, 0, "the boot gate is counters, not unowned client memory reads");
    for counter in ["GDI_BATCH_FLUSHES", "GDI_BATCH_RECORDS_FLUSHED", "GDI_BATCH_FLUSH_FAILURES", "GDI_BATCH_MAX_OFFSET"] {
        assert!(observed.counters.iter().any(|name| name == counter), "retain actual runtime measurement {counter}");
    }
}

fn called_name(call: &syn::ExprCall) -> Option<String> {
    let Expr::Path(path) = &*call.func else { return None };
    path.path.segments.last().map(|segment| segment.ident.to_string())
}

#[derive(Default)]
struct ScanContract {
    old_reads: usize,
    checked_reads: usize,
    unavailable_stops: usize,
}

impl<'ast> Visit<'ast> for ScanContract {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        match called_name(call).as_deref() {
            Some("smss_stack_read") => self.old_reads += 1,
            Some("read_fault_stack_word") => self.checked_reads += 1,
            _ => {}
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_stmt(&mut self, statement: &'ast Stmt) {
        if let Stmt::Local(local) = statement {
            if let Some(initializer) = &local.init {
                if matches!(&*initializer.expr, Expr::Call(call)
                    if called_name(call).as_deref() == Some("read_fault_stack_word"))
                {
                    let Some((_, unavailable)) = &initializer.diverge else {
                        panic!("unavailable diagnostic words must stop, not become zero bytes");
                    };
                    #[derive(Default)]
                    struct Stop(bool);
                    impl<'ast> Visit<'ast> for Stop {
                        fn visit_expr_break(&mut self, _: &'ast syn::ExprBreak) { self.0 = true; }
                    }
                    let mut stop = Stop::default();
                    stop.visit_expr(unavailable);
                    assert!(stop.0, "the first unavailable word terminates the diagnostic walk");
                    self.unavailable_stops += 1;
                }
            }
        }
        syn::visit::visit_stmt(self, statement);
    }
}

#[derive(Default)]
struct InstructionFetchScans(Vec<ScanContract>);

impl<'ast> Visit<'ast> for InstructionFetchScans {
    fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
        let instruction_fetch = matches!(&*branch.cond,
            Expr::Binary(binary) if matches!(binary.op, syn::BinOp::Eq(_))
                && matches!(&*binary.left, Expr::Path(path) if path.path.is_ident("m0"))
                && matches!(&*binary.right, Expr::Path(path) if path.path.is_ident("addr")));
        if instruction_fetch {
            let mut scans = ScanContract::default();
            scans.visit_block(&branch.then_branch);
            if scans.old_reads != 0 || scans.checked_reads != 0 {
                self.0.push(scans);
            }
        }
        syn::visit::visit_expr_if(self, branch);
    }
}

#[test]
fn instruction_fetch_fault_scans_stop_on_unavailable_authenticated_words() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/service_sec_image.rs"
    )).unwrap();
    let mut scans = InstructionFetchScans::default();
    scans.visit_file(&source);
    assert_eq!(scans.0.len(), 1, "identify the actual fault instruction-fetch diagnostic");
    let scans = &scans.0[0];
    assert_eq!(scans.old_reads, 0, "broad arithmetic mirror reads can fault the executive beyond the resident stack");
    assert_eq!(scans.checked_reads, 2, "both top-of-stack and return-address scans use the focused reader");
    assert_eq!(scans.unavailable_stops, 2);
}

#[test]
fn fault_stack_reader_uses_exact_resident_process_backing_without_mirror_or_image_fallback() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/fault_stack_diagnostics.rs");
    let source = std::fs::read_to_string(path).expect("focused fallible fault-stack diagnostic reader");
    let source = syn::parse_file(&source).unwrap();
    let reader = source.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "read_fault_stack_word" => Some(function),
        _ => None,
    }).expect("diagnostic word reader");
    #[derive(Default)]
    struct Contract { mapped: usize, identity: usize, checked_add: usize, checked_mul: usize }
    impl<'ast> Visit<'ast> for Contract {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            match called_name(call).as_deref() {
                Some("client_copyin_process_mapped_for") => {
                    assert_eq!(call.args.len(), 5, "no obsolete mirror-authority or fill-order arguments");
                    assert!(matches!(call.args.first(), Some(Expr::Cast(cast))
                        if matches!(&*cast.expr, Expr::Path(path) if path.path.is_ident("pi"))),
                        "exact target PI");
                    for (index, expected) in [(1, "process"), (2, "address"), (4, "scratch_base")] {
                        assert!(matches!(call.args.iter().nth(index), Some(Expr::Path(path))
                            if path.path.is_ident(expected)), "retained {expected} argument");
                    }
                    assert!(matches!(call.args.iter().nth(3), Some(Expr::Reference(reference))
                        if reference.mutability.is_some()
                            && matches!(&*reference.expr, Expr::Path(path) if path.path.is_ident("bytes"))),
                        "bounded local word destination");
                    self.mapped += 1;
                }
                Some("smss_stack_read" | "smss_copyin" | "smss_mirror" | "client_copyin_mapped") => {
                    panic!("fault diagnostic cannot select an unchecked active-client memory path");
                }
                _ => {}
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            match call.method.to_string().as_str() {
                "capture_process_identity" => self.identity += 1,
                "checked_add" => self.checked_add += 1,
                "checked_mul" => self.checked_mul += 1,
                "xas_read" => panic!("backing PE content is not a resident stack word"),
                _ => {}
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut contract = Contract::default();
    contract.visit_item_fn(reader);
    assert_eq!(contract.mapped, 1);
    assert!(contract.identity >= 1, "revalidate the captured process generation before reading");
    assert!(contract.checked_add >= 1 && contract.checked_mul >= 1, "word addresses must reject overflow");
}
