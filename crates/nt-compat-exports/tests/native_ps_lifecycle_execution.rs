use syn::{visit::Visit, Expr, Item};

#[path = "../../../components/ntos-executive/src/provider_ps_lifecycle.rs"]
mod provider_ps_lifecycle;

use nt_kernel_abi::ps_reactos_x64 as abi;

#[repr(align(16))]
struct Worker([u8; abi::ETHREAD_BODY_BYTES]);

impl Worker {
    fn new() -> Self {
        let mut worker = Self([0; abi::ETHREAD_BODY_BYTES]);
        worker.0[0] = 6;
        for (offset, value) in [
            (abi::ETHREAD_CLIENT_ID_PROCESS, 36u64),
            (abi::ETHREAD_CLIENT_ID_THREAD, 40),
            (abi::ETHREAD_THREADS_PROCESS, 0x1000),
            (abi::KTHREAD_TEB, 0x8000),
        ] {
            worker.0[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        worker
    }

    fn address(&self) -> u64 {
        self.0.as_ptr() as u64
    }
}

#[test]
fn canonical_non_gui_worker_keeps_actual_teb_and_critical_region_owner() {
    let mut worker = Worker::new();
    unsafe {
        assert_eq!(provider_ps_lifecycle::validate_ps_provider_execution_thread(
            36, 40, 0x1000, worker.address(),
        ), Ok(()));
        assert_eq!(provider_ps_lifecycle::read_ps_provider_execution_teb(
            worker.address(), 0x8000,
        ), Ok(0x8000));
        assert_eq!(nt_kernel_exec::executive_sync::enter_critical_region(worker.0.as_mut_ptr()), Ok(-1));
        assert_eq!(nt_kernel_exec::executive_sync::leave_critical_region(worker.0.as_mut_ptr()), Ok(0));
    }
}

#[test]
fn canonical_execution_rejects_wrong_process_thread_or_owner() {
    let worker = Worker::new();
    for (pid, tid, process) in [(37, 40, 0x1000), (36, 41, 0x1000), (36, 40, 0x2000)] {
        assert!(unsafe { provider_ps_lifecycle::validate_ps_provider_execution_thread(
            pid, tid, process, worker.address(),
        ) }.is_err());
    }
    assert_eq!(&worker.0[abi::KTHREAD_WIN32_THREAD..abi::KTHREAD_WIN32_THREAD + 8], &[0; 8]);
}

#[test]
fn canonical_execution_rejects_a_non_thread_dispatcher_body() {
    let mut worker = Worker::new();
    for kind in [0, 3, 5] {
        worker.0[0] = kind;
        assert!(unsafe { provider_ps_lifecycle::validate_ps_provider_execution_thread(
            36, 40, 0x1000, worker.address(),
        ) }.is_err());
    }
}

#[test]
fn canonical_execution_rejects_absent_identity_and_invalid_extent_before_reads() {
    let worker = Worker::new();
    for (pid, tid, process, thread) in [
        (0, 40, 0x1000, worker.address()),
        (36, 0, 0x1000, worker.address()),
        (36, 40, 0, worker.address()),
        (36, 40, 0x1001, worker.address()),
        (36, 40, 0x1000, 0),
        (36, 40, 0x1000, worker.address() + 1),
        (36, 40, 0x1000, u64::MAX - 7),
    ] {
        assert!(unsafe { provider_ps_lifecycle::validate_ps_provider_execution_thread(
            pid, tid, process, thread,
        ) }.is_err());
    }
}

#[test]
fn non_gui_execution_teb_rejects_missing_or_mismatched_actual_teb() {
    let mut worker = Worker::new();
    for supplied in [0, 0x9000] {
        assert!(unsafe { provider_ps_lifecycle::read_ps_provider_execution_teb(
            worker.address(), supplied,
        ) }.is_err());
    }
    worker.0[abi::KTHREAD_TEB..abi::KTHREAD_TEB + 8].fill(0);
    assert!(unsafe { provider_ps_lifecycle::read_ps_provider_execution_teb(
        worker.address(), 0x8000,
    ) }.is_err());
    for thread in [0, worker.address() + 1, u64::MAX - 7] {
        assert!(unsafe { provider_ps_lifecycle::read_ps_provider_execution_teb(
            thread, 0x8000,
        ) }.is_err());
    }
}

fn source() -> syn::File {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/win32k_subsystem.rs");
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn integer(expression: &Expr, expected: u64) -> bool {
    matches!(expression, Expr::Lit(literal)
        if matches!(&literal.lit, syn::Lit::Int(value)
            if matches!(value.base10_parse::<u64>(), Ok(actual) if actual == expected)))
}

#[derive(Default)]
struct CurrentThreadStores {
    stores: usize,
    null_stores: usize,
}

impl<'ast> Visit<'ast> for CurrentThreadStores {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if matches!(&*call.func, Expr::Path(path)
            if path.path.segments.last().is_some_and(|part| part.ident == "write_volatile"))
            && call.args.len() == 2
        {
            if let Expr::Cast(cast) = &call.args[0] {
                let mut address = &*cast.expr;
                while let Expr::Paren(paren) = address {
                    address = &paren.expr;
                }
                if matches!(address, Expr::Binary(binary)
                    if matches!(&binary.op, syn::BinOp::Add(_))
                        && matches!(&*binary.left, Expr::Path(path)
                            if path.path.is_ident("WIN32K_KPCR_VA"))
                        && integer(&binary.right, 0x188))
                {
                    self.stores += 1;
                    self.null_stores += usize::from(integer(&call.args[1], 0));
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn process_exit_selection_never_discards_the_non_gui_execution_thread() {
    let file = source();
    let mut selected = false;
    let mut stores = CurrentThreadStores::default();
    for item in &file.items {
        if let Item::Fn(function) = item {
            if function.sig.ident == "select_existing_ps_provider_context"
                || function.sig.ident == "install_existing_ps_provider_process_context"
            {
                selected |= function.sig.ident == "select_existing_ps_provider_context";
                stores.visit_block(&function.block);
            }
        }
    }
    assert!(selected, "inspect the actual provider lifecycle selection boundary");
    assert!(stores.stores != 0, "lifecycle selection must install CurrentThread");
    assert_eq!(stores.null_stores, 0,
        "a process callout still executes on its canonical last worker ETHREAD even without THREADINFO");
}

#[derive(Default)]
struct SelectionOrder {
    validated: bool,
    writes_before_validation: usize,
}

impl<'ast> Visit<'ast> for SelectionOrder {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            if let Some(name) = path.path.segments.last() {
                if name.ident == "validate_ps_provider_execution_thread" {
                    assert_eq!(call.args.len(), 4);
                    for (argument, expected) in call.args.iter().zip([
                        "pid", "tid", "supplied_eprocess", "supplied_ethread",
                    ]) {
                        assert!(matches!(argument, Expr::Path(path) if path.path.is_ident(expected)),
                            "validate the exact requested {expected}");
                    }
                    self.validated = true;
                }
                if name.ident == "write_volatile" && !self.validated {
                    self.writes_before_validation += 1;
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn lifecycle_selection_validates_canonical_execution_identity_before_publication() {
    let file = source();
    let function = file.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "select_existing_ps_provider_context" => Some(function),
        _ => None,
    }).unwrap();
    let mut order = SelectionOrder::default();
    order.visit_block(&function.block);
    assert!(order.validated, "absent or stale canonical worker identity must reject before selection");
    assert_eq!(order.writes_before_validation, 0);
}

#[test]
fn executable_lifecycle_commands_enter_kernel_mode_without_a_gui_row_gate() {
    let file = source();
    let function = file.items.iter().find_map(|item| match item {
        Item::Fn(function) if function.sig.ident == "dispatch_ps_provider_command" => Some(function),
        _ => None,
    }).unwrap();
    let scope = function.block.stmts.iter().find_map(|statement| {
        let syn::Stmt::Local(local) = statement else { return None; };
        let syn::Pat::Ident(pattern) = &local.pat else { return None; };
        (pattern.ident == "_previous_mode").then_some(local.init.as_ref().unwrap())
    }).expect("lifecycle execution must own a PreviousMode scope");
    let Expr::Call(call) = &*scope.expr else {
        panic!("KernelMode scope must not depend on optional GUI thread_index.map/then");
    };
    assert!(matches!(&*call.func, Expr::Path(path)
        if path.path.segments.iter().map(|part| part.ident.to_string()).collect::<Vec<_>>()
            == ["thread_execution", "PreviousModeScope", "enter"]));
    assert!(matches!(call.args.first(), Some(Expr::Path(path))
        if path.path.segments.last().is_some_and(|part| part.ident == "KernelMode")));
}
