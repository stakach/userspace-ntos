//! Execute the actual Section paging statements with host ports, not a duplicate policy.
use std::process::Command;
use syn::visit::Visit;

#[test]
fn cow_and_native_selftests_preserve_access_before_the_shared_pager() {
    let source = include_str!("../../../components/ntos-executive/src/main.rs");
    assert!(
        !source.contains("vm_ensure_private_pt"),
        "obsolete allocation-window wrapper must be removed"
    );
    assert!(
        !include_str!("../../../components/ntos-executive/src/service_sec_image.rs")
            .contains("vm_ensure_private_pt")
    );
    let parsed = syn::parse_file(source).unwrap();
    for name in [
        "mapped_section_writecopy_cow_selftest",
        "image_writecopy_cow_selftest",
        "vm_promote_mapped_cow_page",
    ] {
        let function = parsed
            .items
            .iter()
            .find_map(|item| match item {
                syn::Item::Fn(function) if function.sig.ident == name => Some(function),
                _ => None,
            })
            .expect("actual COW and selftest functions");
        struct CheckedPager(usize);
        impl<'ast> Visit<'ast> for CheckedPager {
            fn visit_expr_method_call(&mut self, expression: &'ast syn::ExprMethodCall) {
                if expression.method == "and_then" {
                    if let syn::Expr::Call(access) = &*expression.receiver {
                        if matches!(&*access.func, syn::Expr::Path(path) if path.path.is_ident("hosted_thread_memory_access"))
                        {
                            if let Some(syn::Expr::Closure(closure)) = expression.args.first() {
                                if let syn::Expr::Call(pager) = &*closure.body {
                                    if matches!(&*pager.func, syn::Expr::Path(path) if path.path.is_ident("ensure_process_user_page_table"))
                                    {
                                        self.0 += 1;
                                    }
                                }
                            }
                        }
                    }
                }
                syn::visit::visit_expr_method_call(self, expression);
            }
        }
        let mut checked = CheckedPager(0);
        checked.visit_block(&function.block);
        assert_eq!(
            checked.0, 1,
            "{name} must preserve access refusal before paging effects"
        );
    }
}

#[test]
fn actual_private_paging_helper_accepts_low_committed_destinations_and_preserves_refusals() {
    let main = include_str!("../../../components/ntos-executive/src/main.rs");
    let source = include_str!("../../../components/ntos-executive/src/service_sec_image.rs");
    let fault = source
        .find("pub(crate) unsafe fn service_generic_section_fault(")
        .unwrap();
    let start = source[fault..]
        .find("hosted_thread_memory_access(pi as u64, page, nt_address_space::PAGE_SIZE)?;")
        .map(|offset| fault + offset)
        .expect("actual Section pre-pager access check");
    let end = source[start..]
        .find("if fault_plan.mark_dirty")
        .map(|offset| start + offset)
        .expect("next native Section publication phase");
    let statements = &source[start..end];
    let helper = format!("unsafe fn section_pager(nt_handler: &mut ExecNtHandler, pi: usize, page: u64, pml4: u64) -> Result<(),u32> {{ {statements} Ok(()) }}");
    syn::parse_str::<syn::ItemFn>(&helper).expect("extract the actual native paging statements");
    let constants = ["SMSS_ALLOC_VA", "PRIVATE_VM_LIMIT"]
        .map(|name| {
            main.lines()
                .find(|line| line.starts_with(&format!("pub const {name}:")))
                .expect("actual native constant")
        })
        .join("\n");
    let harness = format!("{constants}\n{PORTS}\n{helper}\n{CASES}");
    let directory =
        std::env::temp_dir().join(format!("nt-private-paging-helper-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let input = directory.join("helper.rs");
    let binary = directory.join("helper-tests");
    std::fs::write(&input, harness).unwrap();
    let compile = Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
        .args(["--edition=2021", "--test"])
        .arg(&input)
        .arg("-o")
        .arg(&binary)
        .output()
        .expect("host compiler for actual native helper");
    assert!(
        compile.status.success(),
        "helper harness must compile before behavioral assertions: {}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run = Command::new(&binary).arg("--nocapture").output().unwrap();
    let _ = std::fs::remove_dir_all(&directory);
    assert!(
        run.status.success(),
        "actual native helper behavioral failures:\n{}\n{}",
        String::from_utf8_lossy(&run.stdout),
        String::from_utf8_lossy(&run.stderr)
    );
}

const PORTS: &str = r#"
mod nt_address_space {
    pub const PAGE_SIZE: u64 = 4096;
    pub const STATUS_CONFLICTING_ADDRESSES: u32 = 0xc0000018;
}
use std::cell::RefCell;
thread_local! { static ACCESS: RefCell<(u32, Vec<(u64,u64,u64)>)> = RefCell::new((0, Vec::new())); }
#[derive(Default)]
struct ExecNtHandler { pager_error: u32, calls: Vec<(usize,u64,u64)> }
fn hosted_thread_memory_access(pi: u64, page: u64, size: u64) -> Result<(),u32> {
    ACCESS.with(|state| {
        let mut state = state.borrow_mut();
        state.1.push((pi,page,size));
        if state.0 == 0 { Ok(()) } else { Err(state.0) }
    })
}
unsafe fn ensure_process_user_page_table(handler: &mut ExecNtHandler, pi: usize, page: u64, root: u64) -> Result<u64,u32> {
    handler.calls.push((pi,page,root));
    if handler.pager_error == 0 { Ok(900) } else { Err(handler.pager_error) }
}
fn reset(error: u32) { ACCESS.with(|state| *state.borrow_mut() = (error, Vec::new())); }
fn access_calls() -> Vec<(u64,u64,u64)> { ACCESS.with(|state| state.borrow().1.clone()) }
"#;

const CASES: &str = r#"
#[test]
fn low_committed_destination_reaches_exact_pager() {
    reset(0);
    let mut handler = ExecNtHandler::default();
    assert_eq!(unsafe { section_pager(&mut handler, 15, 0x50000000, 0x327cb) }, Ok(()));
    assert_eq!(access_calls(), [(15,0x50000000,4096)]);
    assert_eq!(handler.calls, [(15,0x50000000,0x327cb)]);
}
#[test]
fn high_destination_keeps_existing_behavior() {
    reset(0);
    let mut handler = ExecNtHandler::default();
    assert_eq!(unsafe { section_pager(&mut handler, 15, SMSS_ALLOC_VA, 123) }, Ok(()));
    assert_eq!(handler.calls, [(15,SMSS_ALLOC_VA,123)]);
}
#[test]
fn access_refusal_precedes_pager_effect() {
    reset(0xc0000005);
    let mut handler = ExecNtHandler::default();
    assert_eq!(unsafe { section_pager(&mut handler, 15, 0x50000000, 123) }, Err(0xc0000005));
    assert_eq!(access_calls(), [(15,0x50000000,4096)]);
    assert!(handler.calls.is_empty());
}
#[test]
fn actual_pager_refusal_is_not_replaced_by_placement_policy() {
    reset(0);
    let mut handler = ExecNtHandler { pager_error: 0xc000009a, ..Default::default() };
    assert_eq!(unsafe { section_pager(&mut handler, 15, SMSS_ALLOC_VA, 123) }, Err(0xc000009a));
    assert_eq!(handler.calls, [(15,SMSS_ALLOC_VA,123)]);
}
"#;
