use syn::visit::Visit;

#[derive(Default)]
struct Calls(Vec<String>);
impl<'a> Visit<'a> for Calls {
    fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn source() -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/native_image_residency.rs");
    syn::parse_file(&std::fs::read_to_string(path).expect(
        "canonical image pages require a retained source cache, not private anonymous pages",
    ))
    .unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing canonical image lifecycle function {name}"))
}

fn calls(file: &syn::File, name: &str) -> Vec<String> {
    let function = function(file, name);
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    calls.0
}

fn residency_calls(file: &syn::File) -> Vec<String> {
    let wrapper = function(file, "service_native_image_page_residency");
    let invocation = wrapper.block.stmts.iter().find_map(|statement| {
        let syn::Stmt::Local(local) = statement else { return None; };
        let syn::Expr::Call(call) = &*local.init.as_ref()?.expr else { return None; };
        matches!(&*call.func, syn::Expr::Path(path) if path.path.is_ident("service_page_residency"))
            .then_some(call)
    }).expect("public residency wrapper must call the actual owner implementation");
    assert_eq!(invocation.args.len(), 6);
    for (argument, expected) in
        invocation
            .args
            .iter()
            .take(5)
            .zip(["handler", "view", "page", "access", "observation"])
    {
        assert!(
            matches!(argument, syn::Expr::Path(path) if path.path.is_ident(expected)),
            "residency wrapper must preserve {expected}"
        );
    }
    let wrapper_calls = calls(file, "service_native_image_page_residency");
    assert_eq!(
        wrapper_calls
            .iter()
            .filter(|call| *call == "service_page_residency")
            .count(),
        1
    );
    assert!(
        !wrapper_calls.iter().any(|call| matches!(
            call.as_str(),
            "acquire" | "ensure_source_page" | "install_view_page"
        )),
        "all borrow and mapping effects belong to the inner residency operation"
    );
    calls(file, "service_page_residency")
}

#[test]
fn canonical_image_source_fill_precedes_any_view_mapping() {
    let file = source();
    let sequence = residency_calls(&file);
    let source = sequence
        .iter()
        .position(|call| call == "ensure_source_page")
        .expect("exact area/RVA source must become resident before view effects");
    let map = sequence
        .iter()
        .position(|call| call == "install_view_page")
        .expect("view mapping must separately own copied caps");
    assert!(source < map);
    assert!(
        !sequence.iter().any(|call| call == "vm_map_private_page"),
        "shared image backing cannot be published as private anonymous ownership"
    );
}

#[test]
fn canonical_image_view_registration_is_borrowed_and_source_purge_is_acknowledged() {
    let file = source();
    let install = calls(&file, "install_view_page");
    assert!(install.iter().any(|call| call == "advance"));
    let map = file.items.iter().find_map(|item| match item {
        syn::Item::Impl(item) if matches!(&*item.self_ty, syn::Type::Path(path) if path.path.segments.last().unwrap().ident == "ViewIo") => {
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "publish" => {
                    let mut calls = Calls::default(); calls.visit_block(&method.block); Some(calls.0)
                }
                _ => None,
            })
        }
        _ => None,
    }).expect("the view journal must publish through its real backend");
    assert!(
        map.iter()
            .any(|call| call == "csrss_frame_put_section_mapping"),
        "per-view resident records must own only copied caps, not the source cache frame"
    );
    assert!(!map.iter().any(|call| call == "csrss_frame_put_at_cap"));
    let purge = calls(&file, "purge_area");
    assert!(purge.iter().any(|call| call == "begin_retirement"));
    assert!(purge.iter().any(|call| call == "advance"));
    let release = calls(&file, "release_source");
    let prepare = release
        .iter()
        .position(|call| call == "prepare")
        .expect("source cache retirement reserves checked frame recycling");
    let publish = release
        .iter()
        .position(|call| call == "publish")
        .expect("source backing must transfer only after retirement acknowledgements");
    assert!(prepare < publish);
    let revoke = release
        .iter()
        .position(|call| call == "cnode_revoke_r")
        .unwrap();
    assert!(prepare < revoke && revoke < publish);
    assert!(!purge.iter().any(|call| call == "vm_frame_release"));
}

#[test]
fn canonical_image_access_uses_current_committed_protection_not_raw_pe_flags() {
    let file = source();
    let sequence = residency_calls(&file);
    let metadata = sequence
        .iter()
        .position(|call| call == "process_committed_mapping_basic_information")
        .expect("NtProtectVirtualMemory must govern demand page access");
    let access = sequence
        .iter()
        .position(|call| call == "image_view_fault_access_status")
        .unwrap();
    let fill = sequence
        .iter()
        .position(|call| call == "ensure_source_page")
        .unwrap();
    assert!(metadata < access && access < fill);
    assert!(
        sequence.iter().any(|call| call == "is_resident"),
        "retirement rows are not usable mappings"
    );
    assert!(!sequence.iter().any(|call|call=="vm_promote_image_cow_page"||call=="vm_promote_mapped_cow_page"),
        "legacy unchecked COW cleanup cannot own canonical image installation");
}

#[test]
fn residency_failure_diagnostic_runs_after_inner_borrow_ends() {
    let file = source();
    let inner = residency_calls(&file);
    assert_eq!(inner.first().map(String::as_str), Some("acquire"));
    assert!(
        !inner.iter().any(|call| call == "trace_image_fault_failure"),
        "do not emit diagnostics while the residency owner is borrowed"
    );
    let wrapper = function(&file, "service_native_image_page_residency");
    let returned = wrapper
        .block
        .stmts
        .iter()
        .position(|statement| {
            matches!(statement, syn::Stmt::Local(local)
            if matches!(&local.pat, syn::Pat::Ident(binding) if binding.ident == "result")
            && local.init.as_ref().is_some_and(|initializer| matches!(&*initializer.expr,
                syn::Expr::Call(call) if matches!(&*call.func,
                    syn::Expr::Path(path) if path.path.is_ident("service_page_residency")))))
        })
        .expect("capture the completed inner operation before formatting evidence");
    let diagnostic = wrapper
        .block
        .stmts
        .iter()
        .enumerate()
        .find_map(|(index, statement)| {
            let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else {
                return None;
            };
            let mut calls = Calls::default();
            calls.visit_block(&branch.then_branch);
            calls
                .0
                .iter()
                .any(|call| call == "trace_image_fault_failure")
                .then_some((index, branch))
        })
        .expect("actual faults retain failure evidence");
    assert!(returned < diagnostic.0);
    assert!(
        matches!(&*diagnostic.1.cond, syn::Expr::Let(condition)
        if matches!(&*condition.pat, syn::Pat::TupleStruct(pattern) if pattern.path.is_ident("Err"))
        && matches!(&*condition.expr, syn::Expr::Path(path) if path.path.is_ident("result"))),
        "successful residency must not emit failure evidence"
    );
    let fault_guarded = diagnostic.1.then_branch.stmts.iter().any(|statement| {
        let syn::Stmt::Expr(syn::Expr::If(branch), _) = statement else {
            return false;
        };
        let mut calls = Calls::default();
        calls.visit_block(&branch.then_branch);
        matches!(&*branch.cond, syn::Expr::Binary(condition)
            if matches!(condition.op, syn::BinOp::Ne(_))
            && matches!(&*condition.left, syn::Expr::Path(path)
                if path.path.is_ident("observation"))
            && matches!(&*condition.right, syn::Expr::Path(path)
                if path.path.segments.len() == 2
                && path.path.segments[0].ident == "ImageFaultObservation"
                && path.path.segments[1].ident == "CopyAccess"))
            && calls
                .0
                .iter()
                .any(|call| call == "trace_image_fault_failure")
    });
    assert!(
        fault_guarded,
        "ordinary memory-copy refusals are not hardware fault diagnostics"
    );
    assert!(
        matches!(wrapper.block.stmts.last(), Some(syn::Stmt::Expr(syn::Expr::Path(path), None))
        if path.path.is_ident("result")),
        "diagnostics must preserve the original residency result"
    );
}

#[test]
fn source_cache_preserves_master_cap_outside_per_view_registry() {
    let file = source();
    struct Publication(bool);
    impl<'a> Visit<'a> for Publication {
        fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
            if matches!(&*call.func,syn::Expr::Path(path) if path.path.segments.last().unwrap().ident=="csrss_frame_put_section_mapping")
            {
                assert_eq!(call.args.len(), 5);
                assert!(
                    matches!(&call.args[3],syn::Expr::Field(field) if matches!(&field.member,syn::Member::Named(ident) if ident=="cap") && matches!(&*field.base,syn::Expr::Path(path) if path.path.is_ident("destination")))
                );
                assert!(
                    matches!(&call.args[4],syn::Expr::Lit(lit) if matches!(&lit.lit,syn::Lit::Int(value) if value.base10_parse::<u64>().unwrap()==0)),
                    "the source cache master must not become a per-view source_cap"
                );
                self.0 = true;
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut publication = Publication(false);
    publication.visit_file(&file);
    assert!(publication.0);
}

#[test]
fn source_purge_resumes_exact_retained_retirement_without_refilling() {
    let file = source();
    let sequence = calls(&file, "purge_area");
    let retiring = sequence
        .iter()
        .position(|call| call == "is_retiring")
        .expect("retained initialization-failure cleanup is not a Ready cache entry");
    let ready = sequence
        .iter()
        .position(|call| call == "ready_frame")
        .unwrap();
    assert!(
        retiring < ready,
        "resume known retained retirement before requiring Ready backing"
    );
    assert!(!sequence.iter().any(|call| call == "ensure_source_page"));
    struct FrameAcquisition(bool);
    impl<'a> Visit<'a> for FrameAcquisition {
        fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                let parts: Vec<_> = path
                    .path
                    .segments
                    .iter()
                    .map(|part| part.ident.to_string())
                    .collect();
                self.0 |= parts.ends_with(&["frame_acquisition".into(), "acquire".into()]);
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let purge = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "purge_area" => Some(function),
            _ => None,
        })
        .unwrap();
    let mut acquisition = FrameAcquisition(false);
    acquisition.visit_block(&purge.block);
    assert!(
        !acquisition.0,
        "purge must not acquire another frame; Borrow::acquire only serializes its owner"
    );

    let backend=file.items.iter().find_map(|item|match item {
        syn::Item::Impl(item) if item.trait_.is_some() && matches!(&*item.self_ty,syn::Type::Path(path) if path.path.segments.last().unwrap().ident=="PurgeIo")=>Some(item),
        _=>None,
    }).expect("purge must use its refusal-only acquisition/initializer backend");
    for (name, refusal) in [("acquire", "Err"), ("initialize", "Refused")] {
        let method = backend
            .items
            .iter()
            .find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                _ => None,
            })
            .unwrap();
        assert_eq!(
            method.block.stmts.len(),
            1,
            "{name} must have no preceding resource effects"
        );
        let mut calls = Calls::default();
        calls.visit_block(&method.block);
        assert_eq!(
            calls.0,
            [refusal],
            "purge {name} must explicitly refuse, never initialize or allocate"
        );
    }
}
