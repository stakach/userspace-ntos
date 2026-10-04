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

fn calls(file: &syn::File, name: &str) -> Vec<String> {
    let function = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing canonical image lifecycle function {name}"));
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    calls.0
}

#[test]
fn canonical_image_source_fill_precedes_any_view_mapping() {
    let file = source();
    let sequence = calls(&file, "service_native_image_page_residency");
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
    let sequence = calls(&file, "service_native_image_page_residency");
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
