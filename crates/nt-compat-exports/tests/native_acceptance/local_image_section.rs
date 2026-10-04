use syn::{visit::Visit, Expr, Pat};

fn image_section_arm() -> syn::Arm {
    struct Arm(Option<syn::Arm>);
    impl<'ast> Visit<'ast> for Arm {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if matches!(&arm.pat, Pat::Path(path)
                if path.path.segments.last().is_some_and(|segment| segment.ident == "NtCreateSection"))
            {
                self.0 = Some(arm.clone());
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let source = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_handler.rs"
    )).unwrap();
    let mut arm = Arm(None);
    arm.visit_file(&source);
    arm.0.expect("actual NtCreateSection service arm")
}

#[derive(Default)]
struct LocalImageAdmission {
    disk: bool,
    overlay: bool,
    admitted_source: bool,
}

#[derive(Default)]
struct OrderedCalls(Vec<String>);

impl<'ast> Visit<'ast> for OrderedCalls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn section_creation_validates_scalar_contract_before_user_capture() {
    let mut calls = OrderedCalls::default();
    calls.visit_arm(&image_section_arm());
    let validation = calls.0.iter().position(|name| name == "validate_section_creation_parameters")
        .expect("public section creation must validate allocation attributes and page protection before probing pointers");
    for capture in ["probe_copy_scalar", "process_memory_read_status", "lookup_native_section_file_source",
        "capture_named_object_attributes"] {
        let capture = calls.0.iter().position(|name| name == capture).expect(capture);
        assert!(validation < capture, "scalar rejection must precede pointer or File capture");
    }
}

#[test]
fn section_output_probe_precedes_maximum_size_file_and_object_attributes_capture() {
    let mut calls = OrderedCalls::default();
    calls.visit_arm(&image_section_arm());
    let probe = calls.0.iter().position(|name| name == "probe_copy_scalar")
        .expect("public SectionHandle output probe");
    for capture in ["process_memory_read_status", "lookup_native_section_file_source", "capture_named_object_attributes"] {
        let capture = calls.0.iter().position(|name| name == capture).expect(capture);
        assert!(probe < capture,
            "NT5 probes SectionHandle before MaximumSize and before File/ObjectAttributes resolution");
    }
    let full_protection = calls.0.iter().position(|name| name == "data_section_file_access")
        .expect("full protection mask validation after public pointer probes");
    let maximum_size = calls.0.iter().position(|name| name == "process_memory_read_status").unwrap();
    let file = calls.0.iter().position(|name| name == "lookup_native_section_file_source").unwrap();
    assert!(maximum_size < full_protection && full_protection < file,
        "MmCreateSection validates the full protection before resolving File authority, not before public probes");
}

impl<'ast> Visit<'ast> for LocalImageAdmission {
    fn visit_pat_struct(&mut self, pattern: &'ast syn::PatStruct) {
        self.disk |= pattern.path.segments.last().is_some_and(|segment| segment.ident == "DiskFile");
        syn::visit::visit_pat_struct(self, pattern);
    }

    fn visit_pat_tuple_struct(&mut self, pattern: &'ast syn::PatTupleStruct) {
        self.overlay |= pattern.path.segments.last().is_some_and(|segment| segment.ident == "OverlayFile");
        syn::visit::visit_pat_tuple_struct(self, pattern);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if matches!(&*call.func, Expr::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "submit_local_image_section"))
        {
            self.admitted_source |= call.args.iter().any(|argument| {
                matches!(argument, Expr::Path(path) if path.path.is_ident("source"))
            });
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "submit_local_image_section" {
            self.admitted_source |= call.args.iter().any(|argument| {
                matches!(argument, Expr::Path(path) if path.path.is_ident("source"))
            });
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn sec_image_admits_exact_local_file_source_not_only_preloaded_boot_images() {
    let mut admission = LocalImageAdmission::default();
    admission.visit_arm(&image_section_arm());
    assert!(admission.disk && admission.overlay,
        "SEC_IMAGE must admit canonical DiskFile/OverlayFile sources, not reject ordinary installed executables outside the boot image catalog");
    assert!(admission.admitted_source,
        "local image admission must receive the exact native File source, not a guessed executable leaf or creator boot role");
}

#[test]
fn local_image_capture_retains_exact_file_and_reads_full_extent_before_publication() {
    struct Capture {
        calls: Vec<String>,
        full_extent: bool,
        exact_count: bool,
    }
    impl<'ast> Visit<'ast> for Capture {
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
        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            self.full_extent |= matches!(&field.member, syn::Member::Named(name) if name == "file_extent")
                && matches!(&*field.base, Expr::Path(path) if path.path.is_ident("backing"));
            syn::visit::visit_expr_field(self, field);
        }
        fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
            self.exact_count |= matches!(binary.op, syn::BinOp::Ne(_))
                && matches!(&*binary.left, Expr::Path(path) if path.path.is_ident("copied"))
                && matches!(&*binary.right, Expr::Path(path) if path.path.is_ident("length"));
            syn::visit::visit_expr_binary(self, binary);
        }
    }
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/file_image_section.rs");
    let source = syn::parse_file(&std::fs::read_to_string(path).expect("local image capture module"))
        .unwrap();
    let function = source.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "submit_local_image_section" => Some(function),
        _ => None,
    }).expect("actual local image capture function");
    let mut capture = Capture { calls: Vec::new(), full_extent: false, exact_count: false };
    capture.visit_block(&function.block);
    let position = |name: &str| capture.calls.iter().position(|call| call == name).unwrap();
    assert!(capture.full_extent && capture.exact_count,
        "capture must check the complete canonical File extent, not just a PE header prefix");
    assert!(position("retain_io") < position("fat_read_file_range"));
    assert!(position("retain_io_reference") < position("read_backing_into"));
    assert!(position("check_data_section_file_access") < position("retain_io"));
    assert!(position("check_data_section_file_access") < position("retain_io_reference"));
    assert!(position("probe_copy_scalar") < position("retain_io"));
    assert!(position("probe_copy_scalar") < position("retain_io_reference"));
    assert!(position("fat_read_file_range") < position("reserve_local_native_image_section"));
    assert!(position("read_backing_into") < position("reserve_local_native_image_section"));
    assert!(!capture.calls.iter().any(|call| matches!(call.as_str(), "admit_dynamic_hosted_exe" | "load_fat")),
        "canonical image capture must not reopen by leaf or depend on boot role");
}

#[test]
fn cached_local_image_acquires_exact_area_before_snapshot_and_transfers_reservation() {
    let source = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/file_image_section.rs"
    )).unwrap();
    let function = source.items.iter().find_map(|item| match item {
        syn::Item::Fn(function) if function.sig.ident == "submit_local_image_section" => Some(function),
        _ => None,
    }).expect("actual local image admission");
    #[derive(Default)]
    struct Reservation {
        calls: Vec<String>,
        exact_area: bool,
        capture_gated: bool,
        transferred: bool,
        abort_pending_only: bool,
    }
    impl<'ast> Visit<'ast> for Reservation {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.calls.push(call.method.to_string());
            if call.method == "reserve" {
                self.exact_area |= matches!(&*call.receiver, Expr::Field(field)
                    if matches!(&field.member, syn::Member::Named(name) if name == "image_sections"));
            }
            if call.method == "reserve_local_native_image_section" {
                self.transferred |= call.args.iter().any(|argument| matches!(argument,
                    Expr::Reference(reference) if reference.mutability.is_some()
                        && matches!(&*reference.expr, Expr::Path(path) if path.path.is_ident("image"))));
            }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let Expr::Path(path) = &*call.func {
                self.calls.push(path.path.segments.last().unwrap().ident.to_string());
            }
            syn::visit::visit_expr_call(self, call);
        }
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            let mut condition = OrderedCalls::default();
            condition.visit_expr(&branch.cond);
            let mut effects = OrderedCalls::default();
            effects.visit_block(&branch.then_branch);
            self.abort_pending_only |= matches!(&*branch.cond, Expr::Binary(binary)
                if matches!(binary.op, syn::BinOp::And(_)))
                && condition.0.iter().any(|call| call == "is_err")
                && condition.0.iter().any(|call| call == "is_pending")
                && effects.0.iter().any(|call| call == "abort");
            if matches!(&*branch.cond, Expr::MethodCall(call) if call.method == "needs_source"
                && matches!(&*call.receiver, Expr::Path(path) if path.path.is_ident("image"))) {
                let mut calls = OrderedCalls::default();
                calls.visit_block(&branch.then_branch);
                self.capture_gated |= ["retain_io", "retain_io_reference", "try_reserve_exact",
                    "fat_read_file_range", "read_backing_into"].iter()
                    .all(|required| calls.0.iter().any(|call| call == required));
            }
            syn::visit::visit_expr_if(self, branch);
        }
    }
    let mut reservation = Reservation::default();
    reservation.visit_block(&function.block);
    assert!(reservation.exact_area,
        "local admission must acquire the exact canonical image area before allocating a duplicate EOF snapshot");
    let position = |name: &str| reservation.calls.iter().position(|call| call == name).expect(name);
    for effect in ["retain_io", "retain_io_reference", "fat_read_file_range", "read_backing_into"] {
        assert!(position("reserve") < position(effect), "area acquisition precedes {effect}");
    }
    assert!(reservation.capture_gated,
        "only a new-area reservation may retain File IO and allocate/read the complete snapshot");
    assert!(reservation.transferred,
        "publication must receive the same held image reservation, not reacquire after capture");
    assert!(reservation.abort_pending_only,
        "local rollback aborts an acquisition only on failure while its token remains pending");

    let publication = syn::parse_file(include_str!(
        "../../../../components/ntos-executive/src/exec_image_section_create.rs"
    )).unwrap();
    struct CommonPublication(bool);
    #[derive(Default)]
    struct AreaAcquisition(bool);
    impl<'ast> Visit<'ast> for AreaAcquisition {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0 |= call.method == "reserve"
                && matches!(&*call.receiver, Expr::Field(field)
                    if matches!(&field.member, syn::Member::Named(name) if name == "image_sections"));
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    impl<'ast> Visit<'ast> for CommonPublication {
        fn visit_impl_item_fn(&mut self, method: &'ast syn::ImplItemFn) {
            if method.sig.ident == "reserve_image_section" {
                let mut acquisition = AreaAcquisition::default();
                acquisition.visit_block(&method.block);
                assert!(!acquisition.0,
                    "common publication consumes the admitted reservation without acquiring another area reference");
                let mut calls = OrderedCalls::default();
                calls.visit_block(&method.block);
                assert!(calls.0.iter().any(|call| call == "cached_source_for_reservation"),
                    "existing-area publication validates the source through the held reservation");
                self.0 = true;
            }
            syn::visit::visit_impl_item_fn(self, method);
        }
    }
    let mut common = CommonPublication(false);
    common.visit_file(&publication);
    assert!(common.0, "actual shared image publication boundary");
}
