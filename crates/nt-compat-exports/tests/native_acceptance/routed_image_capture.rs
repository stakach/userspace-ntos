use syn::{visit::Visit, Expr, Item, Pat};

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src").join(name);
    syn::parse_file(&std::fs::read_to_string(path).expect("routed image source module")).unwrap()
}

fn phase(name: &str) -> syn::Arm {
    struct Phase<'a> { name: &'a str, arm: Option<syn::Arm> }
    impl<'ast> Visit<'ast> for Phase<'_> {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            let path = match &arm.pat {
                Pat::Path(path) => Some(&path.path),
                Pat::Struct(value) => Some(&value.path),
                _ => None,
            };
            if path.is_some_and(|path| path.segments.last().unwrap().ident == self.name) {
                self.arm = Some(arm.clone());
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let file = source("section_metadata_work.rs");
    let advance = file.items.iter().find_map(|item| match item {
        Item::Fn(value) if value.sig.ident == "advance" => Some(value), _ => None,
    }).expect("actual retained metadata advance");
    let mut selected = Phase { name, arm: None };
    selected.visit_block(&advance.block);
    selected.arm.expect("retained image capture phase")
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
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

#[derive(Default)]
struct Extent { eof: bool, captured: bool, equality: bool }
impl<'ast> Visit<'ast> for Extent {
    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        self.eof |= matches!(&field.member, syn::Member::Named(name) if name == "end_of_file");
        self.captured |= matches!(&field.member, syn::Member::Named(name) if name == "image_header");
        syn::visit::visit_expr_field(self, field);
    }
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.captured |= path.path.is_ident("offset");
        syn::visit::visit_expr_path(self, path);
    }
    fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
        self.equality |= matches!(binary.op, syn::BinOp::Eq(_));
        syn::visit::visit_expr_binary(self, binary);
    }
}

#[test]
fn routed_image_publishes_only_after_exact_eof_not_first_parseable_header() {
    struct Publication { exact: bool, guarded: bool, count: usize }
    impl<'ast> Visit<'ast> for Publication {
        fn visit_expr_if(&mut self, branch: &'ast syn::ExprIf) {
            let mut extent = Extent::default();
            extent.visit_expr(&branch.cond);
            let previous = self.exact;
            self.exact |= extent.eof && extent.captured && extent.equality;
            self.visit_block(&branch.then_branch);
            self.exact = previous;
            if let Some((_, alternate)) = &branch.else_branch { self.visit_expr(alternate); }
        }
        fn visit_expr_assign(&mut self, assign: &'ast syn::ExprAssign) {
            if matches!(&*assign.right, Expr::Path(path)
                if path.path.segments.last().unwrap().ident == "Publish") {
                self.count += 1;
                self.guarded &= self.exact;
            }
            syn::visit::visit_expr_assign(self, assign);
        }
    }
    let mut publication = Publication { exact: false, guarded: true, count: 0 };
    publication.visit_arm(&phase("HeaderDispatch"));
    assert!(publication.count != 0 && publication.guarded,
        "parseable headers are not a process image snapshot: retained capture must reach exact canonical EOF before Publish");
    let mut calls = Calls::default();
    calls.visit_arm(&phase("HeaderDispatch"));
    let reserve = calls.0.iter().position(|name| name == "reserve_file_snapshot_capacity")
        .expect("fallible capture storage admission remains required");
    let read = calls.0.iter().position(|name| name == "build_and_dispatch_external_to_device")
        .expect("exact retained File read");
    assert!(reserve < read, "storage admission precedes any provider read effect");
    assert!(calls.0.iter().any(|name| name == "build_and_dispatch_external_to_device"), "capture reads the exact retained File through its driver");
}

#[test]
fn full_image_capture_keeps_exact_pending_identity_and_ack_before_next_read() {
    struct Fields(Vec<String>);
    impl<'ast> Visit<'ast> for Fields {
        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            if let syn::Member::Named(name) = &field.member { self.0.push(name.to_string()); }
            syn::visit::visit_expr_field(self, field);
        }
    }
    let mut fields = Fields(Vec::new());
    fields.visit_arm(&phase("HeaderPending"));
    for identity in ["client_id", "driver_id", "file_id", "device_id", "requestor_tid", "major", "information"] {
        assert!(fields.0.iter().any(|field| field == identity), "pending full-image read retains exact {identity}");
    }
    let mut calls = Calls::default();
    calls.visit_arm(&phase("HeaderCopying"));
    assert!(calls.0.iter().any(|name| name == "copy_completed_irp_output_exact"));
    calls.0.clear();
    calls.visit_arm(&phase("HeaderAckPending"));
    assert!(calls.0.iter().any(|name| name == "acknowledge_completed_irp_strict"));
}

#[test]
fn process_bridge_accepts_complete_routed_source_not_a_local_marker() {
    let file = source("exec_image_process_create.rs");
    let method = file.items.iter().find_map(|item| match item {
        Item::Impl(value) => value.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(value) if value.sig.ident == "reserve_native_image_process" => Some(value), _ => None,
        }), _ => None,
    }).expect("exact image process bridge");
    let mut calls = Calls::default();
    calls.visit_block(&method.block);
    assert!(calls.0.iter().any(|name| name == "has_complete_image"),
        "process construction requires exact complete source bytes, independent of local/routed backing");
    struct LocalMarker(bool);
    impl<'ast> Visit<'ast> for LocalMarker {
        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            self.0 |= matches!(&field.member, syn::Member::Named(name) if name == "local_file");
            syn::visit::visit_expr_field(self, field);
        }
    }
    let mut marker = LocalMarker(false);
    marker.visit_block(&method.block);
    assert!(!marker.0, "canonical source kind is not an executable admission allowlist");
}

#[test]
fn routed_image_display_path_is_owned_from_the_same_retained_file() {
    struct PathCapture { exact: bool, retained: bool }
    impl<'ast> Visit<'ast> for PathCapture {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if call.method == "owned_image_path" {
                self.exact |= matches!(&*call.receiver, Expr::Path(path) if path.path.is_ident("capture"));
            }
            syn::visit::visit_expr_method_call(self, call);
        }
        fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
            if value.path.segments.last().unwrap().ident == "Work" {
                self.retained |= value.fields.iter().any(|field|
                    matches!(&field.member, syn::Member::Named(name) if name == "image_path"));
            }
            syn::visit::visit_expr_struct(self, value);
        }
    }
    let file = source("section_metadata_work.rs");
    let submit = file.items.iter().find_map(|item| match item {
        Item::Fn(value) if value.sig.ident == "submit_hosted" => Some(value), _ => None,
    }).expect("exact retained Section submission");
    let mut calls = Calls::default();
    calls.visit_block(&submit.block);
    assert!(calls.0.iter().any(|name| name == "submit_hosted_inner"));
    let capture = file.items.iter().find_map(|item| match item {
        Item::Fn(value) if value.sig.ident == "submit_hosted_inner" => Some(value), _ => None,
    }).expect("shared routed File capture");
    calls.visit_block(&capture.block);
    assert!(calls.0.iter().any(|name| name == "retain_work"));
    let retain = file.items.iter().find_map(|item| match item {
        Item::Fn(value) if value.sig.ident == "retain_work" => Some(value), _ => None,
    }).expect("shared retained Section work owner");
    let mut path = PathCapture { exact: false, retained: false };
    path.visit_block(&capture.block);
    path.visit_block(&retain.block);
    assert!(path.exact && path.retained,
        "image display metadata must be captured and retained from the same canonical File owner");
    calls.visit_block(&retain.block);
    for forbidden in ["load_file_to_pool", "load_fat", "admit_dynamic_hosted_exe", "get_latest_by_leaf"] {
        assert!(!calls.0.iter().any(|name| name == forbidden), "no path/leaf source selection via {forbidden}");
    }
}

#[test]
fn retained_section_completeness_is_independent_of_closed_file_observation_target() {
    let file = source("native_image_sections.rs");
    let method = file.items.iter().find_map(|item| match item {
        Item::Impl(value) => value.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(value) if value.sig.ident == "has_complete_image" => Some(value),
            _ => None,
        }),
        _ => None,
    }).expect("retained canonical image completeness contract");
    #[derive(Default)]
    struct Fields { extent: bool, bytes: bool, observation: bool }
    impl<'ast> Visit<'ast> for Fields {
        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            if let syn::Member::Named(name) = &field.member {
                self.extent |= name == "file_extent";
                self.bytes |= name == "pe_header";
                self.observation |= name == "observation_target";
            }
            syn::visit::visit_expr_field(self, field);
        }
    }
    let mut fields = Fields::default();
    fields.visit_block(&method.block);
    assert!(fields.extent && fields.bytes);
    assert!(!fields.observation,
        "File close may retire its observational catalog entry; the retained Section still owns its exact image bytes");
}
