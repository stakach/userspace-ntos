//! Live detached File adoption only. Borrowed PnP/lifecycle backends still hold &mut IoManager
//! across their pump and cannot acquire or release projection owners from nested source RPCs.
use syn::visit::Visit;

const OWNERS: &str =
    include_str!("../../../../components/ntos-executive/src/hosted_file_owners.rs");
const SOURCE_IRPS: &str =
    include_str!("../../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");

#[derive(Default)]
struct Evidence {
    calls: Vec<String>,
    fields: Vec<String>,
    types: Vec<String>,
}
impl<'a> Visit<'a> for Evidence {
    fn visit_macro(&mut self, mac: &'a syn::Macro) {
        if let Ok(expression) = syn::parse2::<syn::Expr>(mac.tokens.clone()) {
            let facts = {
                let mut facts = Evidence::default();
                facts.visit_expr(&expression);
                facts
            };
            self.calls.extend(facts.calls);
            self.fields.extend(facts.fields);
        }
        syn::visit::visit_macro(self, mac);
    }
    fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.calls
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_field(&mut self, field: &'a syn::ExprField) {
        if let syn::Member::Named(name) = &field.member {
            self.fields.push(name.to_string());
        }
        syn::visit::visit_expr_field(self, field);
    }
    fn visit_type_path(&mut self, path: &'a syn::TypePath) {
        self.types
            .extend(path.path.segments.iter().map(|part| part.ident.to_string()));
        syn::visit::visit_type_path(self, path);
    }
}
fn function<'a>(file: &'a syn::File, name: &str) -> Option<&'a syn::ItemFn> {
    file.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == name => Some(item),
        _ => None,
    })
}
fn evidence(block: &syn::Block) -> Evidence {
    let mut facts = Evidence::default();
    facts.visit_block(block);
    facts
}
fn delegated(file: &syn::File, name: &str) -> Evidence {
    let mut pending = vec![name.to_owned()];
    let mut seen = Vec::new();
    let mut all = Evidence::default();
    while let Some(name) = pending.pop() {
        if seen.contains(&name) {
            continue;
        }
        seen.push(name.clone());
        let Some(item) = function(file, &name) else {
            continue;
        };
        let facts = evidence(&item.block);
        pending.extend(
            facts
                .calls
                .iter()
                .filter(|call| function(file, call).is_some())
                .cloned(),
        );
        all.calls.extend(facts.calls);
        all.fields.extend(facts.fields);
        all.types.extend(facts.types);
    }
    all
}
fn has(calls: &[String], name: &str) -> bool {
    calls.iter().any(|call| call == name)
}
fn row_owns_projection(file: &syn::File) -> bool {
    let Some(row) = file.items.iter().find_map(|item| match item {
        syn::Item::Struct(item) if item.ident == "Row" => Some(item),
        _ => None,
    }) else {
        return false;
    };
    let mut facts = Evidence::default();
    facts.visit_item_struct(row);
    has(&facts.types, "HostedDeviceProjectionReference")
}

#[test]
fn detached_file_row_owns_exact_projection_stack_before_native_invoke() {
    let file = syn::parse_file(OWNERS).unwrap();
    assert!(
        row_owns_projection(&file),
        "the existing retained Row must own non-Copy projection references"
    );
    let capture = delegated(&file, "capture_route");
    for required in [
        "hosted_device_binding_by_device_id",
        "hosted_device_pointer_registration",
        "retain_hosted_device_projection_reference",
    ] {
        assert!(
            has(&capture.calls, required),
            "capture the real registered projection via {required}"
        );
    }
    for physical in ["projection_domain", "projection_instance", "device_object"] {
        assert!(
            has(&capture.fields, physical),
            "capture authentic physical {physical}, not only canonical DeviceId"
        );
    }
    let dispatch = evidence(&function(&file, "dispatch").unwrap().block);
    let capture = dispatch
        .calls
        .iter()
        .position(|call| call == "capture_route")
        .unwrap();
    let invoke = dispatch
        .calls
        .iter()
        .position(|call| call == "invoke")
        .unwrap();
    assert!(capture < invoke, "own projections before foreign execution");
}

fn checked_release_before_remove(file: &syn::File) -> bool {
    let Some(remove) = function(file, "remove") else {
        return false;
    };
    let direct = evidence(&remove.block);
    let Some(erase) = direct.calls.iter().position(|call| call == "swap_remove") else {
        return false;
    };
    direct.calls[..erase].iter().any(|call| {
        if call == "release_hosted_device_projection_reference" {
            return true;
        }
        let facts = delegated(file, call);
        has(&facts.calls, "release_hosted_device_projection_reference")
    }) && matches!(remove.sig.output, syn::ReturnType::Type(_, _))
}

#[test]
fn detached_file_projection_release_is_checked_before_owner_removal() {
    let file = syn::parse_file(OWNERS).unwrap();
    assert!(
        checked_release_before_remove(&file),
        "release refusal must leave the retained Row intact, not drop an owner on removal"
    );
    let discard = evidence(&function(&file, "discard").unwrap().block);
    assert!(has(&discard.calls, "discard_prepared_external_file_irp"));
    assert!(
        has(&discard.calls, "block"),
        "failed pre-effect rollback must retain ownership"
    );
    let release = delegated(&file, "remove");
    assert!(
        has(&release.calls, "is_held"),
        "a partially released prefix must not be replayed"
    );
}

#[test]
fn detached_file_pending_and_uncertain_paths_keep_projection_ownership() {
    let file = syn::parse_file(OWNERS).unwrap();
    assert!(
        row_owns_projection(&file),
        "pending ownership includes actual projection pins"
    );
    struct Arms {
        retained: usize,
        invalid: bool,
    }
    impl<'a> Visit<'a> for Arms {
        fn visit_arm(&mut self, arm: &'a syn::Arm) {
            struct Pattern(Vec<String>);
            impl<'a> Visit<'a> for Pattern {
                fn visit_path(&mut self, path: &'a syn::Path) {
                    self.0
                        .extend(path.segments.iter().map(|part| part.ident.to_string()));
                    syn::visit::visit_path(self, path);
                }
            }
            let mut pattern = Pattern(Vec::new());
            pattern.visit_pat(&arm.pat);
            if has(&pattern.0, "ExternalFileIrpResult")
                && (has(&pattern.0, "Pending") || has(&pattern.0, "Indeterminate"))
            {
                let mut facts = Evidence::default();
                facts.visit_expr(&arm.body);
                self.retained += 1;
                self.invalid |= !has(&facts.calls, "keep")
                    || facts.calls.iter().any(|call| {
                        matches!(
                            call.as_str(),
                            "remove" | "release_hosted_device_projection_reference"
                        )
                    });
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut arms = Arms {
        retained: 0,
        invalid: false,
    };
    arms.visit_block(&function(&file, "dispatch").unwrap().block);
    assert_eq!(arms.retained, 2);
    assert!(
        !arms.invalid,
        "unknown native effects cannot release projection owners"
    );
    for name in ["keep", "block"] {
        let facts = delegated(&file, name);
        assert!(!has(
            &facts.calls,
            "release_hosted_device_projection_reference"
        ));
    }
}

#[test]
fn source_irp_rpc_cannot_reborrow_manager_for_projection_ownership() {
    let file = syn::parse_file(SOURCE_IRPS).unwrap();
    let rpc = delegated(&file, "service");
    for forbidden in [
        "io_manager_mut",
        "retain_hosted_device_projection_reference",
        "release_hosted_device_projection_reference",
    ] {
        assert!(
            !has(&rpc.calls, forbidden),
            "borrowed PnP/lifecycle pump forbids {forbidden} here"
        );
    }
}

#[test]
fn detached_file_removal_follows_canonical_terminal_and_real_backend_ack() {
    let file = syn::parse_file(OWNERS).unwrap();
    let dispatch = evidence(&function(&file, "dispatch").unwrap().block);
    let terminal = dispatch
        .calls
        .iter()
        .position(|call| call == "retire_external_file_irp_terminal")
        .unwrap();
    assert!(dispatch.calls[terminal..]
        .iter()
        .any(|call| call == "accepts_external_file_irp_receipt"));
    let ack = evidence(&function(&file, "acknowledge").unwrap().block);
    let retire = ack
        .calls
        .iter()
        .position(|call| call == "finish_external_file_irp_completion")
        .unwrap();
    let remove = ack.calls.iter().position(|call| call == "remove").unwrap();
    assert!(retire < remove);
    assert!(has(&ack.calls[retire..remove], "backend_acknowledged"));
    assert!(
        has(&ack.calls, "retry_later"),
        "uncertain ACK retains the existing owner rather than releasing pins"
    );
}

#[test]
fn projection_source_contract_rejects_detached_refs_and_drop_before_release() {
    let detached =
        syn::parse_file("struct Row { owners: Vec<HostedDevicePointerReference> }").unwrap();
    assert!(!row_owns_projection(&detached));
    let wrong_order = syn::parse_file("fn remove(id: u64) -> Result<(), E> { rows().swap_remove(id); release_hosted_device_projection_reference(id)?; Ok(()) }").unwrap();
    assert!(!checked_release_before_remove(&wrong_order));
    let unchecked = syn::parse_file("fn remove(id: u64) { release_hosted_device_projection_reference(id); rows().swap_remove(id); }").unwrap();
    assert!(!checked_release_before_remove(&unchecked));
}
