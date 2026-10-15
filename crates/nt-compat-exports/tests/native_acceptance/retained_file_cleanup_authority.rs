use std::path::PathBuf;
use syn::visit::{self, Visit};

#[path = "../../../../components/ntos-executive/src/win32k_device_consumer/identity_bridge.rs"]
mod identity_bridge;

fn source(name: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function(file: &syn::File, name: &str) -> syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing actual source function {name}"))
}

fn pattern_name(pattern: &syn::Pat) -> Option<String> {
    match pattern {
        syn::Pat::Path(path) => Some(path.path.segments.last()?.ident.to_string()),
        syn::Pat::Ident(binding) if binding.subpat.is_none() => Some(binding.ident.to_string()),
        _ => None,
    }
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        visit::visit_expr_call(self, call);
    }
}

fn calls(node: &syn::ItemFn) -> Vec<String> {
    let mut calls = Calls::default();
    calls.visit_item_fn(node);
    calls.0
}

fn before(calls: &[String], first: &str, second: &str) {
    let position = |name: &str| {
        calls
            .iter()
            .position(|call| call == name)
            .unwrap_or_else(|| panic!("missing actual call {name}: {calls:?}"))
    };
    assert!(
        position(first) < position(second),
        "{first} must precede {second}"
    );
}

#[test]
fn retained_file_operations_are_selected_before_fresh_logical_caller_admission() {
    let file = source("provider_file_objects.rs");
    let service = function(&file, "service_win32k_file_object_request");
    let service_calls = calls(&service);
    before(
        &service_calls,
        "service_win32k_retained_file_object_request",
        "authenticate_win32k_service_request",
    );

    // DEVICE_NAME reads a handle-authorized name, not a retained File pointer.
    struct FreshArms(Vec<String>);
    impl<'ast> Visit<'ast> for FreshArms {
        fn visit_arm(&mut self, arm: &'ast syn::Arm) {
            if let Some(name) = pattern_name(&arm.pat) {
                if matches!(
                    name.as_str(),
                    "W32_FILE_OBJECT_REFERENCE_HANDLE"
                        | "W32_FILE_OBJECT_DEVICE_NAME"
                        | "W32_FILE_OBJECT_OPEN_DEVICE"
                ) {
                    self.0.push(name);
                }
            }
            visit::visit_arm(self, arm);
        }
    }
    let mut fresh = FreshArms(Vec::new());
    fresh.visit_item_fn(&service);
    assert_eq!(
        fresh.0,
        [
            "W32_FILE_OBJECT_REFERENCE_HANDLE",
            "W32_FILE_OBJECT_OPEN_DEVICE",
            "W32_FILE_OBJECT_DEVICE_NAME"
        ],
        "fresh operations remain in the caller-authorized service"
    );
    let fresh_auth = function(
        &source("service_sec_image.rs"),
        "authenticate_win32k_service_request",
    );
    assert!(calls(&fresh_auth).iter().any(|name| name == "resolve"));
}

#[test]
fn retained_file_pointer_wait_and_video_paths_receive_physical_consumer_domain() {
    let file = source("provider_file_objects.rs");
    let retained = function(&file, "service_win32k_retained_file_object_request");
    let names = calls(&retained);
    before(&names, "authenticate", "physical_win32k_provider");
    before(
        &names,
        "physical_win32k_provider",
        "retained_consumer_domain",
    );
    for forbidden in [
        "resolve",
        "authenticate_win32k_service_request",
        "capture_native_handle_caller",
    ] {
        assert!(
            !names.iter().any(|name| name == forbidden),
            "retained cleanup must not acquire fresh {forbidden} authority"
        );
    }
    struct OperationPatterns(Vec<String>);
    impl<'ast> Visit<'ast> for OperationPatterns {
        fn visit_pat(&mut self, pattern: &'ast syn::Pat) {
            if let Some(name) = pattern_name(pattern) {
                self.0.push(name);
            }
            visit::visit_pat(self, pattern);
        }
    }
    let mut patterns = OperationPatterns(Vec::new());
    patterns.visit_item_fn(&retained);
    for operation in [
        "W32_FILE_OBJECT_REFERENCE_POINTER",
        "W32_FILE_OBJECT_DEREFERENCE_POINTER",
        "W32_FILE_OBJECT_RELATED_DEVICE",
        "W32_FILE_OBJECT_WAIT_IDENTITY",
        "W32_FILE_OBJECT_RELEASE_WAIT",
    ] {
        assert!(
            patterns.0.iter().any(|name| name == operation),
            "missing retained operation {operation}"
        );
    }
    for fresh in [
        "W32_FILE_OBJECT_REFERENCE_HANDLE",
        "W32_FILE_OBJECT_DEVICE_NAME",
        "W32_FILE_OBJECT_OPEN_DEVICE",
    ] {
        assert!(
            !patterns.0.iter().any(|name| name == fresh),
            "{fresh} cannot be admitted by the retained-pointer service"
        );
    }
    struct ScopedOperations(Vec<String>);
    impl<'ast> Visit<'ast> for ScopedOperations {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                let name = path.path.segments.last().unwrap().ident.to_string();
                if matches!(
                    name.as_str(),
                    "reference_pointer"
                        | "dereference_pointer"
                        | "related_device_address"
                        | "acquire_wait_identity_for_event"
                        | "release_wait_identity"
                        | "reference_video_file_pointer"
                        | "release_video_file_projection"
                        | "video_related_device_object"
                ) {
                    assert!(call.args.len() >= 2,
                        "{name} must receive authenticated consumer domain, not only a raw pointer/token");
                    assert!(
                        matches!(call.args.first(), Some(syn::Expr::Path(path))
                        if path.path.is_ident("domain")),
                        "{name} uses the authenticated domain"
                    );
                    self.0.push(name);
                }
            }
            visit::visit_expr_call(self, call);
        }
    }
    let mut operations = ScopedOperations(Vec::new());
    operations.visit_item_fn(&retained);
    assert_eq!(
        operations.0.len(),
        8,
        "all retained File, wait and video operations remain checked"
    );
    for operation in &operations.0 {
        before(&names, "retained_consumer_domain", operation);
    }
}

#[test]
fn retained_wait_release_checks_exact_receipt_domain_before_any_release_effect() {
    let file = source("win32k_file_owners.rs");
    let release = function(&file, "release_wait_identity");
    assert!(
        release.sig.inputs.iter().any(|argument| matches!(argument,
        syn::FnArg::Typed(argument) if matches!(&*argument.pat,
            syn::Pat::Ident(name) if name.ident == "domain"))),
        "wait token alone cannot authorize release in another consumer domain"
    );
    struct DomainCheck(bool);
    impl<'ast> Visit<'ast> for DomainCheck {
        fn visit_expr_binary(&mut self, binary: &'ast syn::ExprBinary) {
            if matches!(binary.op, syn::BinOp::Ne(_) | syn::BinOp::Eq(_)) {
                let is_domain = |expression: &syn::Expr| {
                    matches!(expression,
                    syn::Expr::Path(path) if path.path.is_ident("domain"))
                };
                let is_identity_domain = |expression: &syn::Expr| {
                    matches!(expression,
                    syn::Expr::MethodCall(call) if call.method == "domain")
                };
                self.0 |= (is_domain(&binary.left) && is_identity_domain(&binary.right))
                    || (is_domain(&binary.right) && is_identity_domain(&binary.left));
            }
            visit::visit_expr_binary(self, binary);
        }
    }
    let mut checked = false;
    for statement in &release.block.stmts {
        let mut check = DomainCheck(false);
        check.visit_stmt(statement);
        checked |= check.0;
        // These are method calls, so inspect them separately from free-function transport.
        struct Effects(bool);
        impl<'ast> Visit<'ast> for Effects {
            fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
                self.0 |= matches!(
                    call.method.to_string().as_str(),
                    "release_file_reference" | "release_hosted_file_publication"
                );
                visit::visit_expr_method_call(self, call);
            }
        }
        let mut effects = Effects(false);
        effects.visit_stmt(statement);
        assert!(
            !effects.0 || checked,
            "exact receipt domain check precedes owned release"
        );
    }
    assert!(
        checked,
        "release validates the existing receipt's HostedDomainIdentity"
    );
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Catalog(u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Provider {
    slot: u64,
    generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ConsumerDomain {
    slot: u64,
    cookie: u64,
}

#[test]
fn retained_bridge_returns_existing_consumer_identity_without_changing_inputs() {
    let retained = (
        Catalog(11),
        Provider {
            slot: 3,
            generation: 2,
        },
        0x8000,
        ConsumerDomain { slot: 9, cookie: 4 },
    );
    let before = retained;
    assert_eq!(
        identity_bridge::retained_domain(
            retained,
            (retained.0, retained.1, retained.2),
            Some(retained.3)
        ),
        Some(retained.3)
    );
    assert_eq!(retained, before);
}

#[test]
fn retained_bridge_rejects_foreign_catalog_provider_generation_and_vspace() {
    let retained = (
        Catalog(11),
        Provider {
            slot: 3,
            generation: 2,
        },
        0x8000,
        ConsumerDomain { slot: 9, cookie: 4 },
    );
    for physical in [
        (Catalog(12), retained.1, retained.2),
        (
            retained.0,
            Provider {
                slot: 4,
                generation: 2,
            },
            retained.2,
        ),
        (
            retained.0,
            Provider {
                slot: 3,
                generation: 3,
            },
            retained.2,
        ),
        (retained.0, retained.1, 0x9000),
        (retained.0, retained.1, 0),
    ] {
        assert_eq!(
            identity_bridge::retained_domain(retained, physical, Some(retained.3)),
            None
        );
    }
    let mut zero = retained;
    zero.2 = 0;
    assert_eq!(
        identity_bridge::retained_domain(zero, (zero.0, zero.1, 0), Some(zero.3)),
        None
    );
}

#[test]
fn retained_bridge_rejects_removed_or_replaced_io_domain_cookie() {
    let retained = (
        Catalog(11),
        Provider {
            slot: 3,
            generation: 2,
        },
        0x8000,
        ConsumerDomain { slot: 9, cookie: 4 },
    );
    let physical = (retained.0, retained.1, retained.2);
    for canonical in [
        None,
        Some(ConsumerDomain { slot: 9, cookie: 5 }),
        Some(ConsumerDomain {
            slot: 10,
            cookie: 4,
        }),
    ] {
        assert_eq!(
            identity_bridge::retained_domain(retained, physical, canonical),
            None
        );
    }
}

#[test]
fn native_retained_bridge_uses_actual_io_identity_not_live_acquisition_policy() {
    let file = source("win32k_device_consumer.rs");
    let bridge = function(&file, "retained_consumer_domain");
    struct Fields(Vec<String>);
    impl<'ast> Visit<'ast> for Fields {
        fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
            if let syn::Member::Named(name) = &field.member {
                self.0.push(name.to_string());
            }
            visit::visit_expr_field(self, field);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0.push(call.method.to_string());
            visit::visit_expr_method_call(self, call);
        }
    }
    let mut fields = Fields(Vec::new());
    fields.visit_item_fn(&bridge);
    for required in [
        "catalog",
        "provider",
        "pml4",
        "domain",
        "hosted_domain_identity",
    ] {
        assert!(
            fields.0.iter().any(|field| field == required),
            "bridge retains {required} check"
        );
    }
    assert!(
        !fields.0.iter().any(|field| field == "retiring"),
        "held releases do not depend on fresh Consumer admission"
    );
    assert!(
        !calls(&bridge).iter().any(|name| name == "live_consumer"),
        "release uses the retained binding, not acquisition policy"
    );
    assert!(
        calls(&function(&file, "reference_file_by_handle"))
            .iter()
            .any(|name| name == "live_consumer"),
        "fresh acquisition policy remains unchanged"
    );
    for current in [
        "current_win32k_provider_domain",
        "win32k_provider_domain_is_current",
    ] {
        assert!(
            calls(&bridge).iter().any(|name| name == current),
            "bridge checks current {current}"
        );
    }
}

#[test]
fn ordinary_and_video_pointer_owners_check_domain_before_reference_effects() {
    struct DomainCheck(bool);
    impl<'ast> Visit<'ast> for DomainCheck {
        fn visit_expr_binary(&mut self, expression: &'ast syn::ExprBinary) {
            if matches!(expression.op, syn::BinOp::Ne(_)) {
                self.0 |= matches!(&*expression.left,
                    syn::Expr::MethodCall(call) if call.method == "domain")
                    && matches!(&*expression.right,
                        syn::Expr::Path(path) if path.path.is_ident("domain"));
            }
            visit::visit_expr_binary(self, expression);
        }
    }
    for (file, name, effect) in [
        (
            "win32k_file_owners.rs",
            "reference_pointer",
            "reference_file_by_pointer",
        ),
        (
            "win32k_file_owners.rs",
            "dereference_pointer",
            "dereference_file_owner",
        ),
        (
            "win32k_file_owners.rs",
            "related_device_address",
            "related_file_device_address",
        ),
        (
            "video_projection_owners.rs",
            "reference_by_pointer",
            "reference_file_by_pointer",
        ),
        (
            "video_projection_owners.rs",
            "dereference",
            "dereference_file_owner",
        ),
        (
            "video_projection_owners.rs",
            "related_device_address",
            "related_file_device_address",
        ),
    ] {
        let owner = function(&source(file), name);
        let mut checked = false;
        let mut entered = false;
        for statement in &owner.block.stmts {
            let mut check = DomainCheck(false);
            check.visit_stmt(statement);
            checked |= check.0;
            let mut calls = Calls::default();
            calls.visit_stmt(statement);
            if calls.0.iter().any(|name| name == effect) {
                assert!(
                    checked,
                    "{file}::{name} checks actual owner domain before {effect}"
                );
                entered = true;
            }
        }
        assert!(entered, "preserve the actual owner effect {file}::{name}");
    }
}
