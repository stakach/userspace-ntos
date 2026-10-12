//! Physical pool admission must not reborrow the canonical manager during provider pumps.
use syn::visit::Visit;

const LEDGER: &str =
    include_str!("../../../../components/ntos-executive/src/hosted_source_irp_ledger.rs");
const DRIVER: &str = include_str!("../../../../components/ntos-executive/src/driver_launch.rs");
const PUBLICATION: &str = include_str!("../../../../components/ntos-executive/src/hosted_device_publication.rs");
const RETIREMENT: &str = include_str!("../../../../components/ntos-executive/src/hosted_device_retirement.rs");

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == name => Some(item),
            _ => None,
        })
        .unwrap()
}

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
fn calls(item: &syn::ItemFn) -> Vec<String> {
    let mut found = Calls::default();
    found.visit_block(&item.block);
    found.0
}
fn position(calls: &[String], name: &str) -> usize {
    calls
        .iter()
        .position(|call| call == name)
        .unwrap_or_else(|| panic!("missing physical lifetime boundary {name}"))
}

#[test]
fn generic_pool_free_checks_independent_projection_owner_before_unregistered_free() {
    let file = syn::parse_file(LEDGER).unwrap();
    let found = calls(function(&file, "retire_allocation"));
    assert!(position(&found, "generic_free_admission") < position(&found, "pool_free_admission"));
    assert!(!found.iter().any(|call| call == "io_manager_mut"));
}

#[test]
fn physical_device_retirement_checks_captured_owner_before_mutating_or_freeing() {
    let file = syn::parse_file(RETIREMENT).unwrap();
    let found = calls(function(&file, "retire_hosted_device_projection"));
    let admitted = position(&found, "admit_retirement");
    assert!(admitted < position(&found, "write_unaligned"));
    assert!(admitted < position(&found, "hosted_instance_pool_free_unlocked"));
    assert!(
        position(&found, "hosted_instance_pool_free_unlocked")
            < position(&found, "finish_retirement")
    );
}

#[test]
fn ordinary_and_pdo_publication_capture_physical_owner_before_canonical_bind() {
    let file = syn::parse_file(DRIVER).unwrap();
    let publication = syn::parse_file(PUBLICATION).unwrap();
    let found = calls(function(&publication, "register_hosted_device_projection"));
    assert!(
        position(&found, "protect_allocation") < position(&found, "bind_hosted_device_pointer")
    );
    assert!(
        position(&found, "bind_hosted_device_pointer") < position(&found, "publish_registration")
    );
    for name in [
        "service_hosted_device",
        "register_hosted_device_binding",
        "call_add_device_for_existing_pdo",
    ] {
        let found = calls(function(&file, name));
        assert!(
            !found
                .iter()
                .any(|call| call == "bind_hosted_device_pointer"),
            "{name} bypasses physical publication"
        );
    }
}

#[test]
fn retained_creation_reply_cannot_enter_clean_rejection_cleanup() {
    let file = syn::parse_file(DRIVER).unwrap();
    let item = function(&file, "hosted_device_create");
    let found = calls(item);
    assert!(
        !found.iter().any(|call| call == "hosted_device_mutation"),
        "CREATE must preserve its explicit retained outcome, not flatten status"
    );
    struct RetainedArms {
        seen: usize,
    }
    impl<'a> Visit<'a> for RetainedArms {
        fn visit_arm(&mut self, arm: &'a syn::Arm) {
            struct Pattern(bool);
            impl<'a> Visit<'a> for Pattern {
                fn visit_path(&mut self, path: &'a syn::Path) {
                    self.0 |= path.segments.iter().any(|part| part.ident == "Retained");
                    syn::visit::visit_path(self, path);
                }
            }
            let mut pattern = Pattern(false);
            pattern.visit_pat(&arm.pat);
            if pattern.0 {
                self.seen += 1;
                let mut found = Calls::default();
                found.visit_expr(&arm.body);
                assert!(
                    found.0.iter().any(|call| call == "report"),
                    "retained CREATE failure must keep ownership and fail-stop"
                );
                assert!(!found.0.iter().any(|call| matches!(
                    call.as_str(),
                    "pool_free" | "delete_hosted_device_projection" | "into_result"
                )));
            }
            syn::visit::visit_arm(self, arm);
        }
    }
    let mut arms = RetainedArms { seen: 0 };
    arms.visit_block(&item.block);
    assert_eq!(arms.seen, 1, "explicit retained CREATE outcome is required");
}
