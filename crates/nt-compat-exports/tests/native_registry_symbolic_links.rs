//! #417: how the executive's NtCreateKey/NtOpenKey admission handles registry symbolic links. The
//! CM server reports a crossed link as a reparse; the executive restarts the open or create on
//! the link's target (which may be another hive), as ObpLookupObjectName restarts a parse.

use syn::visit::Visit;

const ADMISSION: &str =
    include_str!("../../../components/ntos-executive/src/exec_registry_admission.rs");
const OWNERSHIP: &str = include_str!("../../../components/ntos-executive/src/cm_key_ownership.rs");
const MUTATION_WORK: &str =
    include_str!("../../../components/ntos-executive/src/registry_mutation_work.rs");

/// Every path segment and method name inside function `name`.
fn callees(source: &str, name: &str) -> Vec<String> {
    #[derive(Default)]
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
        // Expressions, struct literals and match patterns all name items through paths.
        fn visit_path(&mut self, path: &'ast syn::Path) {
            self.0.extend(path.segments.iter().map(|segment| segment.ident.to_string()));
            syn::visit::visit_path(self, path);
        }
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            self.0.push(call.method.to_string());
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    struct Find<'a> {
        name: &'a str,
        calls: Option<Calls>,
    }
    impl<'ast> Visit<'ast> for Find<'_> {
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            if item.sig.ident == self.name {
                let mut calls = Calls::default();
                calls.visit_block(&item.block);
                self.calls = Some(calls);
            }
            syn::visit::visit_item_fn(self, item);
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            if item.sig.ident == self.name {
                let mut calls = Calls::default();
                calls.visit_block(&item.block);
                self.calls = Some(calls);
            }
            syn::visit::visit_impl_item_fn(self, item);
        }
    }
    let mut find = Find { name, calls: None };
    find.visit_file(&syn::parse_file(source).expect("native source must parse"));
    find.calls.unwrap_or_else(|| panic!("function {name} not found")).0
}

fn uses(source: &str, function: &str, name: &str) -> bool {
    callees(source, function).iter().any(|callee| callee == name)
}

#[test]
fn opens_and_creates_restart_on_a_link_target() {
    for function in ["nt_open_key_with_options", "nt_create_key_admitted"] {
        assert!(uses(ADMISSION, function, "reparse_hosted_registry_publication"), "{function}");
        assert!(uses(ADMISSION, function, "Reparse"), "{function} handles the reparse step");
    }
    // The restart re-canonicalises the target and drops the captured root handle.
    for callee in ["registry_storage_canon", "release_hosted_registry_root", "MAX_REPARSE"] {
        assert!(uses(ADMISSION, "reparse_hosted_registry_publication", callee), "{callee}");
    }
    // Internal (driver) opens follow links through the same step.
    assert!(uses(ADMISSION, "acquire_registry_target", "acquire_registry_target_step"));
    assert!(uses(ADMISSION, "acquire_relative_registry_target", "acquire_relative_registry_target_step"));
}

#[test]
fn create_link_creates_a_link_and_collides_with_an_existing_key() {
    let create = callees(ADMISSION, "nt_create_key_admitted");
    for name in ["CreateLinkRelative", "STATUS_OBJECT_NAME_COLLISION", "REG_OPTION_CREATE_LINK",
        "SymbolicLink"] {
        assert!(create.iter().any(|callee| callee == name), "{name}");
    }
    assert!(uses(MUTATION_WORK, "submit_hosted", "CreateLinkRelative"),
        "the SYSTEM create broker admits link creation");
    // The created key is published as itself, never followed (a new link has no target yet).
    assert!(uses(OWNERSHIP, "reserve_publication_open", "reserve_with_options"));
    assert!(OWNERSHIP.contains("reserve_with_options(path, Some(root), true)"));
}

const VALUE_MUTATION: &str =
    include_str!("../../../components/ntos-executive/src/exec_registry_value_mutation.rs");
const MUTABLE_WORK: &str =
    include_str!("../../../components/ntos-executive/src/mutable_hive_mutation_work.rs");

#[test]
fn links_outside_system_are_created_followed_and_restricted_like_cm_links() {
    // Durable mutable-hive links are journaled with their kind; volatile ones live in the overlay.
    for name in ["journal_create_secured_mutable_subkey_of_kind", "create_secured_owned_of_kind"] {
        assert!(uses(ADMISSION, "create_secured_registry_child", name), "{name}");
    }
    assert!(MUTABLE_WORK.contains("prepare_owned_create_child_of_kind"),
        "the native mutable-hive create keeps the link kind");
    // Both stores report the links a path crosses.
    for name in ["link_reparse", "resolve_key_following"] {
        assert!(uses(ADMISSION, "acquire_registry_target_step", name), "{name}");
    }
    // CmSetValueKey: a link key holds only SymbolicLinkValue (REG_LINK).
    assert!(uses(VALUE_MUTATION, "nt_set_value_key_admitted", "registry_key_is_symbolic_link"));
    assert!(uses(VALUE_MUTATION, "nt_set_value_key_admitted", "SYMBOLIC_LINK_VALUE"));
}

#[test]
fn hardware_runtime_keys_create_and_follow_links_through_the_cm() {
    for function in ["acquire_registry_target_step", "acquire_relative_registry_target_step"] {
        assert!(uses(ADMISSION, function, "config_manager_open_runtime_key_step"), "{function}");
    }
    assert!(uses(ADMISSION, "nt_create_key_admitted", "config_manager_create_secured_key_of_kind"));
    assert!(!ADMISSION.contains("if link && is_cm_runtime_registry_path"),
        "no hive refuses CREATE_LINK");
}
