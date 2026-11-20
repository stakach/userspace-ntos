//! #422: Explorer and iernonce delete each RunOnce value and RunOnceEx section before running
//! it. In two-boot run 44677193307 boot 2 ran them all again. The SOFTWARE keys are mutable-hive
//! keys, and the volume was on the native disk stack. There, hosted `NtSetValueKey` waits for its
//! record to be anchored in the native WAL. `NtDeleteValueKey` and `NtDeleteKey` still went to the
//! legacy sidecar append, which refuses every write on that route. They returned
//! `STATUS_UNSUCCESSFUL`, journalled nothing, and the callers ran the entries anyway.

use syn::visit::Visit;

#[path = "../../../components/ntos-executive/src/mutable_hive_edit_route.rs"]
mod mutable_hive_edit_route;

use mutable_hive_edit_route::{edit_owner, EditOwner, STATUS_DEVICE_NOT_READY};
use nt_fs::BlockSourceKind;

const VALUE_MUTATION: &str =
    include_str!("../../../components/ntos-executive/src/exec_registry_value_mutation.rs");
const MUTABLE_WORK: &str =
    include_str!("../../../components/ntos-executive/src/mutable_hive_mutation_work.rs");

#[test]
fn an_edit_on_the_native_stack_waits_for_its_anchored_wal_record() {
    assert_eq!(edit_owner(Some(BlockSourceKind::Native), true), EditOwner::NativeWal);
    assert_eq!(edit_owner(Some(BlockSourceKind::Draining), true), EditOwner::NotReady);
    assert_eq!(STATUS_DEVICE_NOT_READY, 0xC000_00A3);
}

/// Every path segment and method name inside function `name`.
fn callees(source: &str, name: &str) -> Vec<String> {
    #[derive(Default)]
    struct Calls(Vec<String>);
    impl<'ast> Visit<'ast> for Calls {
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

#[test]
fn hosted_deletes_take_the_same_owner_as_hosted_sets() {
    for syscall in [
        "nt_set_value_key_admitted",
        "nt_delete_value_key_admitted",
        "nt_delete_key_admitted",
    ] {
        let calls = callees(VALUE_MUTATION, syscall);
        let has = |name: &str| calls.iter().any(|call| call == name);
        assert!(has("NativeWal") && has("mutable_hive_mutation_work"),
            "{syscall} hands a native-route edit to the anchored WAL work");
        assert!(has("STATUS_DEVICE_NOT_READY"), "{syscall} refuses a draining route");
    }
}

#[test]
fn the_native_wal_work_prepares_and_publishes_deletions() {
    for name in [
        "prepare_owned_delete_value",
        "prepare_owned_delete_key",
    ] {
        assert!(MUTABLE_WORK.contains(name), "{name}");
    }
}
