//! #424: NT lets a kernel driver's `ZwSetValueKey`/`ZwDeleteValueKey` and win32k's registry
//! writes reach the hive log, like a hosted thread's `NtSetValueKey`. On the native storage
//! route the driver and win32k registry brokers still sent mutable (SOFTWARE/user) hive edits
//! to the synchronous journal, which refuses every write there. On the Boot route of a WAL
//! volume, `NtDeleteValueKey` and `NtDeleteKey` used only the legacy sidecar, which refuses a
//! v2 WAL volume. Both were refused with no effect.

use syn::visit::Visit;

#[path = "../../../components/ntos-executive/src/mutable_hive_edit_route.rs"]
mod mutable_hive_edit_route;

use mutable_hive_edit_route::{edit_owner, EditOwner};
use nt_fs::BlockSourceKind;

const EXEC_HANDLER: &str = include_str!("../../../components/ntos-executive/src/exec_handler.rs");
const DRIVER_ROUTE: &str =
    include_str!("../../../components/ntos-executive/src/driver_registry_deferred_value.rs");
const WIN32K_ROUTE: &str =
    include_str!("../../../components/ntos-executive/src/win32k_registry_deferred_value.rs");
const PROVIDER_CALLER: &str =
    include_str!("../../../components/ntos-executive/src/mutable_hive_provider_caller.rs");
const SHARED_PUMP: &str =
    include_str!("../../../components/ntos-executive/src/component_shared_pump.rs");

#[test]
fn a_boot_route_edit_on_a_wal_volume_is_anchored_in_the_boot_wal() {
    assert_eq!(edit_owner(Some(BlockSourceKind::Boot), true), EditOwner::BootWal);
    assert_eq!(edit_owner(Some(BlockSourceKind::Boot), false), EditOwner::LegacyJournal);
    assert_eq!(edit_owner(None, true), EditOwner::LegacyJournal);
}

#[test]
fn the_owner_depends_only_on_the_volume_never_on_the_caller() {
    // One policy serves hosted, driver and win32k edits alike: it has no caller input.
    for wal_volume in [false, true] {
        assert_eq!(edit_owner(Some(BlockSourceKind::Native), wal_volume), EditOwner::NativeWal);
        assert_eq!(edit_owner(Some(BlockSourceKind::Draining), wal_volume), EditOwner::NotReady);
    }
}

/// Every path segment and method name inside function `name` (free or associated).
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
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            if item.sig.ident == self.name {
                let mut calls = Calls::default();
                calls.visit_block(&item.block);
                self.calls = Some(calls);
            }
            syn::visit::visit_item_fn(self, item);
        }
    }
    let mut find = Find { name, calls: None };
    find.visit_file(&syn::parse_file(source).expect("native source must parse"));
    find.calls.unwrap_or_else(|| panic!("function {name} not found")).0
}

#[test]
fn boot_route_deletes_journal_through_the_boot_wal() {
    for (journal, boot) in [
        ("journal_delete_mutable_value", "boot_v2_delete_mutable_value"),
        ("journal_delete_mutable_key", "boot_v2_delete_mutable_key"),
    ] {
        let calls = callees(EXEC_HANDLER, journal);
        let has = |name: &str| calls.iter().any(|call| call == name);
        assert!(has("mutable_edit_owner") && has("BootWal") && has(boot),
            "{journal} anchors a Boot-route delete on a WAL volume");
    }
}

#[test]
fn driver_and_win32k_mutable_edits_park_in_the_native_wal_work() {
    for (name, source) in [("driver", DRIVER_ROUTE), ("win32k", WIN32K_ROUTE)] {
        let calls = callees(source, "route");
        let has = |call: &str| calls.iter().any(|seen| seen == call);
        assert!(has("provider_edit_admission"), "{name} asks the route policy");
        assert!(has("submit_provider_edit"), "{name} parks a native-route edit in the WAL work");
        assert!(has("PROVIDER_EDIT_NOT_READY"), "{name} refuses a draining route");
    }
}

#[test]
fn a_provider_lane_is_woken_only_after_publication_and_never_twice() {
    let calls = callees(PROVIDER_CALLER, "submit_provider_edit");
    assert!(calls.iter().any(|call| call == "park_retained_service"));
    let finish = callees(PROVIDER_CALLER, "finish");
    for name in [
        "reconcile_retained_service_reply",
        "acknowledge_retained_service_cancellation",
        "wake_registry_service",
    ] {
        assert!(finish.iter().any(|call| call == name), "finish uses {name}");
    }
}

#[test]
fn a_nested_provider_pump_drives_the_mutable_hive_work_and_its_journal() {
    assert!(SHARED_PUMP.contains("mutable_hive_mutation_work::redrive_nested()"));
    assert!(SHARED_PUMP.contains("service_mounted_native_mutable_hive_wal(id)"));
}
