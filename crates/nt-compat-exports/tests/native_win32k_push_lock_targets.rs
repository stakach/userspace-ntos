//! A contended push lock's lease admits every place NT code keeps one.
//!
//! ExAcquirePushLock* reaches win32k's slow path only under contention (common since guest
//! workers run on several cores). The lock may sit on a provider stack, in provider pool, in the
//! image's writable data (a global), or in an object allocated from a provider heap arena: GDI
//! objects come from paged lookaside lists, whose fallback allocator is the root heap arena.
//! Boot 44899095932 bugchecked PUSH stage 12 on a heap-arena lock at 0x10007402c50.

use syn::{visit::Visit, ImplItem, Item};

const SOURCE: &str =
    include_str!("../../../components/ntos-executive/src/win32k_subsystem/push_lock.rs");

fn method(name: &str) -> syn::ImplItemFn {
    syn::parse_file(SOURCE).unwrap().items.into_iter().find_map(|item| match item {
        Item::Impl(item) => item.items.into_iter().find_map(|item| match item {
            ImplItem::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        }),
        _ => None,
    }).unwrap_or_else(|| panic!("{name} not found"))
}

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(last) = path.path.segments.last() {
                self.0.push(last.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn calls(name: &str) -> Vec<String> {
    let mut calls = Calls::default();
    calls.visit_impl_item_fn(&method(name));
    calls.0
}

#[test]
fn a_heap_arena_lock_is_pinned_through_its_provider_allocation() {
    let capture = calls("capture");
    assert!(capture.iter().any(|name| name == "provider_heap_arena_contains"),
        "the lease must recognise a lock in a provider heap arena");
    assert!(capture.iter().any(|name| name == "pin_containing"),
        "a heap-arena lock is pinned through its exact registered allocation");
    assert!(capture.iter().any(|name| name == "pin_output"),
        "stack, pool and image-data locks keep their existing admission");
}

#[test]
fn every_access_revalidates_the_heap_allocation_pin() {
    let atomic = calls("atomic");
    assert!(atomic.iter().any(|name| name == "snapshot_active"),
        "an access through a heap-arena lease checks the pinned allocation is still live");
}
