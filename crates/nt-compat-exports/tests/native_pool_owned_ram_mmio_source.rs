//! RED source contract for a driver's live NonPagedPool RAM passed to MmMapIoSpace.
//!
//! A component's MmGetPhysicalAddress table is a translation hint, not authority. The root
//! must prove the current caller, live pool allocation and generation, and exact physical
//! frame cap before returning the already mapped WB pool VA. A requested UC type does not
//! change that effective cache type or authorize a second PageMap alias.

use std::fs;
use syn::visit::Visit;

const ROOT: &str = include_str!("../../../components/ntos-executive/src/hosted_mmio_broker.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::Block {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == name => Some(&*item.block),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing production function {name}"))
}

#[derive(Default)]
struct Calls {
    functions: Vec<String>,
    methods: Vec<String>,
    paths: Vec<String>,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(last) = path.path.segments.last() {
                self.functions.push(last.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.methods.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.paths
            .extend(path.path.segments.iter().map(|part| part.ident.to_string()));
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member {
            self.paths.push(name.to_string());
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_field_value(&mut self, field: &'ast syn::FieldValue) {
        if let syn::Member::Named(name) = &field.member {
            self.paths.push(name.to_string());
        }
        syn::visit::visit_field_value(self, field);
    }
}

fn calls(body: &syn::Block) -> Calls {
    let mut result = Calls::default();
    result.visit_block(body);
    result
}

fn has(names: &[String], name: &str) -> bool {
    names.iter().any(|item| item == name)
}

fn position(names: &[String], name: &str) -> usize {
    names
        .iter()
        .position(|item| item == name)
        .unwrap_or_else(|| panic!("missing production call {name}"))
}

fn owned_pool_source() -> syn::File {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../components/ntos-executive/src/hosted_pool_owned_mmio.rs"
    );
    let source = fs::read_to_string(path)
        .expect("root-owned pool RAM MMIO adapter must exist at the native service boundary");
    syn::parse_file(&source).expect("pool-owned MMIO adapter must parse")
}

#[test]
fn authenticated_root_mmio_service_routes_pool_ram_before_unassigned_refusal() {
    let root = syn::parse_file(ROOT).unwrap();
    let route = calls(function(&root, "service_hosted_driver_mmio_request"));
    assert!(has(&route.functions, "instance_for_pump_channel"));
    assert!(has(&route.functions, "hosted_driver_pump_caller_tcb"));
    assert!(
        has(&route.functions, "map_owned_pool") && has(&route.functions, "unmap_owned_pool"),
        "a live pool-owned physical range needs an authenticated root route with exact unmap receipts"
    );
    assert!(
        position(&route.functions, "hosted_driver_pump_caller_tcb")
            < position(&route.functions, "map_owned_pool")
    );
    assert!(
        position(&route.functions, "map_owned_pool")
            < position(&route.functions, "service_hosted_driver_gop_map")
    );
    assert!(
        position(&route.functions, "unmap_owned_pool")
            < position(&route.functions, "service_hosted_driver_gop_unmap")
    );
}

#[test]
fn pool_map_proves_allocation_generation_extent_and_cap_derived_physical_identity() {
    let adapter = owned_pool_source();
    let map = calls(function(&adapter, "map_owned_pool"));
    let captured = calls(function(&adapter, "source"));
    for required in [
        "instance_domain_identity",
        "hosted_instance_pool_lock",
        "pool_range_identity_unlocked",
        "get_frame_paddr_checked",
    ] {
        assert!(
            has(&map.functions, required),
            "root pool map must revalidate {required} before publication"
        );
    }
    assert!(has(&map.paths, "pool_frame_base"));
    assert!(has(&captured.paths, "pool_generation"));
    assert!(has(&captured.paths, "capacity"));
    assert!(
        !has(&map.functions, "hosted_component_physical_mappings"),
        "a component-writable physical table cannot confer mapping authority"
    );
}

#[test]
fn same_wb_pool_va_has_per_call_receipts_and_explicit_requested_effective_cache() {
    let adapter = owned_pool_source();
    let map = calls(function(&adapter, "map_owned_pool"));
    let unmap = calls(function(&adapter, "unmap_owned_pool"));
    assert!(has(&map.functions, "requests_mut") && has(&unmap.functions, "requests_mut"));
    assert!(
        !adapter.items.iter().any(|item| matches!(item, syn::Item::Static(_))),
        "pool requests must use the existing MMIO broker ledger, not a second table"
    );
    for required in ["prepare", "complete"] {
        assert!(has(&map.methods, required), "pool map must {required} one call receipt");
    }
    for required in ["begin_unmap", "acknowledge_unmap"] {
        assert!(has(&unmap.methods, required), "pool unmap must {required} one call receipt");
    }
    assert!(has(&map.paths, "requested_cache"));
    assert!(has(&map.paths, "effective_cache"));
    assert!(
        !has(&map.functions, "page_map") && !has(&map.functions, "page_map_r"),
        "UC request over existing WB pool RAM cannot create a PageMap alias"
    );
}

#[test]
fn all_pool_free_routes_fence_ready_and_uncertain_map_receipts() {
    let adapter = owned_pool_source();
    let source_rows = calls(function(&adapter, "has_source_rows"));
    assert!(
        has(&source_rows.methods, "has_pool_source_rows"),
        "ready, pending and uncertain receipts must all protect pool generation reuse"
    );

    let driver = syn::parse_file(DRIVER).unwrap();
    let raw_free = calls(function(&driver, "hosted_instance_pool_free_unlocked"));
    assert!(
        has(&raw_free.functions, "has_source_rows"),
        "the shared low-level free must fence generic and internal frees without a new lock"
    );
}

#[test]
fn instance_retirement_keeps_pool_caps_and_vspace_until_receipts_resolve() {
    let adapter = owned_pool_source();
    let guard = calls(function(&adapter, "blocks_instance_retirement"));
    assert!(has(&guard.methods, "has_pool_cap_rows"));
    let driver = syn::parse_file(DRIVER).unwrap();
    let teardown = calls(function(&driver, "clear_instance"));
    assert!(
        has(&teardown.functions, "blocks_instance_retirement"),
        "pool caps and VSpace cannot be retired while a map/unmap receipt survives"
    );
    assert!(
        position(&teardown.functions, "blocks_instance_retirement")
            < position(&teardown.functions, "finish_instance_physical_release")
    );
}
