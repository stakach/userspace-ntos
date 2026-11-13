//! A scatter/gather callback in a hosted IRQ lane must use the root-owned DMA graph.
//!
//! The root is waiting for the lane during the callback. An ordinary `call_on5` for
//! QUERY_SG or PUT_SG deadlocks there, and driver-writable SG pointers are not
//! authority to query or retire a graph without the exact adapter lease.

use syn::visit::Visit;

const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const BROKER: &str = include_str!("../../../components/ntos-executive/src/hosted_irq_broker.rs");

fn body<'a>(source: &'a syn::File, name: &str) -> &'a syn::Block {
    source.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == name => Some(&*item.block),
        syn::Item::Impl(item) => item.items.iter().find_map(|method| match method {
            syn::ImplItem::Fn(method) if method.sig.ident == name => Some(&method.block),
            _ => None,
        }),
        _ => None,
    }).unwrap_or_else(|| panic!("missing {name}"))
}

#[derive(Default)]
struct Wiring {
    calls: Vec<String>,
    paths: Vec<String>,
    arrays: Vec<Vec<String>>,
}

impl<'ast> Visit<'ast> for Wiring {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(name) = path.path.segments.last() {
                self.calls.push(name.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.calls.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.paths.extend(path.path.segments.iter().map(|part| part.ident.to_string()));
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member {
            self.paths.push(name.to_string());
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_expr_array(&mut self, array: &'ast syn::ExprArray) {
        let names = array.elems.iter().map(|expr| match expr {
            syn::Expr::Path(path) => path.path.segments.last().unwrap().ident.to_string(),
            _ => String::new(),
        }).collect();
        self.arrays.push(names);
        syn::visit::visit_expr_array(self, array);
    }
}

fn wiring(source: &str, name: &str) -> Wiring {
    let syntax = syn::parse_file(source).expect("native source parses");
    let mut result = Wiring::default();
    result.visit_block(body(&syntax, name));
    result
}

#[test]
fn irq_lane_sg_query_and_put_use_typed_service_with_exact_proof() {
    for (name, kind) in [
        ("dma_query_sg_members", "DmaQuerySg"),
        ("dma_retire_sg_list", "DmaPutSg"),
    ] {
        let helper = wiring(DRIVER, name);
        assert!(helper.calls.iter().any(|call| call == "hosted_irq_lane_context"),
            "{name} must detect the active IRQ lane before the ordinary provider call");
        assert!(helper.calls.iter().any(|call| call == "hosted_irq_lane_service")
            && helper.paths.iter().any(|part| part == kind),
            "{name} must issue a typed {kind} service inside the IRQ lane");
        assert!(helper.arrays.iter().any(|args| args == &[
            "adapter", "list", "lease_id", "adapter_id",
        ]), "{name} must carry [adapter, SG list, lease ID, adapter ID] in order");
    }
}

#[test]
fn irq_root_sg_services_use_lease_bound_private_graph() {
    for (kind, broker_method, root_service, graph_call) in [
        ("DmaQuerySg", "dma_query_sg_service", "service_hosted_irq_lane_dma_query_sg",
            "dma_private_sg_members"),
        ("DmaPutSg", "dma_put_sg_service", "service_hosted_irq_lane_dma_put_sg",
            "retire_dma_private_graph_typed"),
    ] {
        let broker = wiring(BROKER, broker_method);
        assert!(broker.calls.iter().any(|call| call == root_service),
            "the {kind} broker must authenticate the lane and forward the exact command");
        assert!(broker.calls.iter().any(|call| call == "has_dpc_dispatch_grant")
            && broker.calls.iter().any(|call| call == "lane_has_service_grant")
            && broker.paths.iter().any(|part| part == "target_domain_id")
            && broker.paths.iter().any(|part| part == "target_domain_cookie"),
            "the {kind} broker must enforce the live lane grant and domain generation");
        let root = wiring(DRIVER, root_service);
        assert!(root.calls.iter().any(|call| call == "authenticated_hosted_dma_free_lease"),
            "the {kind} root service must authenticate domain, adapter and lease identity");
        assert!(root.paths.iter().any(|part| part == "adapter_address"),
            "the {kind} root service must bind the exact adapter address to the lease");
        assert!(root.calls.iter().any(|call| call == graph_call),
            "the {kind} root service must use the owner-held private SG graph");
        assert!(!root.calls.iter().any(|call| call == "call_on5" || call == "ensure_mapping_at"),
            "the {kind} root service must not reenter the ordinary broker or replay mutable records");
    }
}
