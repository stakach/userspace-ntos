//! The private DMA graph must never infer free authority from driver-writable pointers.

use syn::visit::Visit;

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(name) = path.path.segments.last() {
                self.0.push(name.ident.to_string());
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
    let syntax = syn::parse_file(SOURCE).unwrap();
    let body = syntax.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == name => Some(&item.block),
        _ => None,
    }).unwrap_or_else(|| panic!("missing {name}"));
    let mut calls = Calls(Vec::new());
    calls.visit_block(body);
    calls.0
}

#[test]
fn map_channel_and_scatter_gather_private_members_use_root_broker() {
    for name in [
        "s_dma_allocate_adapter_channel", "dma_allocate_map_register_token",
        "s_dma_free_map_registers", "dma_prepare_one_element_sg_list",
        "s_dma_get_scatter_gather_list", "s_dma_build_scatter_gather_list",
        "s_dma_put_scatter_gather_list",
    ] {
        assert!(!calls(name).iter().any(|call| call == "pool_free"),
            "{name} directly frees private DMA storage");
    }
    let channel = calls("s_dma_allocate_adapter_channel");
    assert!(channel.iter().any(|call| call == "dma_retire_map_token"),
        "DeallocateObject must release the exact root-owned token");
    let put = calls("s_dma_put_scatter_gather_list");
    assert!(put.iter().any(|call| call == "dma_retire_sg_list"),
        "PutScatterGatherList must use the captured graph");
}

#[test]
fn shared_map_replay_requires_root_mapping_receipt_and_cannot_register_anew() {
    let replay = calls("replay_hosted_dma_allocation_records");
    assert!(replay.iter().any(|call| call == "dma_private_mapping_receipt"),
        "shared MAP_TRANSFER records must resolve the exact root lease and saved mapping ID");
    assert!(!replay.iter().any(|call| call == "ensure_mapping_at"),
        "a forged or stale shared record must not create another manager mapping");
    let source = SOURCE.split("unsafe fn replay_hosted_dma_allocation_records(")
        .nth(1).expect("replay function exists");
    let body = source.split("unsafe fn record_hosted_mmio_usage(")
        .next().expect("following function exists");
    assert!(body.contains("lease.owner") && body.contains("hosted_dma_owner(binding)"),
        "replay must bind the graph receipt to this device owner");
    assert!(body.contains("lease.adapter_id") && body.contains("lease.grant"),
        "replay must bind the shared header to the root adapter and grant");
}
