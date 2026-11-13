//! Source contract for the native DMA adapter's private pool retirement.
//! The adapter projection is driver writable, including its DmaOperations pointer.
use syn::visit::Visit;

const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

#[derive(Default)]
struct DirectPoolFrees(usize);

impl<'ast> Visit<'ast> for DirectPoolFrees {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if path.path.segments.last().is_some_and(|part| part.ident == "pool_free") {
                self.0 += 1;
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn dma_adapter_release_cannot_free_a_driver_mutated_ops_pointer_directly() {
    let source = syn::parse_file(DRIVER).expect("native source parses");
    let release = source.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == "s_dma_put_adapter" => Some(item),
        _ => None,
    }).expect("native PutDmaAdapter implementation");
    let mut frees = DirectPoolFrees::default();
    frees.visit_block(&release.block);
    assert_eq!(frees.0, 0,
        "PutDmaAdapter must retire its captured adapter and operations allocations through exact physical acknowledgements; direct pool_free can free a protected DEVICE_OBJECT when the driver mutates DmaOperations; direct frees: {}",
        frees.0);
}
