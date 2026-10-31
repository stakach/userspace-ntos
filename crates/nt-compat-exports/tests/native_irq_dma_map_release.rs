//! A map token freed from an IRQ callback must reach the root-owned DMA graph.
//!
//! The IRQ worker cannot synchronously call the ordinary provider broker while the
//! root broker is waiting for that worker. A shared MAP_TRANSFER record is also
//! driver-writable and is not authority to recreate or free a manager mapping.

use syn::visit::Visit;

const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");
const BROKER: &str = include_str!("../../../components/ntos-executive/src/hosted_irq_broker.rs");

fn function<'a>(source: &'a syn::File, name: &str) -> &'a syn::Block {
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
            if let Some(last) = path.path.segments.last() {
                self.calls.push(last.ident.to_string());
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

    fn visit_expr_array(&mut self, array: &'ast syn::ExprArray) {
        let names = array.elems.iter().map(|expr| match expr {
            syn::Expr::Path(path) => path.path.segments.last().unwrap().ident.to_string(),
            syn::Expr::Field(field) => match &field.member {
                syn::Member::Named(name) => name.to_string(),
                _ => String::new(),
            },
            _ => String::new(),
        }).collect();
        self.arrays.push(names);
        syn::visit::visit_expr_array(self, array);
    }
}

fn wiring(source: &str, name: &str) -> Wiring {
    let syntax = syn::parse_file(source).expect("native source parses");
    let mut result = Wiring::default();
    result.visit_block(function(&syntax, name));
    result
}

fn broker_word_order() -> Vec<u64> {
    struct ForwardedWords(Vec<u64>);
    impl<'ast> Visit<'ast> for ForwardedWords {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            let target = matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.last().is_some_and(|part|
                    part.ident == "service_hosted_irq_lane_dma_free_mapping"));
            if target {
                self.0 = call.args.iter().skip(3).filter_map(|arg| match arg {
                    syn::Expr::Index(index) => match &*index.index {
                        syn::Expr::Lit(literal) => match &literal.lit {
                            syn::Lit::Int(value) => value.base10_parse().ok(),
                            _ => None,
                        },
                        _ => None,
                    },
                    _ => None,
                }).collect();
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let syntax = syn::parse_file(BROKER).expect("native broker parses");
    let mut words = ForwardedWords(Vec::new());
    words.visit_block(function(&syntax, "dma_free_mapping_service"));
    words.0
}

#[test]
fn map_token_release_uses_irq_service_inside_an_irq_lane() {
    let release = wiring(DRIVER, "dma_retire_map_token");
    assert!(release.calls.iter().any(|call| call == "hosted_irq_lane_context"),
        "the map-token release must detect an active IRQ lane before calling the ordinary broker");
    assert!(release.calls.iter().any(|call| call == "hosted_irq_lane_service")
        && release.paths.iter().any(|part| part == "DmaFreeMapping"),
        "IRQ map-token release must use the authenticated DmaFreeMapping root service");
    assert!(release.arrays.iter().any(|args| args == &[
        "adapter", "map", "lease_id", "adapter_id",
    ]), "IRQ command must carry [adapter address, map token, lease ID, adapter ID] in order");
}

#[test]
fn irq_root_release_retires_the_exact_private_graph() {
    let broker = wiring(BROKER, "dma_free_mapping_service");
    assert!(broker.calls.iter().any(|call| call == "service_hosted_irq_lane_dma_free_mapping"),
        "the root IRQ broker must authenticate the lane before invoking the DMA owner");
    assert_eq!(broker_word_order(), [0, 1, 2, 3],
        "broker must forward all four authenticated command words in order");

    let syntax = syn::parse_file(DRIVER).expect("native source parses");
    let service = syntax.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == "service_hosted_irq_lane_dma_free_mapping" => Some(item),
        _ => None,
    }).expect("root DMA IRQ service exists");
    let parameters: Vec<_> = service.sig.inputs.iter().filter_map(|input| match input {
        syn::FnArg::Typed(arg) => match &*arg.pat {
            syn::Pat::Ident(name) => Some(name.ident.to_string()),
            _ => None,
        },
        _ => None,
    }).collect();
    assert_eq!(&parameters[3..], &["adapter_address", "map_token", "lease_id", "adapter_id"],
        "root service must interpret the broker's four command words in the same order");

    let release = wiring(DRIVER, "service_hosted_irq_lane_dma_free_mapping");
    assert!(release.calls.iter().any(|call| call == "retire_dma_private_graph"),
        "root must retire the captured map token and its lease, not replay a shared record");
    assert!(!release.calls.iter().any(|call| call == "free_hosted_dma_mapping_lease"
        || call == "ensure_mapping_at"),
        "IRQ release must not derive free authority from mutable shared MAP_TRANSFER records");
}
