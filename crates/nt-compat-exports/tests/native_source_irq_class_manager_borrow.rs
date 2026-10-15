//! A hosted IRQ callback can run during a scheduler yield inside a borrowed I/O dispatch.
//! Its admission path must not reborrow the global I/O Manager.

use syn::visit::Visit;

const BROKER: &str =
    include_str!("../../../components/ntos-executive/src/hosted_irq_broker.rs");
const THUNK: &str =
    include_str!("../../../components/ntos-executive/src/hosted_class_callback_thunk.rs");
const REVERSE: &str =
    include_str!("../../../components/ntos-executive/src/hosted_reverse_class_projection.rs");
const SCHEDULER: &str =
    include_str!("../../../components/ntos-executive/src/component_scheduler.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn maybe_body<'a>(file: &'a syn::File, name: &str) -> Option<&'a syn::Block> {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == name => Some(&*item.block),
            syn::Item::Impl(item) => item.items.iter().find_map(|member| match member {
                syn::ImplItem::Fn(method) if method.sig.ident == name => Some(&method.block),
                _ => None,
            }),
            _ => None,
        })
}

fn body<'a>(file: &'a syn::File, name: &str) -> &'a syn::Block {
    maybe_body(file, name).unwrap_or_else(|| panic!("missing native function {name}"))
}

#[derive(Default)]
struct Calls {
    names: Vec<String>,
    reverse_calls: Vec<String>,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            let segments: Vec<_> = path.path.segments.iter().collect();
            if let Some(last) = segments.last() {
                self.names.push(last.ident.to_string());
                if segments.iter().any(|segment| segment.ident == "hosted_reverse_class_projection") {
                    self.reverse_calls.push(last.ident.to_string());
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.names.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn calls(block: &syn::Block) -> Calls {
    let mut result = Calls::default();
    result.visit_block(block);
    result
}

fn manager_free_call_graph(
    file: &syn::File,
    entry: &str,
    visited: &mut Vec<String>,
) -> Vec<String> {
    let mut reverse_calls = Vec::new();
    let mut pending = vec![entry.to_owned()];
    while let Some(name) = pending.pop() {
        if visited.contains(&name) {
            continue;
        }
        visited.push(name.clone());
        let facts = calls(body(file, &name));
        assert!(
            !facts.names.iter().any(|call| call == "io_manager_mut"),
            "{name} reborrows the I/O Manager from IRQ admission"
        );
        reverse_calls.extend(facts.reverse_calls);
        pending.extend(
            facts.names.into_iter().filter(|callee| maybe_body(file, callee).is_some()),
        );
    }
    reverse_calls
}

#[test]
fn irq_class_admission_does_not_reborrow_manager_through_reverse_projection() {
    let broker = syn::parse_file(BROKER).unwrap();
    let thunk = syn::parse_file(THUNK).unwrap();
    let reverse = syn::parse_file(REVERSE).unwrap();

    let broker_calls = calls(body(&broker, "class_callback_service"));
    assert!(broker_calls.names.iter().any(|name| name == "admit_irq_request"));
    assert!(!broker_calls.names.iter().any(|name| name == "io_manager_mut"));

    let reverse_calls = manager_free_call_graph(&thunk, "admit_irq_request", &mut Vec::new());
    assert!(!reverse_calls.is_empty(), "IRQ admission must check its reverse owner");
    let mut visited = Vec::new();
    for callee in reverse_calls {
        manager_free_call_graph(&reverse, &callee, &mut visited);
    }
}

#[test]
fn borrowed_dispatch_can_yield_into_irq_class_admission() {
    let scheduler = syn::parse_file(SCHEDULER).unwrap();
    let driver = syn::parse_file(DRIVER).unwrap();
    let pump = calls(body(&scheduler, "hosted_component_pump_inner"));
    let yield_calls = calls(body(&scheduler, "service_irq_yield"));
    let dispatch = calls(body(&driver, "dispatch_irp_for_instance_exact"));
    assert!(pump.names.iter().any(|name| name == "service_irq_yield"));
    assert!(yield_calls.names.iter().any(|name| name == "drain_pending_hosted_irqs_snapshot"));
    assert!(yield_calls.names.iter().any(|name| name == "drain_hosted_driver_dpcs"));
    assert!(dispatch.names.iter().any(|name| name == "hosted_component_pump_with_caller"));
}
