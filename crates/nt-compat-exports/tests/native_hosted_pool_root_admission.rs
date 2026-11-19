//! Root must never wait for a hosted pool lock: every component thread shares root's CPU below
//! root's priority, so a component holder root observes cannot run until root returns.

use syn::visit::Visit;

#[derive(Default)]
struct Effects {
    calls: Vec<String>,
    paths: Vec<String>,
    loops: usize,
}

impl<'ast> Visit<'ast> for Effects {
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

    fn visit_path(&mut self, path: &'ast syn::Path) {
        if let Some(name) = path.segments.last() {
            self.paths.push(name.ident.to_string());
        }
        syn::visit::visit_path(self, path);
    }

    fn visit_expr_loop(&mut self, expression: &'ast syn::ExprLoop) {
        self.loops += 1;
        syn::visit::visit_expr_loop(self, expression);
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        self.loops += 1;
        syn::visit::visit_expr_while(self, expression);
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        self.loops += 1;
        syn::visit::visit_expr_for_loop(self, expression);
    }
}

#[derive(Default)]
struct Functions(Vec<(String, String, Effects)>);

impl Functions {
    fn record(&mut self, file: &str, name: &syn::Ident, block: &syn::Block) {
        let mut effects = Effects::default();
        effects.visit_block(block);
        self.0.push((file.to_owned(), name.to_string(), effects));
    }
}

struct Collector<'a> {
    file: &'a str,
    functions: &'a mut Functions,
}

impl<'ast> Visit<'ast> for Collector<'_> {
    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        self.functions.record(self.file, &function.sig.ident, &function.block);
        syn::visit::visit_item_fn(self, function);
    }

    fn visit_impl_item_fn(&mut self, function: &'ast syn::ImplItemFn) {
        self.functions.record(self.file, &function.sig.ident, &function.block);
        syn::visit::visit_impl_item_fn(self, function);
    }
}

fn executive_functions() -> Functions {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src");
    let mut functions = Functions::default();
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|extension| extension != "rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let file = syn::parse_file(&std::fs::read_to_string(&path).unwrap()).unwrap();
        Collector { file: &name, functions: &mut functions }.visit_file(&file);
    }
    functions
}

#[test]
fn root_never_yield_spins_on_a_component_pool_lock() {
    let functions = executive_functions();
    let admission = functions.0.iter()
        .find(|(file, name, _)| file == "hosted_pool_lock.rs" && name == "hosted_instance_pool_lock")
        .map(|(_, _, effects)| effects)
        .expect("root hosted pool admission");
    assert_eq!(admission.loops, 0, "root pool admission must attempt once");
    assert!(!admission.calls.iter().any(|name| name == "yield_now"),
        "a yield cannot run a component holder below root's priority");
    assert_eq!(admission.calls.iter()
        .filter(|name| name.as_str() == "try_acquire_hosted_pool_lock").count(), 1,
        "one tagged attempt distinguishes acquired from busy");

    // Contention is resolved only by giving the exact registered holder its own dispatch, a
    // bounded number of times; the kernel refuses a holder that cannot run.
    let handoff = functions.0.iter()
        .find(|(file, name, _)| file == "hosted_pool_lock.rs" && name == "hand_off_to_pool_holder")
        .map(|(_, _, effects)| effects)
        .expect("exact holder handoff");
    assert_eq!(handoff.loops, 1, "one bounded handoff loop");
    assert!(handoff.paths.iter().any(|path| path == "HOLDER_HANDOFF_ROUNDS"));
    assert!(handoff.calls.iter().any(|name| name == "handoff_exact_component_once"));
    assert!(!handoff.calls.iter().any(|name| name == "yield_now"));

    // A DPC never runs over a stopped holder of its instance's pool.
    assert!(functions.0.iter().any(|(file, name, effects)| file == "hosted_irq_broker.rs"
        && name == "dispatch_next_dpc"
        && effects.calls.iter().any(|call| call == "hosted_instance_pool_quiescent")));

    // The only waiting acquisition of the shared word is the component's own view.
    let waiting: Vec<_> = functions.0.iter()
        .filter(|(_, _, effects)| effects.paths.iter().any(|path| path == "COMPONENT_POOL_LOCK_OFF")
            && (effects.loops != 0 || effects.calls.iter().any(|name| name == "yield_now")))
        .map(|(file, name, _)| format!("{file}:{name}"))
        .collect();
    assert_eq!(waiting, ["hosted_pool_lock.rs:component_pool_lock"],
        "only component threads may wait on the hosted pool lock word");
}
