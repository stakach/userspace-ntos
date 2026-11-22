//! A hosted IRP dispatch exchanges its canonical request with the root only through
//! `IrpTransport` (#426 step 4a), and the primary-pump transport keeps the original labels.
//! These checks pin source structure; they are not guest proof.
use syn::{visit::Visit, Expr, FnArg, ImplItem, Item, Pat, TraitItem, Type, TypeParamBound};

fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(value) if value.sig.ident == name => Some(value),
            _ => None,
        })
        .expect("actual native function")
}

#[derive(Default)]
struct Effects {
    calls: Vec<String>,
    methods: Vec<String>,
    paths: Vec<String>,
    literals: Vec<String>,
}

impl<'ast> Visit<'ast> for Effects {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.calls.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if let Expr::Path(receiver) = &*call.receiver {
            if receiver.path.is_ident("transport") {
                self.methods.push(call.method.to_string());
            }
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.paths.push(path.path.segments.last().unwrap().ident.to_string());
        syn::visit::visit_expr_path(self, path);
    }

    fn visit_lit_int(&mut self, literal: &'ast syn::LitInt) {
        self.literals.push(literal.base10_digits().to_string());
    }
}

fn effects(function: &syn::ItemFn) -> Effects {
    let mut effects = Effects::default();
    effects.visit_block(&function.block);
    effects
}

const TRANSPORT_LABELS: [&str; 4] = [
    "FSD_SERVICE_PULL_IRP_INPUT_LABEL",
    "FSD_SERVICE_PULL_IRP_OUTPUT_LABEL",
    "FSD_SERVICE_SOURCE_IRP_LABEL",
    "FSD_SERVICE_PUSH_IRP_OUTPUT_LABEL",
];

#[test]
fn hosted_dispatch_reaches_the_root_only_through_its_transport() {
    let driver = source("driver_launch.rs");
    let dispatch = function(&driver, "run_irp_with_bank");
    let first = dispatch.sig.inputs.first().expect("transport parameter");
    assert!(is_dyn_transport(first), "run_irp_with_bank must take `transport: &dyn IrpTransport`");
    let dispatch = effects(dispatch);
    for method in ["pull_input", "pull_output", "bind_packet", "push_output"] {
        assert!(dispatch.methods.iter().any(|name| name == method), "missing transport.{method}");
    }
    let fast_io = effects(function(&driver, "try_fast_io_device_control"));
    assert!(fast_io.methods.iter().any(|name| name == "push_output"));
    for body in [&dispatch, &fast_io] {
        for label in TRANSPORT_LABELS {
            assert!(!body.paths.iter().any(|path| path == label), "raw {label} in dispatch");
        }
        for raw in ["pool_push_request_bytes", "pull_request_bytes", "pool_pull_request_bytes"] {
            assert!(!body.calls.iter().any(|call| call == raw), "raw {raw} in dispatch");
        }
    }

    let run_irp = effects(function(&driver, "run_irp"));
    assert!(run_irp.paths.iter().any(|path| path == "PrimaryPumpIrpTransport"));
    let lane = source("hosted_class_irp_lane.rs");
    let execute = effects(function(&lane, "execute"));
    assert!(execute.paths.iter().any(|path| path == "PrimaryPumpIrpTransport"));
}

#[test]
fn primary_pump_transport_keeps_the_original_labels() {
    let transport = source("hosted_irp_transport.rs");
    let methods: Vec<String> = transport
        .items
        .iter()
        .find_map(|item| match item {
            Item::Trait(value) if value.ident == "IrpTransport" => Some(value),
            _ => None,
        })
        .expect("IrpTransport trait")
        .items
        .iter()
        .filter_map(|item| match item {
            TraitItem::Fn(method) => Some(method.sig.ident.to_string()),
            _ => None,
        })
        .collect();
    assert_eq!(
        methods,
        ["pull_input", "pull_output", "bind_packet", "packet_binding_violation", "push_output"]
    );

    let pump = transport
        .items
        .iter()
        .find_map(|item| match item {
            Item::Impl(value)
                if matches!(&*value.self_ty, Type::Path(ty) if ty.path.is_ident("PrimaryPumpIrpTransport"))
                    && value.trait_.as_ref().is_some_and(|(_, path, _)| path.is_ident("IrpTransport")) =>
            {
                Some(value)
            }
            _ => None,
        })
        .expect("primary pump IrpTransport impl");
    let method = |name: &str| {
        pump.items
            .iter()
            .find_map(|item| match item {
                ImplItem::Fn(method) if method.sig.ident == name => {
                    let mut effects = Effects::default();
                    effects.visit_block(&method.block);
                    Some(effects)
                }
                _ => None,
            })
            .expect("pump transport method")
    };
    let input = method("pull_input");
    assert!(input.paths.iter().any(|path| path == "FSD_SERVICE_PULL_IRP_INPUT_LABEL"));
    assert!(input.calls.iter().any(|call| call == "pull_request_bytes"));
    let output = method("pull_output");
    assert!(output.paths.iter().any(|path| path == "FSD_SERVICE_PULL_IRP_OUTPUT_LABEL"));
    assert!(output.calls.iter().any(|call| call == "pull_request_bytes"));
    let bind = method("bind_packet");
    assert!(bind.calls.iter().any(|call| call == "call_on4_raw"));
    assert!(bind.paths.iter().any(|path| path == "FSD_SERVICE_SOURCE_IRP_LABEL"));
    assert!(bind.literals.iter().any(|literal| literal == "6"));
    let violation = method("packet_binding_violation");
    assert!(violation.paths.iter().any(|path| path == "FSD_SERVICE_SOURCE_IRP_LABEL"));
    assert!(violation.calls.iter().any(|call| call == "report"));
    let push = method("push_output");
    assert!(push.calls.iter().any(|call| call == "pool_push_request_bytes"));

    let pull = function(&transport, "pull_request_bytes");
    let pull = effects(pull);
    assert!(pull.calls.iter().any(|call| call == "call_on4"));
}

fn is_dyn_transport(argument: &FnArg) -> bool {
    let FnArg::Typed(typed) = argument else { return false };
    let Pat::Ident(name) = &*typed.pat else { return false };
    let Type::Reference(reference) = &*typed.ty else { return false };
    let Type::TraitObject(object) = &*reference.elem else { return false };
    name.ident == "transport"
        && reference.mutability.is_none()
        && object.dyn_token.is_some()
        && object.bounds.iter().any(|bound| {
            matches!(bound, TypeParamBound::Trait(t) if t.path.is_ident("IrpTransport"))
        })
}
