use std::path::Path;
use syn::visit::Visit;

fn source(name: &str) -> syn::File {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src").join(name);
    syn::parse_file(&std::fs::read_to_string(path)
        .expect("authenticated power broker source must exist")).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == name => Some(item),
        _ => None,
    }).unwrap_or_else(|| panic!("missing power boundary function {name}"))
}

#[derive(Default)]
struct Paths(Vec<String>);

impl<'ast> Visit<'ast> for Paths {
    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.0.extend(path.path.segments.iter().map(|part| part.ident.to_string()));
        syn::visit::visit_expr_path(self, path);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn paths(function: &syn::ItemFn) -> Paths {
    let mut paths = Paths::default();
    paths.visit_block(&function.block);
    paths
}

#[test]
fn component_power_export_only_enters_the_owned_broker() {
    let file = source("driver_launch.rs");
    let paths = paths(function(&file, "s_po_set_power_state"));
    assert!(paths.0.iter().any(|name| name == "component_report"),
        "PoSetPowerState must report through its authenticated broker");
    for forbidden in ["hosted_power_devnode_by_device_object", "power_manager",
        "HOSTED_DEVICE_BINDINGS", "HOSTED_ADD_DEVICE_POWER_DEVNODE_ID"] {
        assert!(!paths.0.iter().any(|name| name == forbidden),
            "component PoSetPowerState cannot access executive state: {forbidden}");
    }
}

#[test]
fn root_device_service_admits_the_power_report_operation() {
    let file = source("driver_launch.rs");
    let paths = paths(function(&file, "service_hosted_device"));
    assert!(paths.0.iter().any(|name| name == "HOSTED_DEVICE_OP_REPORT_POWER_STATE"));
    assert!(paths.0.iter().any(|name| name == "service_report"),
        "power reporting must reuse the authenticated hosted-device ingress");
}

#[test]
fn root_power_report_resolves_exact_device_and_lifecycle_authority() {
    let file = source("hosted_power_broker.rs");
    let target = paths(function(&file, "resolve_report_target"));
    for required in ["authenticated_hosted_device", "hosted_power_report_target",
        "power_report_target"] {
        assert!(target.0.iter().any(|name| name == required),
            "power target resolution must preserve {required} authority");
    }
    assert!(!target.0.iter().any(|name| name.starts_with("HOSTED_ADD_DEVICE_POWER_")),
        "AddDevice power authority belongs to the retained owner, not ambient globals");
    assert!(!target.0.iter().any(|name| name == "current_hosted_device_dispatch_binding"),
        "committed device reports must not require an active IRP");
    for forbidden in ["hosted_device_binding_by_device_id", "hosted_device_binding_by_pdo_object"] {
        assert!(!target.0.iter().any(|name| name == forbidden),
            "stack routing must not revoke the producer's anchored pointer authority: {forbidden}");
    }
    let service = paths(function(&file, "service_report"));
    for required in ["resolve_report_target", "report_device_power_state", "report_system_power_state"] {
        assert!(service.0.iter().any(|name| name == required),
            "canonical power update must stay in the root broker: {required}");
    }
    assert!(!service.0.iter().any(|name| name == "power_manager"),
        "PoSetPowerState must update the requested canonical DeviceRecord, not a devnode aggregate");
}
