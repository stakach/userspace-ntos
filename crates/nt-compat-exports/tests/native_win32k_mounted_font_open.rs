//! After the native block handoff, a win32k ZwCreateFile/ZwOpenFile of a `\SystemRoot` font
//! reaches the registered mounted-volume Device through canonical CREATE, keeps its Pending IRP
//! owned until terminal completion, and reports a bounded marker once its File handle exists.

use syn::{visit::Visit, ImplItem, Item};

const INGRESS: &str =
    include_str!("../../../components/ntos-executive/src/hosted_io_create_file_ingress.rs");
const WORK: &str = include_str!("../../../components/ntos-executive/src/hosted_io_create_file_work.rs");
const TRACE: &str =
    include_str!("../../../components/ntos-executive/src/mounted_provider_open_trace.rs");

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0.push(path.path.segments.iter().map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>().join("::"));
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(format!(".{}", call.method));
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn function_calls(source: &str, name: &str) -> Vec<String> {
    let file = syn::parse_file(source).unwrap();
    let mut calls = Calls::default();
    let mut found = false;
    for item in &file.items {
        match item {
            Item::Fn(item) if item.sig.ident == name => { calls.visit_item_fn(item); found = true; }
            Item::Impl(block) => for item in &block.items {
                if let ImplItem::Fn(method) = item {
                    if method.sig.ident == name { calls.visit_impl_item_fn(method); found = true; }
                }
            },
            _ => {}
        }
    }
    assert!(found, "missing {name}");
    calls.0
}

fn index(calls: &[String], name: &str) -> usize {
    calls.iter().position(|call| call.ends_with(name)).unwrap_or_else(|| panic!("missing call {name}"))
}

#[test]
fn win32k_absolute_names_resolve_only_through_the_object_manager_to_a_registered_device() {
    let capture = function_calls(INGRESS, "capture_win32k");
    assert!(capture.iter().any(|call| call == "resolve_request"));
    let request = function_calls(INGRESS, "resolve_request");
    assert!(request.iter().any(|call| call == "resolve_absolute_name"));
    let absolute = function_calls(INGRESS, "resolve_absolute_name");
    assert!(absolute.iter().any(|call| call.ends_with("object_manager_resolve_file_target_owned"))
        && absolute.iter().any(|call| call == "from_resolved_file_target"));
    for source in [INGRESS, WORK] {
        for direct in ["fat_open_path(", "fat_read_file(", "installed_image_reader(", "exec_fs()"] {
            assert!(!source.contains(direct),
                "a provider CREATE never reads the installed volume around its Device: {direct}");
        }
    }
}

#[test]
fn pending_create_is_retained_until_its_terminal_and_the_handle_precedes_the_marker() {
    let dispatch = function_calls(WORK, "dispatch_create");
    let enter = index(&dispatch, ".enter_dispatch");
    let send = index(&dispatch, "dispatch_hosted_file_create_irp_result_exact");
    let retain = index(&dispatch, ".retain_irp");
    assert!(enter < send && send < retain, "a Pending CREATE IRP is owned by its delivery");
    let terminal = function_calls(WORK, "observe_terminal");
    assert!(terminal.iter().any(|call| call == "completed_irp_exact"),
        "only the exact completed IRP supplies the CREATE result");
    let publish = function_calls(WORK, "publish_success");
    let handle = index(&publish, ".publish");
    let marker = index(&publish, "mounted_provider_open_trace::opened");
    assert!(handle < marker, "the marker reports a File handle that already exists");
}

#[test]
fn successful_mounted_open_marker_is_bounded_and_names_the_exact_volume() {
    assert!(TRACE.contains("[mounted-provider-open] origin="));
    for field in [" file=0x", " handle=0x", " pending=", " name="] {
        assert!(TRACE.contains(field), "marker field {field}");
    }
    assert!(TRACE.contains("exec_volume_device()"), "only the live mounted volume is reported");
    assert!(TRACE.contains("MARKER_BUDGET"), "boot-visible but bounded");
}
