//! The canonical drive and SystemRoot links are published from the registered mounted-volume
//! Device and validated installation root, only while that exact mount generation is live.

use syn::{visit::Visit, Item};

const NAMESPACE: &str = include_str!("../../../components/ntos-executive/src/boot_namespace.rs");
const MAIN: &str = include_str!("../../../components/ntos-executive/src/main.rs");

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

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items.iter().find_map(|item| match item {
        Item::Fn(item) if item.sig.ident == name => Some(item),
        _ => None,
    }).unwrap_or_else(|| panic!("missing {name}"))
}

fn position(calls: &[String], name: &str) -> Vec<usize> {
    calls.iter().enumerate().filter(|(_, call)| call.ends_with(name)).map(|(index, _)| index).collect()
}

#[test]
fn publication_derives_links_from_the_registered_device_and_validated_root() {
    let file = syn::parse_file(NAMESPACE).unwrap();
    let publish = function(&file, "publish");
    let parameters: Vec<String> = publish.sig.inputs.iter().filter_map(|input| match input {
        syn::FnArg::Typed(typed) => match &*typed.pat {
            syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
            _ => None,
        },
        _ => None,
    }).collect();
    assert!(parameters.iter().any(|name| name == "device_id")
        && !parameters.iter().any(|name| name == "device_path"),
        "publication takes the registered Device identity, not a caller-supplied name");
    let mut calls = Calls::default();
    calls.visit_item_fn(publish);
    assert!(!position(&calls.0, "boot_volume_links").is_empty(),
        "link names and targets come from the tested nt-fs derivation");
    assert!(!position(&calls.0, "registered_volume_name").is_empty(),
        "the target is the registered Device's own name");
}

#[test]
fn publication_requires_the_live_mount_generation_before_create_and_commit() {
    let file = syn::parse_file(NAMESPACE).unwrap();
    let mut publish = Calls::default();
    publish.visit_item_fn(function(&file, "publish"));
    let live = position(&publish.0, "live_registered_volume");
    let create = position(&publish.0, "object_manager_create_symbolic_link_path_with_permanence");
    let mirror = position(&publish.0, "with_object_namespace");
    assert!(!create.is_empty() && mirror.len() >= 2);
    assert!(live.first().is_some_and(|live| live < &create[0]),
        "a stale or unregistered mount must be refused before any link exists");
    assert!(live.iter().any(|live| live > create.last().unwrap() && live < mirror.last().unwrap()),
        "the generation is revalidated before the native mirror commits the links");
    let mut guard = Calls::default();
    guard.visit_item_fn(function(&file, "live_registered_volume"));
    assert!(!position(&guard.0, "exec_volume_device").is_empty(),
        "the live check uses the exact physical/logical mount pair binding");
    assert!(NAMESPACE.contains("VOLUME_DISMOUNTED"), "a stale generation is a dismounted volume");
    let verified = position(&publish.0, "verify");
    assert!(verified.iter().any(|verify| verify > create.last().unwrap()
        && verify < mirror.last().unwrap()),
        "every created link is verified before the native mirror commits it");
    let mut verify = Calls::default();
    verify.visit_item_fn(function(&file, "verify"));
    assert!(!position(&verify.0, "object_manager_query_symbolic_link").is_empty(),
        "each canonical link's stored target is read back from the Object Manager");
    assert!(!position(&verify.0, "object_manager_resolve_file_target_owned").is_empty(),
        "each published spelling must resolve to the registered Device");
}

#[test]
fn boot_publishes_links_only_after_registration_and_root_validation() {
    let start = MAIN.find("match mounted_volume::register_mounted_volume(fs)")
        .expect("mounted volume registration");
    let body = &MAIN[start..];
    let ok = body.find("Ok((device_id,").expect("registered volume arm");
    let publish = body.find("boot_namespace::publish(device_id,").expect("publication from device id");
    let refused = body.find("Err(status) =>").expect("refused arm");
    assert!(ok < publish && publish < refused,
        "links are published only inside the registered-and-validated arm");
}
