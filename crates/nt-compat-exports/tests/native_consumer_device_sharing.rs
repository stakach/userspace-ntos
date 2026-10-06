use syn::{visit::Visit, Item};

fn source() -> syn::File {
    syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/hosted_consumer_file_objects.rs"
    ))
    .unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap()
}

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn calls(function: &syn::ItemFn) -> Vec<String> {
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    calls.0
}

#[test]
fn consumer_files_acquire_shared_exact_device_instead_of_rebinding_it() {
    let file = source();
    let build = calls(function(&file, "build"));
    assert!(
        build.iter().any(|name| name == "acquire_device"),
        "distinct File owners must join a checked shared Device projection"
    );
    assert!(
        !build
            .iter()
            .any(|name| name == "bind_hosted_device_pointer"),
        "per-File construction cannot create a second DeviceId/address binding"
    );
}

#[test]
fn consumer_file_retirement_releases_lease_without_retiring_sibling_device() {
    let file = source();
    let retire = calls(function(&file, "retire"));
    let projection = retire.iter().position(|name| name == "retire").unwrap();
    let shared = retire.iter().position(|name| name == "release_device");
    assert!(
        shared.is_some(),
        "File retirement must release its exact shared lease"
    );
    assert!(
        projection < shared.unwrap(),
        "drain File projection before its Device lease"
    );
    assert!(
        !retire
            .iter()
            .any(|name| name == "retire_hosted_device_pointer"),
        "a File cannot unregister a Device still used by sibling Files"
    );
}
