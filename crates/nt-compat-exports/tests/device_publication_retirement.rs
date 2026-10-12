//! Native caller wiring checks; executable helper behavior lives in device_pool_adapter.
use syn::visit::Visit;
const CONSUMER: &str = include_str!("../../../components/ntos-executive/src/hosted_consumer_device_objects.rs");
const ROLLBACK: &str = include_str!("../../../components/ntos-executive/src/hosted_add_device_rollback.rs");
const DRIVER: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn native_function(start: &str, end: &str) -> syn::ItemFn {
    let source = &DRIVER[DRIVER.find(start).expect("native function")..];
    let source = &source[..source.find(end).expect("next native function")];
    syn::parse_str(source).expect("complete native function")
}

fn function(file: &syn::File, name: &str) -> syn::ItemFn {
    file.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == name => Some(item.clone()),
        _ => None,
    }).unwrap()
}

#[derive(Default)]
struct Calls(Vec<String>);
impl<'a> Visit<'a> for Calls {
    fn visit_expr_call(&mut self, call: &'a syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.0.push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'a syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn consumer_revalidates_canonical_binding_before_each_physical_attempt() {
    let file = syn::parse_file(CONSUMER).unwrap();
    let mut calls = Calls::default();
    calls.visit_block(&function(&file, "retire").block);
    let admission = calls.0.iter().position(|name| name == "admit_retirement").unwrap();
    let canonical = calls.0.iter().position(|name| name == "hosted_device_pointer_registration")
        .expect("successful old retirement does not exclude a new canonical binding");
    assert!(canonical < admission);
}

#[test]
fn pdo_original_registration_survives_until_physical_retirement_ack() {
    let file = syn::parse_file(ROLLBACK).unwrap();
    struct Clear(bool);
    impl<'a> Visit<'a> for Clear {
        fn visit_expr_assign(&mut self, assign: &'a syn::ExprAssign) {
            if let syn::Expr::Field(field) = &*assign.left {
                if matches!(&field.member, syn::Member::Named(name) if name == "pdo_registration") {
                    self.0 |= matches!(&*assign.right, syn::Expr::Path(path) if path.path.is_ident("None"));
                }
            }
            syn::visit::visit_expr_assign(self, assign);
        }
    }
    let mut clear = Clear(false);
    clear.visit_block(&function(&file, "advance_inner").block);
    assert!(!clear.0, "PDO provenance cannot be cleared before the retained rollback row's physical ACK");
}

#[test]
fn add_device_binding_uses_the_created_registration_without_republishing_it() {
    let binding = native_function(
        "fn register_hosted_device_binding(",
        "\nfn hosted_device_binding_by_device_id(",
    );
    let mut calls = Calls::default();
    calls.visit_block(&binding.block);
    assert!(!calls.0.iter().any(|call| call == "register_hosted_device_projection"));
    assert!(calls.0.iter().any(|call| call == "hosted_device_pointer_registration"));
    assert!(calls.0.iter().any(|call| call == "registration"));

    let add_device = native_function(
        "unsafe fn call_add_device_for_existing_pdo(",
        "\n/// Grant a hosted device driver access",
    );
    let mut calls = Calls::default();
    calls.visit_block(&add_device.block);
    let owner = calls.0.iter().position(|call| call == "owns_created_registration").unwrap();
    let binding = calls.0.iter().position(|call| call == "register_hosted_device_binding").unwrap();
    assert!(owner < binding, "the AddDevice row must authenticate the FDO before binding publication");
}
