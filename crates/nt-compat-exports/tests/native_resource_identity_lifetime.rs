use syn::{visit::Visit, ItemFn};

const SOURCE: &str = include_str!("../../../components/ntos-executive/src/driver_launch.rs");

fn function(name: &str) -> ItemFn {
    syn::parse_file(SOURCE)
        .unwrap()
        .items
        .into_iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing native function {name}"))
}

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            if let Some(segment) = path.path.segments.last() {
                self.0.push(segment.ident.to_string());
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn calls(function: &ItemFn) -> Vec<String> {
    let mut calls = Calls::default();
    calls.visit_block(&function.block);
    calls.0
}

#[test]
fn resource_revocation_retains_canonical_identity_until_binding_retirement() {
    let revocation = calls(&function("clear_hosted_resource_projection"));
    assert!(!revocation.iter().any(|call| call == "remove_hosted_device_resource_state"),
        "STOP and failed START must not erase the identity required by later legitimate PnP dispatch");
    assert!(
        revocation
            .iter()
            .any(|call| call == "revoke_hosted_device_resource_state"),
        "resource release must explicitly leave a canonical empty identity row"
    );
}

#[test]
fn terminal_binding_teardown_removes_identity_only_after_pointer_retirement() {
    let teardown = calls(&function("teardown_hosted_device_binding"));
    let position = |name| {
        teardown
            .iter()
            .position(|call| call == name)
            .unwrap_or_else(|| panic!("terminal teardown must call {name}"))
    };
    assert!(
        position("clear_hosted_resource_projection")
            < position("remove_hosted_device_resource_state")
    );
    assert!(
        position("preflight_hosted_device_resource_identity_retirement")
            < position("retire_hosted_device_pointer")
    );
    assert!(
        position("retire_hosted_device_pointer") < position("remove_hosted_device_resource_state")
    );
    assert!(
        position("remove_hosted_device_resource_state")
            < position("release_hosted_registry_identity")
    );
}

#[test]
fn terminal_identity_removal_has_no_fallible_native_lease_release() {
    let removal = calls(&function("remove_hosted_device_resource_state"));
    assert!(removal
        .iter()
        .any(|call| call == "preflight_hosted_device_resource_identity_retirement"));
    assert!(
        !removal
            .iter()
            .any(|call| call == "release_hosted_pnp_context_lease"),
        "all native/context effects must finish before canonical pointer retirement"
    );
    assert!(removal.iter().any(|call| call == "remove"));
    struct PointerReceipt(bool);
    impl<'ast> Visit<'ast> for PointerReceipt {
        fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
            if matches!(assignment.left.as_ref(), syn::Expr::Field(field)
                if matches!(&field.member, syn::Member::Named(name) if name == "pointer_retired"))
                && matches!(assignment.right.as_ref(), syn::Expr::Lit(value)
                    if matches!(&value.lit, syn::Lit::Bool(value) if value.value))
            {
                self.0 = true;
            }
            syn::visit::visit_expr_assign(self, assignment);
        }
    }
    let mut receipt = PointerReceipt(false);
    receipt.visit_block(&function("teardown_hosted_device_binding").block);
    assert!(
        receipt.0,
        "successful direct pointer retirement must update the exact retained receipt"
    );
}

#[test]
fn revoked_identity_has_no_retained_resource_grants_or_context_lease() {
    let revoked = function("revoke_hosted_device_resource_state");
    let operations = calls(&revoked);
    assert!(operations
        .iter()
        .any(|call| call == "release_hosted_pnp_context_lease"));
    assert!(
        !operations.iter().any(|call| call == "remove"),
        "revocation is not row retirement"
    );
    struct IdentityLiteral(bool);
    impl<'ast> Visit<'ast> for IdentityLiteral {
        fn visit_expr_struct(&mut self, literal: &'ast syn::ExprStruct) {
            if literal.path.is_ident("HostedDeviceResourceState") {
                let fields: Vec<_> = literal
                    .fields
                    .iter()
                    .filter_map(|field| match &field.member {
                        syn::Member::Named(name) => Some(name.to_string()),
                        _ => None,
                    })
                    .collect();
                self.0 = ["device_id", "driver_id", "instance", "projection_domain", "pdo_object"]
                    .iter().all(|required| fields.iter().any(|field| field == required))
                    && fields.iter().all(|field| matches!(field.as_str(),
                        "device_id" | "driver_id" | "instance" | "projection_domain" | "pdo_object"
                        | "interface_type" | "bus_number" | "address"))
                    && literal.rest.as_ref().is_some_and(|rest| matches!(rest.as_ref(),
                        syn::Expr::Call(call) if matches!(call.func.as_ref(), syn::Expr::Path(path)
                            if path.path.segments.last().is_some_and(|segment| segment.ident == "default"))));
            }
            syn::visit::visit_expr_struct(self, literal);
        }
    }
    let mut identity = IdentityLiteral(false);
    identity.visit_block(&revoked.block);
    assert!(
        identity.0,
        "revocation must rebuild only exact identity and bus metadata over empty defaults"
    );
}

#[test]
fn lease_release_failure_propagates_before_identity_reset() {
    let revoked = function("revoke_hosted_device_resource_state");
    let operations = calls(&revoked);
    let release = operations
        .iter()
        .position(|call| call == "release_hosted_pnp_context_lease")
        .unwrap();
    let reset = operations
        .iter()
        .position(|call| call == "default")
        .unwrap();
    assert!(
        release < reset,
        "lease retirement must precede removal of the retained lease token"
    );
    struct PropagatedRelease(bool);
    impl<'ast> Visit<'ast> for PropagatedRelease {
        fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
            if matches!(expression.expr.as_ref(), syn::Expr::Call(call)
                if matches!(call.func.as_ref(), syn::Expr::Path(path)
                    if path.path.segments.last().is_some_and(|segment|
                        segment.ident == "release_hosted_pnp_context_lease")))
            {
                self.0 = true;
            }
            syn::visit::visit_expr_try(self, expression);
        }
    }
    let mut propagation = PropagatedRelease(false);
    propagation.visit_block(&revoked.block);
    assert!(
        propagation.0,
        "failed lease release must retain the canonical row and propagate the error"
    );
}
