use syn::{visit::Visit, Expr, Item, Member, Pat, Stmt};

fn snapshot_function() -> syn::ItemFn {
    syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/driver_launch.rs"
    ))
    .unwrap()
    .items
    .into_iter()
    .find_map(|item| match item {
        Item::Fn(function)
            if function.sig.ident == "read_hosted_device_resource_state_from_shared" =>
        {
            Some(function)
        }
        _ => None,
    })
    .expect("canonical resource snapshot boundary")
}

#[derive(Default)]
struct ResourceSelection {
    filters: usize,
    maps: usize,
    canonical_source: bool,
}

impl<'ast> Visit<'ast> for ResourceSelection {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.filters += usize::from(
            call.method == "filter"
                && matches!(&*call.receiver, Expr::Path(path) if path.path.is_ident("previous_state")),
        );
        self.maps += usize::from(call.method == "map");
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        self.canonical_source |= path.path.is_ident("previous_state");
        syn::visit::visit_expr_path(self, path);
    }
}

#[test]
fn existing_canonical_resource_row_keeps_its_empty_grant_set() {
    let function = snapshot_function();
    let initializer = function
        .block
        .stmts
        .iter()
        .find_map(|statement| {
            let Stmt::Local(local) = statement else {
                return None;
            };
            let Pat::Tuple(tuple) = &local.pat else {
                return None;
            };
            matches!(tuple.elems.first(), Some(Pat::Ident(ident))
            if ident.ident == "address_resource_count")
            .then(|| &*local.init.as_ref().unwrap().expr)
        })
        .expect("resource count and records selected together");
    let mut selection = ResourceSelection::default();
    selection.visit_expr(initializer);
    assert!(selection.canonical_source && selection.maps != 0);
    assert_eq!(
        selection.filters, 0,
        "an existing stopped identity's empty resource set is authoritative, not missing metadata"
    );
}

#[derive(Default)]
struct PdoIdentity {
    canonical: bool,
    fields: usize,
}

impl<'ast> Visit<'ast> for PdoIdentity {
    fn visit_expr_struct(&mut self, expression: &'ast syn::ExprStruct) {
        if expression
            .path
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "HostedDeviceResourceState")
        {
            for field in &expression.fields {
                if matches!(&field.member, Member::Named(name) if name == "pdo_object") {
                    self.fields += 1;
                    self.canonical = matches!(&field.expr, Expr::Field(access)
                        if matches!(&*access.base, Expr::Path(path) if path.path.is_ident("binding"))
                        && matches!(&access.member, Member::Named(name) if name == "pdo_object"));
                }
            }
        }
        syn::visit::visit_expr_struct(self, expression);
    }
}

#[test]
fn resource_snapshot_cannot_replace_canonical_pdo_identity_from_shared_bank() {
    let mut identity = PdoIdentity::default();
    identity.visit_item_fn(&snapshot_function());
    assert_eq!(identity.fields, 1);
    assert!(
        identity.canonical,
        "PDO identity comes from the exact binding, not mutable shared projection bytes"
    );
}
