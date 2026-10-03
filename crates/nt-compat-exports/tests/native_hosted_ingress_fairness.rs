use syn::visit::Visit;

#[derive(Default)]
struct SelectionAudit {
    calls: Vec<String>,
    methods: Vec<String>,
    fields: Vec<String>,
    delivered_assignment: Option<usize>,
    indexed_selector: bool,
}

impl<'ast> Visit<'ast> for SelectionAudit {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            if let Some(name) = path.path.segments.last() {
                self.calls.push(name.ident.to_string());
                if name.ident == "oldest_external_ingress" {
                    let mut candidates = SelectionAudit::default();
                    for argument in &call.args {
                        candidates.visit_expr(argument);
                    }
                    self.indexed_selector =
                        candidates.methods.iter().any(|name| name == "enumerate");
                }
            }
        }
        syn::visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.methods.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_field(&mut self, field: &'ast syn::ExprField) {
        if let syn::Member::Named(name) = &field.member {
            self.fields.push(name.to_string());
        }
        syn::visit::visit_expr_field(self, field);
    }

    fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
        if matches!(&*assignment.left, syn::Expr::Field(field)
            if matches!(&field.member, syn::Member::Named(name) if name == "delivered"))
        {
            assert!(matches!(&*assignment.right, syn::Expr::Lit(value)
                if matches!(&value.lit, syn::Lit::Bool(value) if value.value)));
            self.delivered_assignment = Some(self.calls.len());
        }
        syn::visit::visit_expr_assign(self, assignment);
    }
}

#[test]
fn retained_hosted_calls_select_oldest_admission_without_weakening_authority() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/component_ingress_hosted.rs"
    ))
    .unwrap();
    let body = source
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "take_hosted_with" => {
                Some(&*function.block)
            }
            _ => None,
        })
        .expect("retained hosted ingress selector exists");
    let mut audit = SelectionAudit::default();
    audit.visit_block(body);

    assert!(audit.calls.iter().any(|name| name == "oldest_external_ingress"),
        "a recurring Call reusing an earlier slot must not overtake an older retained fault; select by ExternalIngress admission order");
    assert!(audit.indexed_selector,
        "oldest selection must receive indexed eligible ExternalIngress candidates, not reusable slot order");
    assert!(
        !audit.methods.iter().any(|name| name == "find"),
        "first-ready slot selection can indefinitely starve an older retained Call"
    );
    assert!(audit.fields.iter().any(|name| name == "delivered"));
    assert!(audit.fields.iter().any(|name| name == "call"));
    assert!(
        audit
            .calls
            .iter()
            .any(|name| name == "hosted_ingress_binding"),
        "selection does not replace exact live hosted-thread authority"
    );
    let query = audit
        .calls
        .iter()
        .position(|name| name == "query_component_reply_binding")
        .expect("selected retained Reply must be physically revalidated");
    let import = audit
        .calls
        .iter()
        .position(|name| name == "import")
        .expect("selected message must be imported before delivery");
    assert!(query < import);
    assert!(
        import
            < audit
                .delivered_assignment
                .expect("successful import marks delivered"),
        "failed import must not consume or replay retained delivery"
    );
}
