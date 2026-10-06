use syn::visit::Visit;

fn method<'a>(file: &'a syn::File, name: &str) -> &'a syn::Block {
    file.items
        .iter()
        .find_map(|item| {
            let syn::Item::Impl(item) = item else {
                return None;
            };
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => Some(&method.block),
                _ => None,
            })
        })
        .expect("actual native registry method")
}

#[derive(Default)]
struct Calls {
    prepared: usize,
    obsolete: usize,
    progress: usize,
    guarded: bool,
    premature: usize,
}

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        let outer = self.guarded;
        self.guarded |= matches!(&*expression.cond, syn::Expr::Field(field)
            if matches!(&field.member, syn::Member::Named(name) if name == "durable"));
        self.visit_block(&expression.then_branch);
        self.guarded = outer;
        if let Some((_, branch)) = &expression.else_branch {
            self.visit_expr(branch);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        match call.method.to_string().as_str() {
            "try_set_value" => self.prepared += 1,
            "mutate_with_live_apply" | "set_value" | "set_value_from_existing_value" => {
                self.obsolete += 1
            }
            "note_mutable_hive_journal_record" => {
                self.progress += 1;
                self.premature += usize::from(!self.guarded || self.prepared == 0);
            }
            _ => {}
        }
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn native_value_publication_uses_prepared_manager_without_replay_fallback() {
    let file = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/exec_registry_set_value.rs"
    ))
    .unwrap();
    let mut audit = Calls::default();
    audit.visit_block(method(&file, "journal_set_mutable_value"));
    assert_eq!(
        audit.prepared, 1,
        "prepare resources before entering journal effects"
    );
    assert_eq!(
        audit.obsolete, 0,
        "no post-journal allocation or replay fallback"
    );
    assert_eq!(audit.progress, 1);
    assert_eq!(
        audit.premature, 0,
        "only acknowledged durable receipts advance progress"
    );
}

#[test]
fn retained_value_resources_are_owned_outside_rewindable_allocation_scopes() {
    let file = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/exec_registry_set_value.rs"
    ))
    .unwrap();
    let block = method(&file, "journal_set_mutable_value");
    let Some(syn::Stmt::Local(local)) = block.stmts.first() else {
        panic!("durable routing must precede resource preparation");
    };
    assert!(
        matches!(&local.pat, syn::Pat::Ident(name) if name.ident == "_durable"),
        "retain the allocator guard until publication or error return"
    );
    assert!(
        matches!(&local.init, Some(init)
        if matches!(&*init.expr, syn::Expr::Call(call)
            if matches!(&*call.func, syn::Expr::Path(path)
                if path.path.segments.iter().map(|segment| segment.ident.to_string())
                    .collect::<Vec<_>>() == ["allocator", "enter_durable"]))),
        "prepared cells, payloads and uncertain records must not become rewindable"
    );
}

#[test]
fn obsolete_native_copy_publication_adapter_is_removed() {
    let file = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/exec_registry_set_value.rs"
    ))
    .unwrap();
    for item in &file.items {
        if let syn::Item::Impl(item) = item {
            assert!(
                !item.items.iter().any(|item| matches!(item,
                syn::ImplItem::Fn(method)
                    if method.sig.ident == "journal_set_mutable_value_from_existing_value")),
                "remove the dormant second publication path"
            );
        }
    }
}
