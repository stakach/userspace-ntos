use syn::{visit::Visit, ImplItem, Item};

fn query() -> syn::ImplItemFn {
    syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/mounted_directory_query.rs"
    ))
    .unwrap()
    .items
    .into_iter()
    .find_map(|item| {
        let Item::Impl(item) = item else {
            return None;
        };
        item.items.into_iter().find_map(|item| match item {
            ImplItem::Fn(method) if method.sig.ident == "query_directory" => Some(method),
            _ => None,
        })
    })
    .expect("focused mounted directory-query implementation")
}

#[derive(Default)]
struct Facts {
    calls: Vec<String>,
    cursor_writes: usize,
}
impl<'ast> Visit<'ast> for Facts {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*call.func {
            self.calls
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_assign(&mut self, assignment: &'ast syn::ExprAssign) {
        if matches!(&*assignment.left, syn::Expr::Field(field)
            if matches!(&field.member, syn::Member::Named(name) if name == "directory_query"))
        {
            self.cursor_writes += 1;
        }
        syn::visit::visit_expr_assign(self, assignment);
    }
}
fn facts(node: &syn::Block) -> Facts {
    let mut facts = Facts::default();
    facts.visit_block(node);
    facts
}
fn scratch(body: &syn::Block) -> (usize, &syn::Block) {
    body.stmts
        .iter()
        .enumerate()
        .find_map(|(index, statement)| {
            let syn::Stmt::Local(local) = statement else {
                return None;
            };
            let syn::Expr::Block(block) = &*local.init.as_ref()?.expr else {
                return None;
            };
            facts(&block.block)
                .calls
                .iter()
                .any(|call| call == "enter_transient")
                .then_some((index, &block.block))
        })
        .expect("temporary directory lists need a scoped transient capture, not durable ownership")
}

#[test]
fn all_directory_capture_and_encoding_scratch_is_scoped_before_cursor_publication() {
    let method = query();
    let (index, block) = scratch(&method.block);
    let captured = facts(block);
    for call in [
        "fat_visit_directory_checked",
        "directory_entries_opened",
        "directory_entries_relative",
        "merge_layered_directory_entries",
        "query_directory",
    ] {
        assert!(
            captured.calls.iter().any(|value| value == call),
            "temporary operation {call} escaped scratch lifetime"
        );
    }
    assert_eq!(
        captured.cursor_writes, 0,
        "do not publish persistent state from scratch"
    );
    let mut after = Facts::default();
    for statement in &method.block.stmts[index + 1..] {
        after.visit_stmt(statement);
    }
    assert_eq!(
        after.cursor_writes, 1,
        "publish only the copied query state after scratch drops"
    );
    assert!(
        !captured.calls.iter().any(|value| value == "ensure_mounted"),
        "lazy mount ownership must not be allocated from transient storage"
    );
}

#[test]
fn lazy_volume_mount_uses_durable_scope_after_admission_before_scratch() {
    let method = query();
    let (index, _) = scratch(&method.block);
    let prepared = method.block.stmts[..index]
        .iter()
        .position(|statement| {
            let syn::Stmt::Expr(syn::Expr::Block(block), _) = statement else {
                return false;
            };
            let observed = facts(&block.block);
            let Some(durable) = observed
                .calls
                .iter()
                .position(|value| value == "enter_durable")
            else {
                return false;
            };
            let Some(mount) = observed
                .calls
                .iter()
                .position(|value| value == "ensure_mounted")
            else {
                return false;
            };
            durable < mount
        })
        .expect("initialize persistent writable-volume state in a completed durable scope");
    let mut admission = Facts::default();
    for statement in &method.block.stmts[..prepared] {
        admission.visit_stmt(statement);
    }
    assert!(admission
        .calls
        .iter()
        .any(|value| value == "directory_notify_access_granted"));
    assert!(
        prepared > 0,
        "do not mount before validating the directory request"
    );
}

#[test]
fn allocation_failure_diagnostics_report_effective_arenas_not_only_total_capacity() {
    let source = syn::parse_file(include_str!(
        "../../../components/ntos-executive/src/allocator.rs"
    ))
    .unwrap();
    let report = source
        .items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "report_oom" => Some(function),
            _ => None,
        })
        .unwrap();
    let observed = facts(&report.block);
    assert!(
        observed
            .calls
            .iter()
            .any(|value| value == "durable_heap_capacity"),
        "aggregate heap cap includes the non-durable transient reservation"
    );
    assert!(
        observed
            .calls
            .iter()
            .any(|value| value == "transient_heap_size"),
        "report the separate scratch arena without changing allocation policy"
    );
}
