use syn::visit::Visit;

fn source() -> syn::File {
    syn::parse_file(include_str!("../../nt-ntdll-dll/src/dll_relocation.rs")).unwrap()
}

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }
}

#[test]
fn unacknowledged_map_result_cannot_discard_the_owned_load() {
    let file = source();
    let finish = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item) => Some(item),
            _ => None,
        })
        .flat_map(|item| &item.items)
        .find_map(|item| match item {
            syn::ImplItem::Fn(function) if function.sig.ident == "finish" => Some(function),
            _ => None,
        })
        .unwrap();
    let rejected = finish
        .block
        .stmts
        .iter()
        .find_map(|statement| match statement {
            syn::Stmt::Expr(syn::Expr::If(branch), _) => Some(branch),
            _ => None,
        })
        .expect("Map ACK discrimination must precede relocation effects");
    let mut calls = Calls::default();
    calls.visit_block(&rejected.then_branch);
    assert!(
        !calls.0.iter().any(|name| name == "forget"),
        "a negative Map status may follow committed mapping and a failed output store"
    );
    assert!(
        rejected
            .then_branch
            .stmts
            .iter()
            .any(|statement| matches!(statement, syn::Stmt::Expr(syn::Expr::Return(_), _))),
        "unacknowledged Map keeps the load owner and stops relocation"
    );
}

#[test]
fn acknowledged_protection_receipts_belong_to_the_retained_view_owner() {
    let file = source();
    let owner = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "ViewOwner" => Some(item),
            _ => None,
        })
        .unwrap();
    assert!(
        owner.fields.iter().any(|field| {
            field
                .ident
                .as_ref()
                .is_some_and(|name| name == "protections")
                && matches!(&field.ty, syn::Type::Path(path)
                if path.path.segments.last().is_some_and(|segment| segment.ident == "Vec"))
        }),
        "failed restore/unmap must retain the exact acknowledged range journal"
    );
    let relocate = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "relocate" => Some(function),
            _ => None,
        })
        .unwrap();
    struct OwnedJournal {
        reserved: bool,
        appended: bool,
    }
    impl<'ast> Visit<'ast> for OwnedJournal {
        fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
            if matches!(&*call.receiver, syn::Expr::Field(field)
                if matches!(&field.member, syn::Member::Named(name) if name == "protections"))
            {
                self.reserved |= call.method == "try_reserve_exact";
                self.appended |= call.method == "push";
            }
            syn::visit::visit_expr_method_call(self, call);
        }
    }
    let mut journal = OwnedJournal {
        reserved: false,
        appended: false,
    };
    journal.visit_block(&relocate.block);
    assert!(
        journal.reserved && journal.appended,
        "reserve before effects and append receipts directly into the retained owner"
    );
}
