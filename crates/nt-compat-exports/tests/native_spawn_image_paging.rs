use syn::visit::Visit;
use syn::parse::Parser;

#[derive(Default)]
struct Calls(Vec<String>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
        if let Ok(arguments) = parser.parse2(mac.tokens.clone()) {
            for argument in &arguments {
                let mut nested = Calls::default();
                nested.visit_expr(argument);
                self.0.extend(nested.0);
            }
        }
    }
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
fn source(name: &str) -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src")
        .join(name);
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing exact prepublication paging boundary {name}"))
}
fn calls(block: &syn::Block) -> Vec<String> {
    let mut calls = Calls::default();
    calls.visit_block(block);
    calls.0
}

#[test]
fn spawn_parents_use_the_retained_paging_ledger_after_exact_prepublication_admission() {
    let file = source("user_image_paging.rs");
    let spawn = function(&file, "ensure_spawn_user_paging_parents");
    let sequence = calls(&spawn.block);
    let admit = sequence
        .iter()
        .position(|name| name == "spawn_process_is_current")
        .expect("prepublication caps require authentic runtime/bootstrap or mechanism ownership");
    let construct = sequence
        .iter()
        .position(|name| name == "construct")
        .unwrap();
    let publish = sequence
        .iter()
        .position(|name| name == "reserve_path")
        .unwrap();
    assert!(
        admit < publish && publish < construct,
        "exact owners are recorded before native effects"
    );
    let reserve = calls(&function(&file, "reserve_path").block);
    assert!(
        reserve.iter().any(|name| name == "push"),
        "shared path records missing owners before construction"
    );
    assert!(
        !sequence
            .iter()
            .any(|name| name == "checked_spawn_paging_map"),
        "the same retained OwnedPagingStructure journal governs prepublication parents"
    );
}

#[test]
fn spawn_slot_reuse_requires_empty_retained_parent_ledger_before_allocating_root() {
    let file = source("img_spawn.rs");
    let sequence = calls(&function(&file, "spawn_sec_image").block);
    let available = sequence
        .iter()
        .position(|name| name == "spawn_process_available")
        .expect("old parent rows must block PI reuse even when no leaf was created");
    let allocate = sequence
        .iter()
        .position(|name| name == "alloc_slot")
        .unwrap();
    assert!(
        available < allocate,
        "failed old construction ownership precedes every new VSpace effect"
    );
}

#[test]
fn initial_accounting_uses_actual_construction_caps_after_ack_before_publication() {
    let file = source("exec_handler.rs");
    let method = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method)
                    if method.sig.ident == "publish_hosted_process_vspace" =>
                {
                    Some(method)
                }
                _ => None,
            }),
            _ => None,
        })
        .unwrap();
    let sequence = calls(&method.block);
    let registered = sequence
        .iter()
        .position(|name| name == "ensure_process_commit_owner")
        .unwrap();
    let marked = sequence
        .iter()
        .position(|name| name == "mark_process_accounted")
        .expect("prepublication physical rows require an explicit NT-account ACK");
    assert!(registered < marked);
    struct Receipt(bool);
    impl<'ast> Visit<'ast> for Receipt {
        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if let syn::Expr::Path(path) = &*call.func {
                if path
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "mark_process_accounted")
                {
                    self.0 |= call.args.len() == 3
                        && matches!(&call.args[2],
                        syn::Expr::Path(path) if path.path.is_ident("caps"));
                }
            }
            syn::visit::visit_expr_call(self, call);
        }
    }
    let mut receipt = Receipt(false);
    receipt.visit_block(&method.block);
    assert!(
        receipt.0,
        "the exact factory caps receipt authenticates the unpublished root"
    );
    let file = source("user_image_paging.rs");
    let marker = calls(&function(&file, "mark_process_accounted").block);
    assert!(marker.iter().any(|name| name == "spawn_process_is_current"));
    assert!(
        !marker.iter().any(|name| name == "current"),
        "initial accounting cannot require a VSpace which is deliberately not published yet"
    );
}

#[test]
fn physical_retype_and_initial_nt_commitment_have_distinct_acknowledgements() {
    let file = source("user_image_paging.rs");
    let row = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(row) if row.ident == "Row" => Some(row),
            _ => None,
        })
        .unwrap();
    let fields: Vec<_> = row
        .fields
        .iter()
        .filter_map(|field| field.ident.as_ref())
        .map(ToString::to_string)
        .collect();
    assert!(
        fields.iter().any(|name| name == "retyped") && fields.iter().any(|name| name == "charged"),
        "physical backing ownership is not an acknowledged NT charge"
    );
    let normal = calls(&function(&file, "ensure_process_user_paging_parents").block);
    let accounting = normal
        .iter()
        .position(|name| name == "ensure_process_commit_owner")
        .expect("initial charge acknowledgement must not reborrow a live paging ledger row");
    let borrow = normal.iter().position(|name| name == "acquire").unwrap();
    assert!(accounting < borrow);
    let file = source("exec_handler.rs");
    let method = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Impl(item) => item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "ensure_process_commit_owner" => {
                    Some(method)
                }
                _ => None,
            }),
            _ => None,
        })
        .unwrap();
    let sequence = calls(&method.block);
    let registered = sequence
        .iter()
        .position(|name| name == "register_with_limit")
        .unwrap();
    let marked = sequence
        .iter()
        .position(|name| name == "mark_process_accounted")
        .expect("only actual initial registration acknowledges prepublication paging commitment");
    assert!(registered < marked);
}
