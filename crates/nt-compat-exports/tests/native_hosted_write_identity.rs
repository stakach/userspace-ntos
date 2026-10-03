use syn::{visit::Visit, Expr, Item};

fn source() -> syn::File {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/hosted_write_work.rs");
    syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn function<'a>(file: &'a syn::File, name: &str) -> &'a syn::ItemFn {
    file.items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == name => Some(function),
            _ => None,
        })
        .unwrap_or_else(|| panic!("missing focused WRITE boundary {name}"))
}

#[derive(Default)]
struct Calls(Vec<(String, Vec<Expr>)>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0.push((
                path.path.segments.last().unwrap().ident.to_string(),
                call.args.iter().cloned().collect(),
            ));
        }
        syn::visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0
            .push((call.method.to_string(), call.args.iter().cloned().collect()));
        syn::visit::visit_expr_method_call(self, call);
    }
}

fn calls(block: &syn::Block) -> Calls {
    let mut calls = Calls::default();
    calls.visit_block(block);
    calls
}

#[derive(Default)]
struct Names(Vec<String>);
impl<'ast> Visit<'ast> for Names {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        self.0.push(ident.to_string());
    }
}

#[test]
fn write_admission_reconciles_old_ack_then_deduplicates_captured_generation() {
    let file = source();
    let calls = calls(&function(&file, "submit").block);
    let position = |name: &str| {
        calls
            .0
            .iter()
            .position(|(call, _)| call == name)
            .unwrap_or_else(|| panic!("WRITE submission must call {name}"))
    };
    assert!(
        position("reconcile_source_acks") < position("capture"),
        "next ingress must settle the old exact physical ACK before taking new source owners"
    );
    assert!(position("capture") < position("source_identity"));
    assert!(
        position("source_identity") < position("source_work_index"),
        "duplicate admission must use the captured generation, not the reusable address"
    );
    let (_, arguments) = &calls.0[position("source_work_index")];
    let mut names = Names::default();
    for argument in arguments {
        names.visit_expr(argument);
    }
    assert!(
        !names.0.iter().any(|name| name == "source_irp_address"),
        "raw address is not source admission identity"
    );
}

#[test]
fn executing_and_retained_write_dedup_require_exact_identity_and_pin_ownership() {
    let file = source();
    let executing = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Static(item) if item.ident == "EXECUTING" => Some(item),
            _ => None,
        })
        .unwrap();
    let mut names = Names::default();
    names.visit_type(&executing.ty);
    assert!(
        names
            .0
            .iter()
            .any(|name| name == "SourceIrpForwardIdentity"),
        "EXECUTING must retain ticket/allocation generations, not just a source address"
    );
    let index = function(&file, "source_work_index");
    let calls = calls(&index.block);
    assert!(
        calls.0.iter().any(|(name, _)| name == "duplicates_owned"),
        "dedup must require full identity equality and a still-owned source pin"
    );
    let mut fields = Names::default();
    fields.visit_block(&index.block);
    assert!(
        fields
            .0
            .iter()
            .any(|name| matches!(name.as_str(), "source_pin_owned" | "source_pinned")),
        "retained ACK identity after pin release cannot exclude a new allocation"
    );
}

#[test]
fn next_write_ingress_preserves_old_ack_until_exact_reply_acknowledgement() {
    let file = source();
    let helper = function(&file, "reconcile_source_acks");
    let calls = calls(&helper.block);
    let reconcile = calls
        .0
        .iter()
        .position(|(name, _)| name == "reconcile_retained_service_reply")
        .expect("old ACK needs its physical Reply acknowledgement");
    let retire = calls
        .0
        .iter()
        .position(|(name, _)| name == "retire_stopped_acknowledged_retained_service")
        .expect("only the acknowledged exact semantic receipt may retire");
    assert!(reconcile < retire);
    for index in [reconcile, retire] {
        let mut names = Names::default();
        for argument in &calls.0[index].1 {
            names.visit_expr(argument);
        }
        for expected in ["ack", "route", "dispatch", "reply", "token"] {
            assert!(
                names.0.iter().any(|name| name == expected),
                "ACK settlement must use its retained {expected}, not the next dispatch"
            );
        }
    }
    assert!(
        !calls.0.iter().any(|(name, _)| matches!(
            name.as_str(),
            "release" | "unpin" | "s_io_free_irp" | "complete_hosted_irp"
        )),
        "ACK reconciliation must not replay source completion or touch retired source storage"
    );
}
