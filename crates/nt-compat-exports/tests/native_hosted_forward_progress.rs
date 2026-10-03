use syn::{visit::Visit, Expr, Item};

#[derive(Default)]
struct Calls(Vec<String>);

impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.0.push(call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            self.0
                .push(path.path.segments.last().unwrap().ident.to_string());
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn check_progress_boundary(name: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../components/ntos-executive/src/hosted_{name}_work.rs"
    ));
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    let runner = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "redrive_one" => Some(function),
            _ => None,
        })
        .unwrap();
    let mut calls = Calls::default();
    calls.visit_block(&runner.block);
    let advance = calls.0.iter().position(|call| call == "advance").unwrap();
    let observations: Vec<_> = calls
        .0
        .iter()
        .enumerate()
        .filter_map(|(index, call)| (call == "progress").then_some(index))
        .collect();
    assert_eq!(
        observations.len(),
        2,
        "{name} must observe both sides of advance"
    );
    assert!(observations[0] < advance && advance < observations[1]);
    assert!(
        calls.0.iter().any(|call| call == "advanced"),
        "{name} selection is not evidence of a transition"
    );
    let Some(syn::Stmt::Expr(Expr::Path(result), None)) = runner.block.stmts.last() else {
        panic!("{name} runner must return its actual progress result");
    };
    assert!(result.path.is_ident("progressed"));

    let nested = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Fn(function) if function.sig.ident == "redrive_nested_ready" => Some(function),
            _ => None,
        })
        .unwrap();
    let mut nested_calls = Calls::default();
    nested_calls.visit_block(&nested.block);
    assert!(
        nested_calls.0.iter().any(|call| call == "len"),
        "{name} must bound its ready pass by retained table size"
    );
    assert!(
        nested_calls
            .0
            .iter()
            .any(|call| call == "redrive_ready_pass"),
        "{name} must try later candidates before declaring no progress"
    );
}

#[test]
fn read_retirement_retry_does_not_starve_physical_receive() {
    check_progress_boundary("read");
}

#[test]
fn write_retirement_retry_does_not_starve_physical_receive() {
    check_progress_boundary("write");
}

#[test]
fn flush_retirement_retry_does_not_starve_physical_receive() {
    check_progress_boundary("flush");
}

#[test]
fn query_retirement_retry_does_not_starve_physical_receive() {
    check_progress_boundary("query_information");
}
