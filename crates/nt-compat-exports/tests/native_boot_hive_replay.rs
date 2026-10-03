use std::path::PathBuf;
use syn::{visit::Visit, Expr, ImplItem, Item};

#[derive(Default)]
struct ReplayContract {
    strict_calls: usize,
    tolerant_calls: usize,
    propagating: bool,
}

impl<'ast> Visit<'ast> for ReplayContract {
    fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
        let previous = self.propagating;
        self.propagating = true;
        self.visit_expr(&expression.expr);
        self.propagating = previous;
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*call.func {
            match path
                .path
                .segments
                .last()
                .unwrap()
                .ident
                .to_string()
                .as_str()
            {
                "replay_log" => self.tolerant_calls += 1,
                "try_replay_log" => {
                    self.strict_calls += 1;
                    assert!(self.propagating,
                        "complete journal corruption must propagate before clean/success publication");
                }
                _ => {}
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

#[test]
fn every_boot_checkpoint_journal_branch_propagates_strict_replay_failure() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../components/ntos-executive/src/exec_handler.rs");
    let file = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    let restore = file
        .items
        .iter()
        .filter_map(|item| match item {
            Item::Impl(implementation) => Some(implementation),
            _ => None,
        })
        .flat_map(|implementation| &implementation.items)
        .find_map(|item| match item {
            ImplItem::Fn(function)
                if function.sig.ident == "refresh_boot_hive_checkpoint_from_path" =>
            {
                Some(function)
            }
            _ => None,
        })
        .expect("native installed/core/REGF checkpoint restore boundary");
    let mut contract = ReplayContract::default();
    contract.visit_block(&restore.block);
    assert_eq!(
        contract.tolerant_calls, 0,
        "boot recovery must not silently truncate a complete invalid CreateChild record"
    );
    assert_eq!(
        contract.strict_calls, 3,
        "installed-source, core-image and REGF-image branches must all use strict replay"
    );
}
